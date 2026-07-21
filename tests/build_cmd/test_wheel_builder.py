from __future__ import annotations

import hashlib
import os
import stat
import sys
import sysconfig
import zipfile
from pathlib import Path

import pytest

import rextio.build.wheel_builder as wheel_builder
from rextio.build.wheel_builder import build_artifact_wheel


def _external_contract() -> wheel_builder.ExternalWheelContract:
    payloads = {
        "demo_pkg/__init__.py": b"def affine(x): return x + 1\n",
        "demo_pkg-1.0.0.dist-info/METADATA": b"metadata",
        "demo_pkg-1.0.0.dist-info/WHEEL": b"wheel",
        "demo_pkg-1.0.0.dist-info/licenses/LICENSE": b"license",
        "demo_pkg-1.0.0.dist-info/RECORD": b"record",
    }
    identities = tuple(
        wheel_builder.ExternalWheelMemberIdentity(
            path=path,
            sha256=hashlib.sha256(payload).hexdigest(),
            size=len(payload),
        )
        for path, payload in sorted(payloads.items())
    )
    return wheel_builder.ExternalWheelContract(
        package="demo_pkg",
        distribution="demo-pkg",
        version="1.0.0",
        source_members=("demo_pkg/__init__.py",),
        external_members=identities,
    )


def test_build_artifact_wheel_is_deterministic_and_records_files(tmp_path: Path) -> None:
    python_dir = tmp_path / "python"
    dist_dir = tmp_path / "dist"
    (python_dir / "pkg").mkdir(parents=True)
    (python_dir / "pkg" / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (python_dir / "pkg" / "mod.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8"
    )

    first = build_artifact_wheel(tmp_path / "Demo Project", python_dir, dist_dir)
    first_bytes = Path(first.path or "").read_bytes()
    second = build_artifact_wheel(tmp_path / "Demo Project", python_dir, dist_dir)
    second_bytes = Path(second.path or "").read_bytes()

    assert first.status == "built"
    assert second.status == "built"
    assert first.path == second.path
    assert first_bytes == second_bytes
    assert Path(first.path or "").name == "demo_project-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(first.path or "") as archive:
        names = set(archive.namelist())
        record = archive.read("demo_project-0.1.0.dist-info/RECORD").decode("utf-8")

    assert "pkg/__init__.py" in names
    assert "pkg/mod.py" in names
    assert "demo_project-0.1.0.dist-info/METADATA" in names
    assert "demo_project-0.1.0.dist-info/WHEEL" in names
    assert "demo_project-0.1.0.dist-info/RECORD" in names
    assert "pkg/mod.py,sha256=" in record


def test_build_artifact_wheel_uses_platform_tag_for_native_extension(tmp_path: Path) -> None:
    python_dir = tmp_path / "python"
    dist_dir = tmp_path / "dist"
    python_dir.mkdir()
    native_name = (
        f"_rextio_native.cpython-{sys.version_info.major}{sys.version_info.minor}-darwin.so"
    )
    (python_dir / native_name).write_bytes(b"fake native extension")

    result = build_artifact_wheel(tmp_path / "Native Project", python_dir, dist_dir)

    python_tag = f"cp{sys.version_info.major}{sys.version_info.minor}"
    platform_tag = sysconfig.get_platform().replace("-", "_").replace(".", "_")
    expected_name = f"native_project-0.1.0-{python_tag}-{python_tag}-{platform_tag}.whl"
    assert Path(result.path or "").name == expected_name
    with zipfile.ZipFile(result.path or "") as archive:
        wheel = archive.read("native_project-0.1.0.dist-info/WHEEL").decode("utf-8")

    assert "Root-Is-Purelib: false" in wheel
    assert f"Tag: {python_tag}-{python_tag}-{platform_tag}" in wheel


def test_nuitka_compiled_modules_ship_without_shadowed_py(tmp_path: Path) -> None:
    # After a nuitka fallback build the tree holds `module.py` AND its compiled
    # `module.so` sibling. The import system prefers the extension, so the .py
    # is dead weight in the wheel and exposes the source; it must be excluded.
    # Modules kept plain (external accelerators) have no compiled sibling and
    # keep their .py. The wheel tag must be platform-specific: it carries
    # binaries even though no _rextio_native extension exists.
    python_dir = tmp_path / "python"
    (python_dir / "hb").mkdir(parents=True)
    (python_dir / "hb" / "__init__.py").write_text("", encoding="utf-8")
    (python_dir / "hb" / "plain.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (python_dir / "hb" / "plain.so").write_bytes(b"fake extension")
    (python_dir / "hb" / "plain2.py").write_text("def g():\n    return 2\n", encoding="utf-8")
    (python_dir / "hb" / "kernels.py").write_text(
        "from numba import njit\n\n@njit\ndef total(n):\n    return n\n", encoding="utf-8"
    )

    result = build_artifact_wheel(tmp_path, python_dir, tmp_path / "dist")

    assert result.status == "built"
    assert result.path is not None
    assert "py3-none-any" not in result.path  # platform tag required
    with zipfile.ZipFile(result.path) as archive:
        names = set(archive.namelist())
    assert "hb/plain.so" in names
    assert "hb/plain.py" not in names  # shadowed source excluded
    assert "hb/plain2.py" in names  # prefix-similar module is NOT shadowed
    assert "hb/kernels.py" in names  # accelerated module keeps its source
    assert "hb/__init__.py" in names
    record = [name for name in names if name.endswith("RECORD")]
    assert record  # metadata still written


def test_ctypes_payload_does_not_shadow_its_python_wrapper(tmp_path: Path) -> None:
    # A .dylib/.dll next to a same-stem .py is a ctypes payload, not an
    # importable extension module (EXTENSION_SUFFIXES only has .so/.pyd):
    # the wrapper .py must stay in the wheel, while the platform tag still
    # applies (the wheel carries platform-specific content).
    python_dir = tmp_path / "python"
    (python_dir / "pkg").mkdir(parents=True)
    (python_dir / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (python_dir / "pkg" / "libfoo.py").write_text("# ctypes wrapper\n", encoding="utf-8")
    (python_dir / "pkg" / "libfoo.native.dylib").write_bytes(b"payload")

    result = build_artifact_wheel(tmp_path, python_dir, tmp_path / "dist")

    assert result.status == "built"
    assert result.path is not None
    assert "py3-none-any" not in result.path
    with zipfile.ZipFile(result.path) as archive:
        names = set(archive.namelist())
    assert "pkg/libfoo.py" in names  # wrapper survives
    assert "pkg/libfoo.native.dylib" in names


def test_external_wheel_contract_pins_requirement_and_excludes_source(
    tmp_path: Path,
) -> None:
    contract_type = getattr(wheel_builder, "ExternalWheelContract", None)
    verifier = getattr(wheel_builder, "verify_external_wheel_contract", None)
    assert contract_type is not None, "external wheel contract is not implemented"
    assert verifier is not None, "external wheel verifier is not implemented"
    python_dir = tmp_path / "python"
    (python_dir / "app").mkdir(parents=True)
    (python_dir / "app" / "__init__.py").write_text("", encoding="utf-8")
    contract = _external_contract()

    result = build_artifact_wheel(
        tmp_path / "project",
        python_dir,
        tmp_path / "dist",
        external_contract=contract,
    )

    assert result.status == "built"
    assert result.path is not None
    verified = verifier(Path(result.path), contract)
    assert verified.requirement == "demo-pkg==1.0.0"
    with zipfile.ZipFile(result.path) as archive:
        names = archive.namelist()
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8")
    assert metadata.count("Requires-Dist: demo-pkg==1.0.0\n") == 1
    assert "demo_pkg/__init__.py" not in names


def test_external_wheel_capture_binds_native_member_to_exact_expected_bytes(
    tmp_path: Path,
) -> None:
    python_dir = tmp_path / "python"
    python_dir.mkdir()
    native_name = "_rextio_native.cpython-311-test.so"
    native_bytes = b"cargo-native-extension"
    (python_dir / native_name).write_bytes(native_bytes)
    contract = _external_contract()
    result = build_artifact_wheel(
        tmp_path / "project",
        python_dir,
        tmp_path / "dist",
        external_contract=contract,
    )
    assert result.path is not None

    capture = wheel_builder.capture_external_wheel_contract(
        Path(result.path),
        contract,
        native_member_path=native_name,
        native_member_bytes=native_bytes,
    )

    assert hashlib.sha256(capture.wheel_bytes).hexdigest() == (
        capture.verification.wheel_sha256
    )
    assert capture.native_member.path == native_name
    assert capture.native_member.sha256 == hashlib.sha256(native_bytes).hexdigest()
    with pytest.raises(wheel_builder.WheelContractError, match="differs from Cargo"):
        wheel_builder.capture_external_wheel_contract(
            Path(result.path),
            contract,
            native_member_path=native_name,
            native_member_bytes=b"different-cargo-artifact",
        )


@pytest.mark.parametrize("extra_native", (False, True))
def test_external_wheel_capture_requires_exact_native_member_coverage(
    tmp_path: Path,
    extra_native: bool,
) -> None:
    python_dir = tmp_path / "python"
    python_dir.mkdir()
    native_name = "_rextio_native.cpython-311-test.so"
    if extra_native:
        (python_dir / native_name).write_bytes(b"expected")
        (python_dir / "_rextio_native.other.so").write_bytes(b"extra")
    contract = _external_contract()
    result = build_artifact_wheel(
        tmp_path / "project",
        python_dir,
        tmp_path / "dist",
        external_contract=contract,
    )
    assert result.path is not None

    with pytest.raises(wheel_builder.WheelContractError, match="coverage"):
        wheel_builder.capture_external_wheel_contract(
            Path(result.path),
            contract,
            native_member_path=native_name,
            native_member_bytes=b"expected",
        )


@pytest.mark.parametrize(
    "relative",
    ("demo_pkg/__init__.py", "DEMO_PKG/hidden.PY"),
)
def test_external_wheel_contract_rejects_staged_external_python_source(
    tmp_path: Path,
    relative: str,
) -> None:
    contract_type = getattr(wheel_builder, "ExternalWheelContract", None)
    error_type = getattr(wheel_builder, "WheelContractError", None)
    assert contract_type is not None, "external wheel contract is not implemented"
    assert error_type is not None, "external wheel contract error is not implemented"
    python_dir = tmp_path / "python"
    (python_dir / "app").mkdir(parents=True)
    (python_dir / "app" / "__init__.py").write_text("", encoding="utf-8")
    source_path = python_dir / relative
    source_path.parent.mkdir()
    source_path.write_text(
        "def affine(x): return x + 1\n",
        encoding="utf-8",
    )
    contract = _external_contract()

    with pytest.raises(error_type, match="external package material"):
        build_artifact_wheel(
            tmp_path / "project",
            python_dir,
            tmp_path / "dist",
            external_contract=contract,
        )

    assert not list((tmp_path / "dist").glob("*.whl"))


@pytest.mark.parametrize(
    "relative",
    (
        "demo_pkg/config.json",
        "demo_pkg-1.0.0.dist-info/licenses/LICENSE",
        "demo_pkg-1.0.0.dist-info/RECORD",
    ),
)
def test_external_contract_rejects_non_python_package_and_metadata_material(
    tmp_path: Path,
    relative: str,
) -> None:
    python_dir = tmp_path / "python"
    path = python_dir / relative
    path.parent.mkdir(parents=True)
    path.write_bytes(b"external material")

    with pytest.raises(
        wheel_builder.WheelContractError, match="external package material"
    ):
        build_artifact_wheel(
            tmp_path / "project",
            python_dir,
            tmp_path / "dist",
            external_contract=_external_contract(),
        )


@pytest.mark.parametrize("link_kind", ("symlink", "hardlink"))
def test_ordinary_wheel_builder_preserves_linked_staging_files(
    tmp_path: Path,
    link_kind: str,
) -> None:
    python_dir = tmp_path / "python"
    python_dir.mkdir()
    target = tmp_path / "target.py"
    target.write_text("VALUE = 1\n", encoding="utf-8")
    linked = python_dir / "linked.py"
    if link_kind == "symlink":
        linked.symlink_to(target)
    else:
        os.link(target, linked)

    result = build_artifact_wheel(tmp_path, python_dir, tmp_path / "dist")

    assert result.status == "built"
    assert result.path is not None
    with zipfile.ZipFile(result.path) as archive:
        assert archive.read("linked.py") == b"VALUE = 1\n"


@pytest.mark.parametrize("link_kind", ("symlink", "hardlink"))
def test_strict_wheel_builder_rejects_linked_staging_files(
    tmp_path: Path,
    link_kind: str,
) -> None:
    python_dir = tmp_path / "python"
    (python_dir / "app").mkdir(parents=True)
    (python_dir / "app" / "__init__.py").write_text("", encoding="utf-8")
    target = tmp_path / "target.py"
    target.write_text("VALUE = 1\n", encoding="utf-8")
    linked = python_dir / "app" / "linked.py"
    if link_kind == "symlink":
        linked.symlink_to(target)
        reason = "symlink"
    else:
        os.link(target, linked)
        reason = "unalias"

    with pytest.raises(wheel_builder.WheelContractError, match=reason):
        build_artifact_wheel(
            tmp_path / "project",
            python_dir,
            tmp_path / "dist",
            external_contract=_external_contract(),
        )


def test_ordinary_wheel_build_does_not_require_posix_open_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    python_dir = tmp_path / "python"
    (python_dir / "pkg").mkdir(parents=True)
    (python_dir / "pkg" / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (python_dir / "pkg" / "module.so").write_bytes(b"compiled module")
    monkeypatch.delattr(wheel_builder.os, "O_NOFOLLOW", raising=False)
    monkeypatch.delattr(wheel_builder.os, "O_DIRECTORY", raising=False)

    result = build_artifact_wheel(tmp_path, python_dir, tmp_path / "dist")

    assert result.status == "built"
    assert result.path is not None
    assert "py3-none-any" not in result.path
    with zipfile.ZipFile(result.path) as archive:
        names = set(archive.namelist())
    assert "pkg/module.so" in names
    assert "pkg/module.py" not in names


def test_strict_wheel_build_requires_posix_open_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    python_dir = tmp_path / "python"
    (python_dir / "app").mkdir(parents=True)
    (python_dir / "app" / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.delattr(wheel_builder.os, "O_NOFOLLOW", raising=False)
    monkeypatch.delattr(wheel_builder.os, "O_DIRECTORY", raising=False)

    with pytest.raises(wheel_builder.WheelContractError, match="no-follow traversal"):
        build_artifact_wheel(
            tmp_path / "project",
            python_dir,
            tmp_path / "dist",
            external_contract=_external_contract(),
        )


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is POSIX-only")
def test_ordinary_wheel_builder_omits_special_staging_entries(tmp_path: Path) -> None:
    python_dir = tmp_path / "python"
    python_dir.mkdir()
    (python_dir / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    os.mkfifo(python_dir / "runtime.pipe")

    result = build_artifact_wheel(tmp_path, python_dir, tmp_path / "dist")

    assert result.status == "built"
    assert result.path is not None
    with zipfile.ZipFile(result.path) as archive:
        names = set(archive.namelist())
    assert "module.py" in names
    assert "runtime.pipe" not in names


def _strict_external_wheel(tmp_path: Path):
    python_dir = tmp_path / "python"
    (python_dir / "app").mkdir(parents=True)
    (python_dir / "app" / "__init__.py").write_text("", encoding="utf-8")
    contract = _external_contract()
    result = build_artifact_wheel(
        tmp_path / "project",
        python_dir,
        tmp_path / "dist",
        external_contract=contract,
    )
    assert result.path is not None
    return Path(result.path), contract


@pytest.mark.parametrize(
    ("member", "mode", "reason"),
    (
        ("../escape.py", stat.S_IFREG | 0o644, "unsafe"),
        ("DEMO_PKG/hidden.PY", stat.S_IFREG | 0o644, "external package material"),
        ("APP/__init__.py", stat.S_IFREG | 0o644, "aliased"),
        ("payload-link", stat.S_IFLNK | 0o777, "regular file"),
    ),
)
def test_external_wheel_verifier_rejects_unsafe_alias_and_nonregular_members(
    tmp_path: Path,
    member: str,
    mode: int,
    reason: str,
) -> None:
    wheel, contract = _strict_external_wheel(tmp_path)
    info = zipfile.ZipInfo(member)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = mode << 16
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(info, b"payload")

    with pytest.raises(wheel_builder.WheelContractError, match=reason):
        wheel_builder.verify_external_wheel_contract(wheel, contract)


def test_external_wheel_verifier_rejects_compression_bomb(tmp_path: Path) -> None:
    wheel, contract = _strict_external_wheel(tmp_path)
    info = zipfile.ZipInfo("payload.bin")
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(info, b"0" * 1_000_000)

    with pytest.raises(wheel_builder.WheelContractError, match="compression ratio"):
        wheel_builder.verify_external_wheel_contract(wheel, contract)


def test_external_wheel_verifier_treats_dependency_headers_case_insensitively(
    tmp_path: Path,
) -> None:
    wheel, contract = _strict_external_wheel(tmp_path)
    rewritten = wheel.with_suffix(".rewritten")
    with zipfile.ZipFile(wheel) as source, zipfile.ZipFile(rewritten, "w") as target:
        for original in source.infolist():
            payload = source.read(original)
            if original.filename.endswith(".dist-info/METADATA"):
                payload += b"requires-dist: unexpected==9\n"
            target.writestr(original, payload)
    rewritten.replace(wheel)

    with pytest.raises(wheel_builder.WheelContractError, match="exact pin"):
        wheel_builder.verify_external_wheel_contract(wheel, contract)


def test_external_wheel_verifier_rejects_symlinked_wheel_path(tmp_path: Path) -> None:
    wheel, contract = _strict_external_wheel(tmp_path)
    target = wheel.with_suffix(".real")
    wheel.replace(target)
    wheel.symlink_to(target)

    with pytest.raises(wheel_builder.WheelContractError, match="regular file"):
        wheel_builder.verify_external_wheel_contract(wheel, contract)
