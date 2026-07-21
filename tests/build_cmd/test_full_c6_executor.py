"""Adversarial tests for the strict Full C6 two-build executor."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest


STRICT_BUILD = (
    "cargo",
    "build",
    "--release",
    "--locked",
    "--offline",
    "--frozen",
)


def _project(tmp_path: Path, *, lock: bool = True) -> Path:
    root = tmp_path / "generated-project"
    source = root / "src"
    source.mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2021"\n',
        encoding="utf-8",
    )
    if lock:
        (root / "Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "demo"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )
    (source / "lib.rs").write_text("pub fn answer() -> i64 { 42 }\n", encoding="utf-8")
    return root


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    roots = (tmp_path / "quarantine-one", tmp_path / "quarantine-two")
    for root in roots:
        root.mkdir(mode=0o700)
        root.chmod(0o700)
    return roots


def _outputs(root: Path, *, wheel: bytes = b"reproducible-wheel"):
    from rextio.build.reproducibility import ReproducibilityBuildOutputs

    output = root / "output"
    output.mkdir()
    wheel_path = output / "demo.whl"
    sbom = output / "sbom.json"
    provenance = output / "provenance.json"
    wheel_path.write_bytes(wheel)
    sbom.write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
    provenance.write_text('{"buildType":"rextio/full-c6","externalParameters":{}}', encoding="utf-8")
    return ReproducibilityBuildOutputs(wheel_path, sbom, provenance)


def test_executor_freezes_two_independent_copies_and_returns_path_free_receipt(
    tmp_path: Path,
) -> None:
    from rextio.build.full_c6_executor import execute_full_c6_two_build

    source = _project(tmp_path)
    roots = _roots(tmp_path)
    calls = []

    def build(request):
        calls.append(request)
        assert request.context.ordinal == len(calls)
        assert request.context.inherit_env is False
        assert request.cargo_argv == STRICT_BUILD
        environment = request.context.environment_dict()
        assert environment["CARGO_NET_OFFLINE"] == "true"
        assert environment["SOURCE_DATE_EPOCH"] == "1"
        assert environment["LANG"] == environment["LC_ALL"] == "C"
        assert environment["TZ"] == "UTC"
        assert "RUSTC_WRAPPER" not in environment
        assert "HTTP_PROXY" not in environment
        assert Path(environment["HOME"]).is_relative_to(request.context.build_root)
        assert Path(environment["CARGO_HOME"]).is_relative_to(request.context.build_root)
        assert Path(environment["CARGO_TARGET_DIR"]).is_relative_to(
            request.context.build_root
        )
        remaps = environment["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
        assert len(remaps) == 2
        assert all(item.startswith("--remap-path-prefix=") for item in remaps)
        assert stat.S_IMODE(request.context.project_root.stat().st_mode) == 0o700
        assert stat.S_IMODE(
            request.context.project_root.joinpath("Cargo.toml").stat().st_mode
        ) == 0o644
        return _outputs(request.context.build_root)

    receipt = execute_full_c6_two_build(
        source,
        *roots,
        build=build,
        cargo_command=STRICT_BUILD,
        base_environment={"PATH": "/usr/bin:/bin"},
        source_date_epoch=1,
    )

    assert len(calls) == 2
    assert receipt.reproducibility.reproducible is True
    assert receipt.authorizes_distribution is False
    assert receipt.complete_for_scope is True
    assert receipt.frozen_tree.cargo_lock_generated is False
    assert {item.logical_name for item in receipt.frozen_tree.entries} >= {
        "Cargo.lock",
        "Cargo.toml",
        "src",
        "src/lib.rs",
    }
    assert receipt.invocations[0].argv_sha256 == receipt.invocations[1].argv_sha256
    serialized = json.dumps(receipt.to_dict(), sort_keys=True)
    assert str(tmp_path) not in serialized
    assert str(source) not in repr(receipt)

    first_file = calls[0].context.project_root / "src" / "lib.rs"
    second_file = calls[1].context.project_root / "src" / "lib.rs"
    assert (first_file.stat().st_dev, first_file.stat().st_ino) != (
        second_file.stat().st_dev,
        second_file.stat().st_ino,
    )


def test_missing_lock_is_generated_once_offline_and_frozen_into_both_copies(
    tmp_path: Path,
) -> None:
    from rextio.build.full_c6_executor import execute_full_c6_two_build

    source = _project(tmp_path, lock=False)
    roots = _roots(tmp_path)
    lock_calls = []
    observed_locks: list[bytes] = []

    def generate_lock(request):
        lock_calls.append(request)
        assert request.cargo_argv == ("cargo", "generate-lockfile", "--offline")
        assert request.inherit_env is False
        assert request.environment_dict()["CARGO_NET_OFFLINE"] == "true"
        (request.project_root / "Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "demo"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )

    def build(request):
        observed_locks.append((request.context.project_root / "Cargo.lock").read_bytes())
        return _outputs(request.context.build_root)

    receipt = execute_full_c6_two_build(
        source,
        *roots,
        build=build,
        cargo_command=STRICT_BUILD,
        lock_generator=generate_lock,
        source_date_epoch=7,
    )

    assert len(lock_calls) == 1
    assert len(observed_locks) == 2 and observed_locks[0] == observed_locks[1]
    assert receipt.frozen_tree.cargo_lock_generated is True
    assert not (source / "Cargo.lock").exists()


def test_command_factory_runs_twice_with_closed_bounded_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rextio.build.full_c6_executor as executor
    from rextio.build.full_c6_executor import FullC6BuildCommand

    source = _project(tmp_path)
    roots = _roots(tmp_path)
    runs = []

    def fake_run(command, *, cwd, timeout, env, inherit_env, max_output_bytes):
        runs.append((command, cwd, timeout, dict(env), inherit_env, max_output_bytes))
        root = Path(cwd).parent
        _outputs(root)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(executor, "run_build_tool", fake_run)

    def command_factory(_context):
        return FullC6BuildCommand(
            argv=STRICT_BUILD,
            unsigned_wheel="output/demo.whl",
            sbom_json="output/sbom.json",
            provenance_input_json="output/provenance.json",
        )

    receipt = executor.execute_full_c6_two_build(
        source,
        *roots,
        command_factory=command_factory,
        base_environment={"PATH": "/usr/bin:/bin"},
        source_date_epoch=3,
        timeout_seconds=30,
        max_output_bytes=4096,
    )

    assert len(runs) == 2
    for command, cwd, timeout, environment, inherit_env, output_bound in runs:
        assert tuple(command) == STRICT_BUILD
        assert Path(cwd).name == "project"
        assert timeout == 30
        assert environment["CARGO_NET_OFFLINE"] == "true"
        assert inherit_env is False
        assert output_bound == 4096
    assert receipt.reproducibility.reproducible is True


@pytest.mark.parametrize(
    "command",
    (
        ("cargo", "build", "--release"),
        ("cargo", "build", "--release", "--locked", "--offline"),
        ("cargo", "build", "--release", "--locked", "--offline", "--frozen", "--config", "net.offline=false"),
        ("not-cargo", "build", "--locked", "--offline", "--frozen"),
    ),
)
def test_executor_rejects_missing_or_boundary_changing_strict_flags(
    tmp_path: Path,
    command: tuple[str, ...],
) -> None:
    from rextio.build.full_c6_executor import FullC6ExecutorError, execute_full_c6_two_build

    with pytest.raises(FullC6ExecutorError, match="strict|Cargo"):
        execute_full_c6_two_build(
            _project(tmp_path),
            *_roots(tmp_path),
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=command,
            source_date_epoch=0,
        )


@pytest.mark.parametrize(
    "environment",
    (
        {"CARGO_NET_OFFLINE": "false"},
        {"HTTP_PROXY": "http://127.0.0.1:8080"},
        {"RUSTC_WRAPPER": "ccache"},
        {"not_allowlisted": "value"},
    ),
)
def test_executor_rejects_environment_override_or_leakage(
    tmp_path: Path,
    environment: dict[str, str],
) -> None:
    from rextio.build.full_c6_executor import FullC6ExecutorError, execute_full_c6_two_build

    with pytest.raises(FullC6ExecutorError, match="environment|override|proxy|wrapper"):
        execute_full_c6_two_build(
            _project(tmp_path),
            *_roots(tmp_path),
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            base_environment=environment,
            source_date_epoch=0,
        )


def test_executor_rejects_unsafe_quarantine_roots(tmp_path: Path) -> None:
    from rextio.build.full_c6_executor import FullC6ExecutorError, execute_full_c6_two_build

    source = _project(tmp_path)
    first, second = _roots(tmp_path)
    first.chmod(0o755)
    with pytest.raises(FullC6ExecutorError, match="0700"):
        execute_full_c6_two_build(
            source,
            first,
            second,
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    first.chmod(0o700)
    (first / "existing").write_text("unsafe", encoding="utf-8")
    with pytest.raises(FullC6ExecutorError, match="empty"):
        execute_full_c6_two_build(
            source,
            first,
            second,
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    (first / "existing").unlink()
    link = tmp_path / "quarantine-link"
    try:
        link.symlink_to(first, target_is_directory=True)
    except (NotImplementedError, OSError):
        return
    with pytest.raises(FullC6ExecutorError, match="symlink|real"):
        execute_full_c6_two_build(
            source,
            link,
            second,
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )


def test_executor_rejects_source_symlinks_hardlinks_and_special_files(tmp_path: Path) -> None:
    from rextio.build.full_c6_executor import FullC6ExecutorError, execute_full_c6_two_build

    source = _project(tmp_path)
    roots = _roots(tmp_path)
    symlink = source / "linked.rs"
    try:
        symlink.symlink_to(source / "src" / "lib.rs")
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")
    with pytest.raises(FullC6ExecutorError, match="symlink"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    symlink.unlink()
    hardlink = source / "hardlinked.rs"
    os.link(source / "src" / "lib.rs", hardlink)
    with pytest.raises(FullC6ExecutorError, match="hardlink"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    hardlink.unlink()
    if hasattr(os, "mkfifo"):
        fifo = source / "pipe"
        os.mkfifo(fifo)
        with pytest.raises(FullC6ExecutorError, match="non-regular"):
            execute_full_c6_two_build(
                source,
                *roots,
                build=lambda request: _outputs(request.context.build_root),
                cargo_command=STRICT_BUILD,
                source_date_epoch=0,
            )


def test_executor_rejects_source_or_project_mutation(tmp_path: Path) -> None:
    from rextio.build.full_c6_executor import FullC6ExecutorError, execute_full_c6_two_build

    source = _project(tmp_path)
    roots = _roots(tmp_path)
    calls = 0

    def mutate_source(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            (source / "src" / "lib.rs").write_text("mutated\n", encoding="utf-8")
        return _outputs(request.context.build_root)

    with pytest.raises(FullC6ExecutorError, match="source tree changed"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=mutate_source,
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    source = _project(tmp_path / "other")
    roots = _roots(tmp_path / "other")

    def mutate_copy(request):
        (request.context.project_root / "src" / "lib.rs").write_text(
            "mutated copy\n", encoding="utf-8"
        )
        return _outputs(request.context.build_root)

    with pytest.raises(FullC6ExecutorError, match="materialized project tree changed"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=mutate_copy,
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    source = _project(tmp_path / "root-mode")
    roots = _roots(tmp_path / "root-mode")

    def weaken_root(request):
        request.context.build_root.chmod(0o755)
        return _outputs(request.context.build_root)

    with pytest.raises(FullC6ExecutorError, match="quarantine root changed"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=weaken_root,
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    source = _project(tmp_path / "cross-build")
    roots = _roots(tmp_path / "cross-build")
    first_project = None

    def mutate_prior_copy(request):
        nonlocal first_project
        if first_project is None:
            first_project = request.context.project_root
        else:
            (first_project / "src" / "lib.rs").write_text(
                "mutated after first build\n", encoding="utf-8"
            )
        return _outputs(request.context.build_root)

    with pytest.raises(FullC6ExecutorError, match="materialized project tree changed"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=mutate_prior_copy,
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )


def test_executor_rejects_nonreproducible_builds_and_hardlinked_outputs(tmp_path: Path) -> None:
    from rextio.build.full_c6_executor import FullC6ExecutorError, execute_full_c6_two_build

    source = _project(tmp_path)
    roots = _roots(tmp_path)

    def different(request):
        return _outputs(
            request.context.build_root,
            wheel=f"wheel-{request.context.ordinal}".encode(),
        )

    with pytest.raises(FullC6ExecutorError, match="wheel bytes"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=different,
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )

    source = _project(tmp_path / "hardlink-case")
    roots = _roots(tmp_path / "hardlink-case")

    def hardlinked(request):
        outputs = _outputs(request.context.build_root)
        outputs.sbom_json.unlink()
        os.link(outputs.unsigned_wheel, outputs.sbom_json)
        return outputs

    with pytest.raises(FullC6ExecutorError, match="hardlink|independent"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=hardlinked,
            cargo_command=STRICT_BUILD,
            source_date_epoch=0,
        )


def test_lock_generation_may_only_add_lockfile(tmp_path: Path) -> None:
    from rextio.build.full_c6_executor import FullC6ExecutorError, execute_full_c6_two_build

    source = _project(tmp_path, lock=False)
    roots = _roots(tmp_path)

    def malicious_lock_generator(request):
        (request.project_root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        (request.project_root / "Cargo.toml").write_text("changed\n", encoding="utf-8")

    with pytest.raises(FullC6ExecutorError, match="outside Cargo.lock"):
        execute_full_c6_two_build(
            source,
            *roots,
            build=lambda request: _outputs(request.context.build_root),
            cargo_command=STRICT_BUILD,
            lock_generator=malicious_lock_generator,
            source_date_epoch=0,
        )
    assert list(roots[0].iterdir()) == []


@pytest.mark.parametrize(
    "overrides",
    (
        {"timeout_seconds": 0},
        {"timeout_seconds": float("inf")},
        {"max_output_bytes": 0},
        {"max_output_bytes": 16 * 1024 * 1024 + 1},
        {"source_date_epoch": -1},
    ),
)
def test_executor_rejects_unbounded_time_output_or_epoch(
    tmp_path: Path,
    overrides: dict[str, object],
) -> None:
    from rextio.build.full_c6_executor import execute_full_c6_two_build

    arguments = {
        "build": lambda request: _outputs(request.context.build_root),
        "cargo_command": STRICT_BUILD,
        "source_date_epoch": 0,
        **overrides,
    }
    with pytest.raises((ValueError, RuntimeError), match="bound|timeout|SOURCE_DATE_EPOCH"):
        execute_full_c6_two_build(_project(tmp_path), *_roots(tmp_path), **arguments)
