from __future__ import annotations

from pathlib import Path
import os
import stat
from types import SimpleNamespace

import pytest

from rextio.build import full_c6_linux_launcher as launcher


def _environment() -> dict[str, str]:
    return {
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": "/rextio/build/target",
        "HOME": "/rextio/build/home",
        "LANG": "C",
        "LC_ALL": "C",
        "LD_LIBRARY_PATH": "/rextio/support/runtime-libs",
        "PATH": "/rextio/toolchain/bin:/rextio/toolchain",
        "PYO3_CONFIG_FILE": "/rextio/build/rextio.pyo3-config.txt",
        "PYO3_ENVIRONMENT_SIGNATURE": (
            launcher.expected_linux_pyo3_environment_signature()
        ),
        "SOURCE_DATE_EPOCH": "0",
        "TMPDIR": "/tmp",
        "TZ": "UTC",
    }


def _argv(environment: dict[str, str]) -> tuple[str, ...]:
    return (
        launcher.FULL_C6_LINUX_LAUNCHER,
        "--environment-sha256",
        launcher.linux_payload_environment_digest(environment),
        "--",
        "/rextio/toolchain/cargo",
        "build",
    )


def test_payload_environment_is_closed_canonical_and_digest_bound() -> None:
    environment = _environment()
    rows = launcher.canonical_linux_payload_environment(environment)

    assert rows == tuple(sorted(environment.items()))
    assert len(launcher.linux_payload_environment_digest(environment)) == 64

    extra = dict(environment, HTTP_PROXY="http://host.invalid")
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="closed contract"):
        launcher.canonical_linux_payload_environment(extra)
    missing = dict(environment)
    missing.pop("CARGO_NET_OFFLINE")
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="closed contract"):
        launcher.canonical_linux_payload_environment(missing)


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("HOME", "/private/host"),
        ("PYO3_ENVIRONMENT_SIGNATURE", "not-a-digest"),
        ("SOURCE_DATE_EPOCH", "-1"),
    ),
)
def test_payload_environment_rejects_changed_fixed_or_variable_values(
    name: str, value: str
) -> None:
    environment = _environment()
    environment[name] = value

    with pytest.raises(launcher.FullC6LinuxLauncherError):
        launcher.canonical_linux_payload_environment(environment)


def test_launcher_argv_requires_digest_and_mapped_toolchain_payload() -> None:
    environment = _environment()

    assert launcher.validate_linux_launcher_argv(
        _argv(environment), environment
    ) == ("/rextio/toolchain/cargo", "build")

    changed = list(_argv(environment))
    changed[2] = "e" * 64
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="digest differs"):
        launcher.validate_linux_launcher_argv(changed, environment)
    changed = list(_argv(environment))
    changed[4] = "/usr/bin/cargo"
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="outside"):
        launcher.validate_linux_launcher_argv(changed, environment)
    changed = list(_argv(environment))
    changed.append("bad\nargument")
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="malformed"):
        launcher.validate_linux_launcher_argv(changed, environment)


def test_isolated_python_runtime_accepts_only_canonical_landmark_layout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flags = SimpleNamespace(
        isolated=1,
        ignore_environment=1,
        no_user_site=1,
        no_site=1,
        dont_write_bytecode=1,
        safe_path=True,
    )
    runtime = SimpleNamespace(
        implementation=SimpleNamespace(name="cpython"),
        version_info=(3, 11, 9),
        executable=launcher.FULL_C6_LINUX_PYTHON,
        argv=[launcher.FULL_C6_LINUX_LAUNCHER],
        prefix=launcher.FULL_C6_LINUX_PYTHON_PREFIX,
        exec_prefix=launcher.FULL_C6_LINUX_PYTHON_PREFIX,
        base_prefix=launcher.FULL_C6_LINUX_PYTHON_PREFIX,
        base_exec_prefix=launcher.FULL_C6_LINUX_PYTHON_PREFIX,
        flags=flags,
        path=[
            "/rextio/toolchain/lib/python311.zip",
            launcher.FULL_C6_LINUX_PYTHON_STDLIB,
            f"{launcher.FULL_C6_LINUX_PYTHON_STDLIB}/lib-dynload",
        ],
    )
    monkeypatch.setattr(launcher, "sys", runtime)

    launcher.validate_isolated_python_runtime()
    runtime.prefix = "/usr/local"
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="contract differs"):
        launcher.validate_isolated_python_runtime()


def test_descriptor_boundary_closes_stdin_and_every_extra_fd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[int] = []
    ranges: list[tuple[int, int]] = []
    monkeypatch.setattr(
        os,
        "fstat",
        lambda _fd: os.stat_result((stat.S_IFIFO | 0o600,) + (0,) * 9),
    )
    monkeypatch.setattr(os, "close", closed.append)
    monkeypatch.setattr(os, "sysconf", lambda _name: 4096)
    monkeypatch.setattr(os, "closerange", lambda low, high: ranges.append((low, high)))

    launcher.close_untrusted_file_descriptors()

    assert closed == [0]
    assert ranges == [(3, 4096)]


def test_launcher_revalidates_exact_pyo3_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "rextio.pyo3-config.txt"
    path.write_bytes(launcher._PYO3_CONFIG_CONTENT)
    monkeypatch.setattr(launcher, "_PYO3_CONFIG_PATH", str(path))

    launcher.verify_full_c6_pyo3_config()
    path.write_bytes(launcher._PYO3_CONFIG_CONTENT + b"changed")
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="differs"):
        launcher.verify_full_c6_pyo3_config()


def test_landlock_is_applied_after_namespace_to_all_fixed_roots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    next_fd = 70

    def syscall(*args: object) -> int:
        calls.append(args)
        if args[0] == 444 and getattr(args[2], "value", None) == 0:
            return 3
        if args[0] == 444:
            return 60
        return 0

    def fake_lstat(path: str) -> os.stat_result:
        if path in {"/dev/null", "/dev/random", "/dev/urandom"}:
            mode = stat.S_IFCHR | 0o666
        elif path == "/lib64/ld-linux-x86-64.so.2":
            mode = stat.S_IFREG | 0o755
        else:
            mode = stat.S_IFDIR | 0o755
        return os.stat_result((mode,) + (0,) * 9)

    opened: list[str] = []

    def fake_open(path: str, _flags: int) -> int:
        nonlocal next_fd
        opened.append(path)
        next_fd += 1
        return next_fd

    closed: list[int] = []
    prctl_calls: list[tuple[object, ...]] = []

    def prctl(*args: object) -> int:
        prctl_calls.append(args)
        return 0

    monkeypatch.setattr(os, "lstat", fake_lstat)
    monkeypatch.setattr(os, "open", fake_open)
    monkeypatch.setattr(os, "close", closed.append)

    launcher.apply_full_c6_landlock(
        syscall=syscall,
        prctl=prctl,
    )

    assert opened == [path for path, _access in launcher._LANDLOCK_RULES]
    assert prctl_calls == [(38, 1, 0, 0, 0)]
    assert sum(call[0] == 445 for call in calls) == len(launcher._LANDLOCK_RULES)
    assert calls[-1][:2] == (446, 60)
    assert 60 in closed


def test_landlock_old_abi_and_device_execute_fail_closed() -> None:
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="ABI 3"):
        launcher.apply_full_c6_landlock(
            syscall=lambda *_args: 2,
            prctl=lambda *_args: 0,
        )
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="device"):
        launcher._landlock_access(
            "read-execute", directory=False, character_device=True
        )
    assert launcher._landlock_access(
        "read-write", directory=False, character_device=True
    ) == (1 << 1) | (1 << 2)


def test_launcher_orders_validation_fd_close_landlock_then_exec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment()
    argv = _argv(environment)
    calls: list[object] = []
    monkeypatch.setattr(launcher.sys, "argv", list(argv))
    monkeypatch.setattr(launcher.os, "environ", environment)
    monkeypatch.setattr(
        launcher,
        "validate_isolated_python_runtime",
        lambda: calls.append("runtime"),
    )
    monkeypatch.setattr(
        launcher,
        "verify_full_c6_pyo3_config",
        lambda: calls.append("pyo3"),
    )
    monkeypatch.setattr(
        launcher,
        "close_untrusted_file_descriptors",
        lambda: calls.append("fds"),
    )
    monkeypatch.setattr(
        launcher,
        "apply_full_c6_landlock",
        lambda: calls.append("landlock"),
    )
    monkeypatch.setattr(
        launcher.os,
        "execve",
        lambda executable, payload, env: calls.append(
            ("execve", executable, payload, env)
        ),
    )

    with pytest.raises(launcher.FullC6LinuxLauncherError, match="returned"):
        launcher.run_linux_launcher()

    assert calls[:4] == ["runtime", "pyo3", "fds", "landlock"]
    assert calls[4] == (
        "execve",
        "/rextio/toolchain/cargo",
        ("/rextio/toolchain/cargo", "build"),
        environment,
    )


def test_launcher_file_uses_no_external_imports() -> None:
    source = Path(launcher.__file__).read_text(encoding="utf-8")

    assert "import numpy" not in source
    assert "import rextio" not in source
