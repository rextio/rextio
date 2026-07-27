from __future__ import annotations

from pathlib import Path
import os
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from rextio.artifacts.contract_dialects import (
    CURRENT,
    LINUX_LAUNCHER_DOMAIN,
    PYO3_CONFIG_DOMAIN,
)
from rextio.build import full_c6_linux_launcher as launcher


def _environment() -> dict[str, str]:
    return {
        "AR": "/rextio/toolchain/bin/ar",
        "CC": "/rextio/toolchain/bin/linker",
        "CARGO_BUILD_TARGET": "x86_64-unknown-linux-gnu",
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(
            (
                "--remap-path-prefix=/rextio/project=/rextio/project",
                "--remap-path-prefix=/rextio/build=/rextio/build",
                "-C",
                "linker=/rextio/toolchain/bin/linker",
            )
        ),
        "CARGO_HOME": "/rextio/build/cargo-home",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TARGET_DIR": "/rextio/build/target",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": ("/rextio/toolchain/bin/linker"),
        "COMPILER_PATH": ("/rextio/toolchain/bin:/rextio/support/gcc-toolchain"),
        "HOME": "/rextio/build/home",
        "LANG": "C",
        "LC_ALL": "C",
        "LD": "/rextio/toolchain/bin/ld",
        "LD_LIBRARY_PATH": (
            "/rextio/toolchain/lib:/rextio/python/lib:"
            "/rextio/support/python-library-root:"
            "/x86_64-linux-gnu"
        ),
        "LIBRARY_PATH": ("/rextio/support/gcc-toolchain:/x86_64-linux-gnu"),
        "PATH": "/rextio/toolchain/bin:/rextio/python/bin",
        "PYO3_CONFIG_FILE": "/rextio/support/pyo3-config",
        "PYO3_ENVIRONMENT_SIGNATURE": (launcher.expected_linux_pyo3_environment_signature()),
        "PWD": "/rextio/project",
        "PYTHONHASHSEED": "0",
        "RANLIB": "/rextio/toolchain/bin/ranlib",
        "RUSTC": "/rextio/toolchain/bin/rustc",
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
        launcher.FULL_C6_LINUX_CARGO,
        "build",
    )


def test_launcher_domains_match_the_current_semantic_contract() -> None:
    assert launcher.FULL_C6_LINUX_LAUNCHER_DOMAIN == CURRENT.string_value(LINUX_LAUNCHER_DOMAIN)
    assert launcher.FULL_C6_LINUX_PYO3_CONFIG_DOMAIN == CURRENT.string_value(PYO3_CONFIG_DOMAIN)


def test_payload_environment_is_closed_canonical_and_digest_bound() -> None:
    environment = _environment()
    rows = launcher.canonical_linux_payload_environment(environment)

    assert rows == tuple(sorted(environment.items()))
    assert len(launcher.linux_payload_environment_digest(environment)) == 64
    encoded = environment["CARGO_ENCODED_RUSTFLAGS"]
    assert encoded.split("\x1f") == [
        "--remap-path-prefix=/rextio/project=/rextio/project",
        "--remap-path-prefix=/rextio/build=/rextio/build",
        "-C",
        "linker=/rextio/toolchain/bin/linker",
    ]
    assert {character for character in encoded if ord(character) < 32} == {"\x1f"}
    assert environment["COMPILER_PATH"].split(":") == [
        "/rextio/toolchain/bin",
        "/rextio/support/gcc-toolchain",
    ]
    assert environment["LIBRARY_PATH"].split(":") == [
        "/rextio/support/gcc-toolchain",
        "/x86_64-linux-gnu",
    ]
    assert environment["LD_LIBRARY_PATH"].split(":") == [
        "/rextio/toolchain/lib",
        "/rextio/python/lib",
        "/rextio/support/python-library-root",
        "/x86_64-linux-gnu",
    ]

    extra = dict(environment, HTTP_PROXY="http://host.invalid")
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="closed contract"):
        launcher.canonical_linux_payload_environment(extra)
    missing = dict(environment)
    missing.pop("CARGO_NET_OFFLINE")
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="closed contract"):
        launcher.canonical_linux_payload_environment(missing)
    changed_flags = dict(environment)
    changed_flags["CARGO_ENCODED_RUSTFLAGS"] = encoded.replace("\x1f", "\x1e")
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="fixed"):
        launcher.canonical_linux_payload_environment(changed_flags)


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("AR", "/host/ar"),
        ("CC", "/host/cc"),
        ("COMPILER_PATH", "/host/compiler"),
        ("HOME", "/private/host"),
        ("LD", "/host/ld"),
        ("LD_LIBRARY_PATH", "/host/lib"),
        ("LIBRARY_PATH", "/host/lib"),
        ("PYO3_ENVIRONMENT_SIGNATURE", "not-a-digest"),
        ("PWD", "/private/owner/project"),
        ("RANLIB", "/host/ranlib"),
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

    assert launcher.validate_linux_launcher_argv(_argv(environment), environment) == (
        launcher.FULL_C6_LINUX_CARGO,
        "build",
    )

    changed = list(_argv(environment))
    changed[2] = "e" * 64
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="digest differs"):
        launcher.validate_linux_launcher_argv(changed, environment)
    changed = list(_argv(environment))
    changed[4] = "/rextio/toolchain/bin/rustc"
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="fixed Cargo"):
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
            "/rextio/python/lib/python311.zip",
            launcher.FULL_C6_LINUX_PYTHON_STDLIB,
            f"{launcher.FULL_C6_LINUX_PYTHON_STDLIB}/lib-dynload",
        ],
    )
    monkeypatch.setattr(launcher, "sys", runtime)

    launcher.validate_isolated_python_runtime()
    runtime.prefix = "/usr/local"
    with pytest.raises(launcher.FullC6LinuxLauncherError, match="contract differs"):
        launcher.validate_isolated_python_runtime()


def test_descriptor_boundary_installs_inheritable_eof_and_closes_extra_fds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[int] = []
    ranges: list[tuple[int, int]] = []
    duplicated: list[tuple[int, int, bool]] = []

    def fake_fstat(descriptor: int) -> os.stat_result:
        mode = stat.S_IFIFO | 0o600 if descriptor in {1, 2} else stat.S_IFCHR | 0o666
        return os.stat_result((mode,) + (0,) * 9)

    fake_os = SimpleNamespace(
        O_RDONLY=os.O_RDONLY,
        O_CLOEXEC=getattr(os, "O_CLOEXEC", 0),
        O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0),
        lstat=lambda _path: fake_fstat(0),
        fstat=fake_fstat,
        open=lambda _path, _flags: 9,
        dup2=lambda source, target, *, inheritable: duplicated.append(
            (source, target, inheritable)
        ),
        get_inheritable=lambda _fd: True,
        close=closed.append,
        sysconf=lambda _name: 4096,
        closerange=lambda low, high: ranges.append((low, high)),
    )
    monkeypatch.setattr(launcher, "os", fake_os)

    launcher.close_untrusted_file_descriptors()

    assert duplicated == [(9, 0, True)]
    assert closed == [9]
    assert ranges == [(3, 4096)]


def test_payload_stdin_reads_eof_and_inheritable_sentinel_is_absent() -> None:
    sentinel, writer = os.pipe()
    os.set_inheritable(sentinel, True)
    script = """
import errno
import os
import sys
from rextio.build import full_c6_linux_launcher as launcher

launcher.os.sysconf = lambda _name: 256
launcher.close_untrusted_file_descriptors()
try:
    eof = os.read(0, 1) == b""
except OSError:
    eof = False
try:
    os.fstat(int(sys.argv[1]))
    sentinel_absent = False
except OSError as exc:
    sentinel_absent = exc.errno == errno.EBADF
print(f"{eof}:{sentinel_absent}")
"""
    try:
        completed = subprocess.run(
            [sys.executable, "-c", script, str(sentinel)],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10.0,
            pass_fds=(sentinel,),
        )
    finally:
        os.close(sentinel)
        os.close(writer)

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "True:True"


def test_launcher_revalidates_exact_pyo3_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "pyo3-config"
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
    assert ("/x86_64-linux-gnu", "read") in launcher._LANDLOCK_RULES
    assert all(
        access != "read-execute"
        for path, access in launcher._LANDLOCK_RULES
        if path == "/x86_64-linux-gnu"
    )
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
        launcher._landlock_access("read-execute", directory=False, character_device=True)
    assert launcher._landlock_access("read-write", directory=False, character_device=True) == (
        1 << 1
    ) | (1 << 2)


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
        lambda executable, payload, env: calls.append(("execve", executable, payload, env)),
    )

    with pytest.raises(launcher.FullC6LinuxLauncherError, match="returned"):
        launcher.run_linux_launcher()

    assert calls[:4] == ["runtime", "pyo3", "fds", "landlock"]
    assert calls[4] == (
        "execve",
        launcher.FULL_C6_LINUX_CARGO,
        (launcher.FULL_C6_LINUX_CARGO, "build"),
        environment,
    )


@pytest.mark.parametrize(
    "failure_stage",
    (
        "cpython-runtime",
        "environment-argv",
        "pyo3-config",
        "descriptors",
        "landlock",
        "cargo-exec",
    ),
)
def test_launcher_main_emits_only_the_exact_static_failure_stage(
    failure_stage: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment()
    argv = _argv(environment)
    calls: list[str] = []
    writes: list[tuple[int, bytes]] = []
    private = "/private/runner/project secret diagnostics"

    def stage_action(stage: str, result: object = None):
        def action(*_args: object) -> object:
            calls.append(stage)
            if stage == failure_stage:
                raise RuntimeError(private)
            return result

        return action

    monkeypatch.setattr(launcher.sys, "argv", list(argv))
    monkeypatch.setattr(launcher.os, "environ", environment)
    monkeypatch.setattr(
        launcher,
        "validate_isolated_python_runtime",
        stage_action("cpython-runtime"),
    )
    monkeypatch.setattr(
        launcher,
        "validate_linux_launcher_argv",
        stage_action(
            "environment-argv",
            (launcher.FULL_C6_LINUX_CARGO, "build"),
        ),
    )
    monkeypatch.setattr(
        launcher,
        "verify_full_c6_pyo3_config",
        stage_action("pyo3-config"),
    )
    monkeypatch.setattr(
        launcher,
        "close_untrusted_file_descriptors",
        stage_action("descriptors"),
    )
    monkeypatch.setattr(
        launcher,
        "apply_full_c6_landlock",
        stage_action("landlock"),
    )
    monkeypatch.setattr(
        launcher.os,
        "execve",
        stage_action("cargo-exec"),
    )
    monkeypatch.setattr(
        launcher.os,
        "write",
        lambda descriptor, data: writes.append((descriptor, data)) or len(data),
    )

    assert launcher._main() == 125
    assert calls == list(
        (
            "cpython-runtime",
            "environment-argv",
            "pyo3-config",
            "descriptors",
            "landlock",
            "cargo-exec",
        )[: calls.index(failure_stage) + 1]
    )
    assert writes == [
        (
            2,
            (f"Rextio artifact build Linux launcher failed closed: {failure_stage}\n").encode(
                "ascii"
            ),
        )
    ]
    assert private.encode("utf-8") not in writes[0][1]
    assert len(writes[0][1]) < 128


@pytest.mark.parametrize(
    ("case", "expected_stage"),
    (
        ("pwd-fixed-value", "environment-argv-fixed-value"),
        ("unexpected-lc-ctype", "environment-argv-unexpected-lc-ctype"),
        ("closed-set-missing", "environment-argv-closed-set"),
        ("closed-set-other", "environment-argv-closed-set"),
        ("closed-set-pwd-and-missing", "environment-argv-closed-set"),
        ("fixed-value", "environment-argv-fixed-value"),
        ("variable-value", "environment-argv-variable-value"),
        ("malformed-row", "environment-argv-malformed-row"),
        ("argv-shape", "environment-argv-argv-shape"),
        ("environment-digest", "environment-argv-environment-digest"),
        ("malformed-argument", "environment-argv-malformed-argument"),
        ("payload-executable", "environment-argv-payload-executable"),
    ),
)
def test_launcher_main_classifies_exact_environment_argv_failures(
    case: str,
    expected_stage: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment()
    argv = list(_argv(environment))
    if case == "pwd-fixed-value":
        environment["PWD"] = "/private/owner/project"
    elif case == "unexpected-lc-ctype":
        environment["LC_CTYPE"] = "owner-controlled"
    elif case == "closed-set-missing":
        environment.pop("LANG")
    elif case == "closed-set-other":
        environment["PRIVATE_OWNER_KEY"] = "private-owner-value"
    elif case == "closed-set-pwd-and-missing":
        environment["PWD"] = "/private/owner/project"
        environment.pop("LANG")
    elif case == "fixed-value":
        environment["LANG"] = "private-owner-value"
    elif case == "variable-value":
        environment["SOURCE_DATE_EPOCH"] = "private-owner-value"
    elif case == "malformed-row":

        class EqualStr(str):
            pass

        environment["LANG"] = EqualStr("C")
    elif case == "argv-shape":
        argv[1] = "--private-owner-flag"
    elif case == "environment-digest":
        argv[2] = "e" * 64
    elif case == "malformed-argument":
        argv.append("private-owner\nargument")
    elif case == "payload-executable":
        argv[4] = "/private/owner/cargo"
    else:  # pragma: no cover - the parameter table is closed above
        raise AssertionError("unknown environment/argv test case")

    writes: list[tuple[int, bytes]] = []
    monkeypatch.setattr(launcher.sys, "argv", argv)
    monkeypatch.setattr(launcher.os, "environ", environment)
    monkeypatch.setattr(launcher, "validate_isolated_python_runtime", lambda: None)
    monkeypatch.setattr(
        launcher.os,
        "write",
        lambda descriptor, data: writes.append((descriptor, data)) or len(data),
    )

    assert launcher._main() == 125
    assert writes == [(2, launcher.linux_launcher_failure_marker(expected_stage))]
    marker = writes[0][1]
    for private in (
        b"PRIVATE_OWNER_KEY",
        b"private-owner",
        b"/private/owner",
        b"owner-controlled",
    ):
        assert private not in marker


def test_launcher_main_rejects_injected_environment_argv_error_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _environment()
    writes: list[tuple[int, bytes]] = []
    private = "private-owner-error-text"

    def injected_failure(*_args: object) -> tuple[str, ...]:
        raise launcher.FullC6LinuxLauncherError(
            f"artifact build Linux fixed environment value differs: {private}"
        )

    monkeypatch.setattr(launcher.sys, "argv", list(_argv(environment)))
    monkeypatch.setattr(launcher.os, "environ", environment)
    monkeypatch.setattr(launcher, "validate_isolated_python_runtime", lambda: None)
    monkeypatch.setattr(launcher, "validate_linux_launcher_argv", injected_failure)
    monkeypatch.setattr(
        launcher.os,
        "write",
        lambda descriptor, data: writes.append((descriptor, data)) or len(data),
    )

    assert launcher._main() == 125
    assert writes == [(2, launcher.linux_launcher_failure_marker("environment-argv"))]
    assert private.encode("utf-8") not in writes[0][1]


def test_launcher_file_uses_no_external_imports() -> None:
    source = Path(launcher.__file__).read_text(encoding="utf-8")

    assert "import numpy" not in source
    assert "import rextio" not in source
