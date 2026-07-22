from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
from types import ModuleType

import pytest

pytestmark = pytest.mark.no_toolchain


def _load_diagnostic() -> ModuleType:
    path = Path(__file__).with_name("full_c6_ci_failure_diagnostic.py")
    name = "_rextio_full_c6_ci_failure_diagnostic_tests"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("diagnostic fixture module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


DIAGNOSTIC = _load_diagnostic()


def _zero_counts(names: tuple[str, ...]) -> dict[str, int]:
    return {name: 0 for name in names}


def _substitute_macos_log_process(
    monkeypatch: pytest.MonkeyPatch,
    *,
    script: str,
    ignore_sigterm: bool = False,
) -> tuple[dict[str, object], list[object]]:
    original_popen = DIAGNOSTIC.subprocess.Popen
    seen: dict[str, object] = {}
    children: list[object] = []

    def fake_popen(command: list[str], **kwargs: object) -> object:
        seen["command"] = command
        seen.update(kwargs)
        launch_kwargs = dict(kwargs)
        if ignore_sigterm:

            def ignore_termination() -> None:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)

            launch_kwargs["preexec_fn"] = ignore_termination
        child = original_popen(
            [sys.executable, "-c", script],
            **launch_kwargs,
        )
        children.append(child)
        return child

    monkeypatch.setattr(DIAGNOSTIC.subprocess, "Popen", fake_popen)
    return seen, children


def test_macos_sandbox_log_parser_emits_only_closed_count_families() -> None:
    messages = [
        "Sandbox: cargo(1) deny(1) file-read-data /dev/null",
        "Sandbox: rustc(2) deny(2) file-write-create /private/var/db/secret",
        "Sandbox: clang(3) deny(3) file-map-executable /Applications/Xcode.app/bin/clang",
        "Sandbox: ld(4) deny(4) process-exec /private/etc/private-tool",
        "Sandbox: cc(5) deny(5) sysctl-read hw.ncpu",
        "Sandbox: ar(6) deny(6) mach-lookup private.owner.service",
        "Sandbox: ranlib(7) deny(7) ipc-posix-shm-read private-owner",
        "Sandbox: build-script-build(8) deny(8) network-outbound private.example:443",
        "Sandbox: cargo(9) deny(9) file-write-data /private/var/folders/private/T/item",
        "Sandbox: untrusted(10) deny(10) file-read-data /owner/private",
        "prefix Sandbox: cargo(11) deny(11) file-read-data /owner/private",
    ]
    document = [
        {
            "subsystem": "com.apple.sandbox.reporting",
            "eventMessage": message,
            "privateIgnoredField": "/must/not/escape",
        }
        for message in messages
    ]

    summary = DIAGNOSTIC._parse_macos_sandbox_log_json(
        json.dumps(document).encode("utf-8")
    )

    assert summary["status"] == "ok"
    assert summary["accepted_count"] == 9
    assert summary["process_counts"] == {
        "cargo": 2,
        "rustc": 1,
        "clang": 1,
        "ld": 1,
        "cc": 1,
        "ar": 1,
        "ranlib": 1,
        "build-script-build": 1,
    }
    assert summary["resource_counts"]["private-var-db-other"] == 1
    assert summary["resource_counts"]["private-var-folders"] == 1
    assert summary["resource_counts"]["private-etc-other"] == 1
    assert sum(row["count"] for row in summary["denial_rows"]) == 9
    assert "/must/not/escape" not in json.dumps(summary)
    assert (
        DIAGNOSTIC._macos_sandbox_resource_family(
            operation="file-read",
            resource="/Users/runner/work/_temp/private",
        )
        == "users-runner-work"
    )


def test_macos_sandbox_log_parser_preserves_closed_operation_resource_pairs() -> None:
    messages = [
        "Sandbox: cargo(1) deny(1) file-test-existence /dev/null",
        "Sandbox: rustc(2) deny(2) file-read-data /dev/random",
        "Sandbox: clang(3) deny(3) file-read-metadata /dev/urandom",
        "Sandbox: ld(4) deny(4) file-write-create /dev/tty",
        "Sandbox: cc(5) deny(5) file-map-executable /System/Library/private",
        "Sandbox: ar(6) deny(6) process-exec /usr/bin/private-tool",
        "Sandbox: ranlib(7) deny(7) sysctl-read hw.ncpu",
        "Sandbox: cargo(8) deny(8) sysctl-read hw.private-owner-value",
        "Sandbox: rustc(9) deny(9) mach-lookup private.owner.service",
        "Sandbox: clang(10) deny(10) ipc-posix-shm-read private-owner",
        "Sandbox: ld(11) deny(11) network-outbound private.example:443",
        "Sandbox: cc(12) deny(12) file-read-data /Library/private",
        "Sandbox: ar(13) deny(13) file-read-data /private/etc/private",
        "Sandbox: ranlib(14) deny(14) file-read-data /private/var/private",
        "Sandbox: cargo(15) deny(15) file-read-data /Users/runner/private",
        "Sandbox: rustc(16) deny(16) file-read-data /owner/private",
        "Sandbox: clang(17) deny(17) unknown-operation private-owner",
    ]
    document = [
        {
            "subsystem": "com.apple.sandbox.reporting",
            "eventMessage": message,
            "privateIgnoredField": "/must/not/escape",
        }
        for message in messages
    ]

    summary = DIAGNOSTIC._parse_macos_sandbox_log_json(
        json.dumps(document).encode("utf-8")
    )

    assert summary["accepted_count"] == len(messages)
    assert summary["operation_counts"] == {
        "file-test-existence": 1,
        "file-read": 7,
        "file-write": 1,
        "file-map-exec": 1,
        "process-exec": 1,
        "sysctl-read": 2,
        "mach": 1,
        "ipc": 1,
        "network": 1,
        "other": 1,
    }
    assert summary["resource_counts"]["dev-tty"] == 1
    assert summary["resource_counts"]["library-other"] == 1
    assert summary["resource_counts"]["private-etc-other"] == 1
    assert summary["resource_counts"]["private-var-other"] == 1
    assert summary["resource_counts"]["users-runner-other"] == 1
    assert summary["resource_counts"]["sysctl-hw"] == 1
    assert sum(row["count"] for row in summary["denial_rows"]) == len(messages)
    assert all(
        set(row) == {"process", "operation", "resource", "count"}
        for row in summary["denial_rows"]
    )
    encoded = json.dumps(summary, sort_keys=True)
    assert "/must/not/escape" not in encoded
    assert "private-owner" not in encoded


@pytest.mark.parametrize(
    ("resource", "expected"),
    (
        ("/dev/zero", "dev-zero"),
        ("/dev/tty", "dev-tty"),
        ("/dev/fd/7", "dev-fd"),
        ("/dev/stdin", "dev-stdin"),
        ("/dev/stdout", "dev-stdout"),
        ("/dev/stderr", "dev-stderr"),
        ("/dev/autofs_nowait", "dev-autofs-nowait"),
        ("/dev/dtracehelper", "dev-dtracehelper"),
        (
            "/Library/Preferences/.GlobalPreferences.plist",
            "library-preferences-global",
        ),
        (
            "/Library/Preferences/.GlobalPreferences_m.plist",
            "library-preferences-global-m",
        ),
        ("/Library/Preferences/private", "library-preferences-other"),
        ("/Library/Developer/private", "library-developer"),
        ("/Library/private", "library-other"),
        ("/private/etc/localtime", "private-etc-localtime"),
        ("/private/etc/passwd", "private-etc-passwd"),
        ("/private/etc/group", "private-etc-group"),
        ("/private/etc/hosts", "private-etc-hosts"),
        ("/private/etc/resolv.conf", "private-etc-resolv"),
        ("/private/etc/ssl/private", "private-etc-ssl-other"),
        ("/private/etc/ssl/cert.pem", "private-etc-ssl-cert-pem"),
        ("/private/etc/private", "private-etc-other"),
        ("/private/var/db/timezone/private", "private-var-db-timezone"),
        ("/private/var/db/dyld/private", "private-var-dyld"),
        ("/private/var/db/private", "private-var-db-other"),
        (
            "/private/var/db/DetachedSignatures/private",
            "private-var-db-detached-signatures",
        ),
        (
            "/private/var/db/SystemPolicyConfiguration/private",
            "private-var-db-system-policy",
        ),
        ("/private/var/db/mds/private", "private-var-db-mds"),
        ("/private/var/db/receipts/private", "private-var-db-receipts"),
        ("/private/var/run/private", "private-var-run"),
        ("/private/var/folders/private", "private-var-folders"),
        ("/private/var/private", "private-var-other"),
        ("/Users/runner/hostedtoolcache/private", "users-runner-hostedtoolcache"),
        ("/Users/runner/work/private", "users-runner-work"),
        ("/Users/runner/.cargo/private", "users-runner-cargo"),
        ("/Users/runner/.rustup/private", "users-runner-rustup"),
        ("/Users/runner/Library/private", "users-runner-library"),
        ("/Users/runner/private", "users-runner-other"),
        ("/Users/runner/.CFUserTextEncoding", "users-runner-cf-user-text-encoding"),
        ("/Users/runner/.gitconfig", "users-runner-gitconfig"),
        ("/Users/runner/.netrc", "users-runner-netrc"),
    ),
)
def test_macos_sandbox_resource_family_uses_only_closed_subfamilies(
    resource: str,
    expected: str,
) -> None:
    assert (
        DIAGNOSTIC._macos_sandbox_resource_family(
            operation="file-read",
            resource=resource,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("resource", "expected"),
    (
        ("/Library/Preferences", "library-preferences-root"),
        (
            "/Library/Preferences/.GlobalPreferences",
            "library-preferences-global",
        ),
        (
            "/Library/Preferences/.GlobalPreferences_m",
            "library-preferences-global-m",
        ),
        ("/private/etc/ssl", "private-etc-ssl-root"),
        ("/etc/ssl", "private-etc-ssl-root"),
        ("/private/etc/ssl/openssl.cnf", "private-etc-ssl-openssl-cnf"),
        ("/etc/ssl/openssl.cnf", "private-etc-ssl-openssl-cnf"),
        ("/private/etc/ssl/certs", "private-etc-ssl-certs-directory"),
        ("/etc/ssl/certs", "private-etc-ssl-certs-directory"),
        (
            "/private/etc/ssl/certs/ca-certificates.crt",
            "private-etc-ssl-ca-certificates-crt",
        ),
        (
            "/etc/ssl/certs/ca-certificates.crt",
            "private-etc-ssl-ca-certificates-crt",
        ),
        ("/private/etc/ssl/ca-bundle.pem", "private-etc-ssl-ca-bundle-pem"),
        ("/etc/ssl/ca-bundle.pem", "private-etc-ssl-ca-bundle-pem"),
        ("/private/var/db", "private-var-db-root"),
        ("/var/db", "private-var-db-root"),
        (
            "/private/var/db/ConfigurationProfiles/Settings/private",
            "private-var-db-configuration-profiles",
        ),
        (
            "/var/db/ConfigurationProfiles/Settings/private",
            "private-var-db-configuration-profiles",
        ),
        (
            "/private/var/db/dslocal/nodes/private",
            "private-var-db-dslocal",
        ),
        ("/var/db/dslocal/nodes/private", "private-var-db-dslocal"),
        (
            "/private/var/db/com.apple.xpc.launchd/private",
            "private-var-db-xpc-launchd",
        ),
        (
            "/var/db/com.apple.xpc.launchd/private",
            "private-var-db-xpc-launchd",
        ),
        (
            "/private/var/db/.AppleSetupDone",
            "private-var-db-apple-setup-done",
        ),
        ("/var/db/.AppleSetupDone", "private-var-db-apple-setup-done"),
    ),
)
def test_macos_sandbox_fixed_startup_candidates_use_closed_families(
    resource: str,
    expected: str,
) -> None:
    assert (
        DIAGNOSTIC._macos_sandbox_resource_family(
            operation="file-test-existence",
            resource=resource,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("resource", "expected"),
    (
        ("hw.ncpu", "sysctl-hw-ncpu"),
        ("hw.private", "sysctl-hw"),
        ("kern.private", "sysctl-kern-other"),
        ("kern.osrelease", "sysctl-kern-osrelease"),
        ("kern.osversion", "sysctl-kern-osversion"),
        ("kern.version", "sysctl-kern-version"),
        ("kern.hostname", "sysctl-kern-hostname"),
        ("machdep.private", "sysctl-machdep"),
        ("sysctl.proc_translated", "sysctl-proc-translated"),
        ("private.owner", "sysctl-other"),
    ),
)
def test_macos_sandbox_sysctl_family_uses_only_closed_subfamilies(
    resource: str,
    expected: str,
) -> None:
    assert (
        DIAGNOSTIC._macos_sandbox_resource_family(
            operation="sysctl-read",
            resource=resource,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("resource", "expected"),
    (
        ("kern.argmax", "sysctl-kern-argmax"),
        ("kern.osproductversion", "sysctl-kern-osproductversion"),
        ("kern.bootargs", "sysctl-kern-bootargs"),
        ("kern.boottime", "sysctl-kern-boottime"),
        ("kern.iossupportversion", "sysctl-kern-iossupportversion"),
        ("kern.osvariant_status", "sysctl-kern-osvariant-status"),
    ),
)
def test_macos_sandbox_fixed_kern_sysctls_use_exact_closed_families(
    resource: str,
    expected: str,
) -> None:
    assert (
        DIAGNOSTIC._macos_sandbox_resource_family(
            operation="sysctl-read",
            resource=resource,
        )
        == expected
    )


def test_macos_sandbox_exact_candidate_rows_never_emit_raw_resources() -> None:
    resources = (
        "/dev/autofs_nowait",
        "/Library/Preferences/.GlobalPreferences.plist",
        "/private/etc/ssl/cert.pem",
        "/private/var/db/DetachedSignatures/private-owner",
        "/Users/runner/.gitconfig",
    )
    messages = [
        f"Sandbox: cargo({index}) deny({index}) file-read-data {resource}"
        for index, resource in enumerate(resources, start=1)
    ]
    messages.append("Sandbox: rustc(9) deny(9) sysctl-read kern.osrelease")
    document = [
        {
            "subsystem": "com.apple.sandbox.reporting",
            "eventMessage": message,
            "privateIgnoredField": "/must/not/escape",
        }
        for message in messages
    ]

    summary = DIAGNOSTIC._parse_macos_sandbox_log_json(
        json.dumps(document).encode("utf-8")
    )

    assert summary["accepted_count"] == len(messages)
    encoded = json.dumps(summary, sort_keys=True)
    assert all(resource not in encoded for resource in resources)
    assert "kern.osrelease" not in encoded
    assert "private-owner" not in encoded
    assert "/must/not/escape" not in encoded


def test_macos_sandbox_new_candidate_rows_emit_only_static_labels() -> None:
    resources = (
        "/Library/Preferences/.GlobalPreferences",
        "/private/etc/ssl/openssl.cnf",
        "/private/var/db/ConfigurationProfiles/Settings/private-owner",
    )
    messages = [
        f"Sandbox: cargo({index}) deny({index}) file-test-existence {resource}"
        for index, resource in enumerate(resources, start=1)
    ]
    sysctl_resource = "kern.osproductversion"
    messages.append(
        f"Sandbox: cargo(4) deny(4) sysctl-read {sysctl_resource}"
    )
    document = [
        {
            "subsystem": "com.apple.sandbox.reporting",
            "eventMessage": message,
            "privateIgnoredField": "/must/not/escape",
        }
        for message in messages
    ]

    summary = DIAGNOSTIC._parse_macos_sandbox_log_json(
        json.dumps(document).encode("utf-8")
    )

    assert summary["accepted_count"] == 4
    assert {
        (row["operation"], row["resource"], row["count"])
        for row in summary["denial_rows"]
    } == {
        ("file-test-existence", "library-preferences-global", 1),
        ("file-test-existence", "private-etc-ssl-openssl-cnf", 1),
        (
            "file-test-existence",
            "private-var-db-configuration-profiles",
            1,
        ),
        ("sysctl-read", "sysctl-kern-osproductversion", 1),
    }
    encoded = json.dumps(summary, sort_keys=True)
    assert all(resource not in encoded for resource in resources)
    assert sysctl_resource not in encoded
    assert "private-owner" not in encoded
    assert "/must/not/escape" not in encoded


def test_macos_sandbox_summary_pairs_closed_process_operation_and_resource() -> None:
    messages = [
        "Sandbox: cargo(1) deny(1) file-read-data /dev/zero",
        "Sandbox: rustc(2) deny(2) file-read-data /Library/Preferences/private",
        "Sandbox: cargo(3) deny(3) sysctl-read kern.private-owner",
        "Sandbox: build-script-build(4) deny(4) file-read-data /Users/runner/.cargo/private",
    ]
    document = [
        {
            "subsystem": "com.apple.sandbox.reporting",
            "eventMessage": message,
            "privateIgnoredField": "/must/not/escape",
        }
        for message in messages
    ]

    summary = DIAGNOSTIC._parse_macos_sandbox_log_json(
        json.dumps(document).encode("utf-8")
    )

    assert summary["process_counts"] == {
        "cargo": 2,
        "rustc": 1,
        "clang": 0,
        "ld": 0,
        "cc": 0,
        "ar": 0,
        "ranlib": 0,
        "build-script-build": 1,
    }
    assert summary["denial_rows"] == [
        {
            "process": "cargo",
            "operation": "file-read",
            "resource": "dev-zero",
            "count": 1,
        },
        {
            "process": "cargo",
            "operation": "sysctl-read",
            "resource": "sysctl-kern-other",
            "count": 1,
        },
        {
            "process": "rustc",
            "operation": "file-read",
            "resource": "library-preferences-other",
            "count": 1,
        },
        {
            "process": "build-script-build",
            "operation": "file-read",
            "resource": "users-runner-cargo",
            "count": 1,
        },
    ]
    encoded = json.dumps(summary, sort_keys=True)
    assert "/must/not/escape" not in encoded
    assert "private-owner" not in encoded
    assert "/Users/runner" not in encoded


def test_macos_sandbox_log_query_uses_fixed_bounded_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.dumps(
        [
            {
                "subsystem": "com.apple.sandbox.reporting",
                "eventMessage": "Sandbox: cargo(42) deny(1) file-read-data /Library/private",
            }
        ]
    ).encode("utf-8")
    seen, children = _substitute_macos_log_process(
        monkeypatch,
        script=f"import os; os.write(1, {payload!r})",
    )
    summary = DIAGNOSTIC._query_macos_sandbox_log()

    assert seen["command"] == [
        "/usr/bin/log",
        "show",
        "--last",
        "15m",
        "--style",
        "json",
        "--predicate",
        (
            'subsystem == "com.apple.sandbox.reporting" AND '
            'eventMessage BEGINSWITH "Sandbox:"'
        ),
    ]
    assert seen["stdin"] == DIAGNOSTIC.subprocess.DEVNULL
    assert seen["stdout"] == DIAGNOSTIC.subprocess.PIPE
    assert seen["stderr"] == DIAGNOSTIC.subprocess.DEVNULL
    assert seen["env"] == {"LANG": "C", "LC_ALL": "C"}
    assert len(children) == 1
    assert children[0].poll() == 0
    assert summary["status"] == "ok"
    assert summary["resource_counts"]["library-other"] == 1


def test_macos_sandbox_log_query_fails_closed_with_static_zero_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seen, children = _substitute_macos_log_process(
        monkeypatch,
        script="import os; os.write(1, b'not-json-private-owner-data')",
    )
    summary = DIAGNOSTIC._query_macos_sandbox_log()

    assert summary == {
        "status": "failed-closed",
        "accepted_count": 0,
        "operation_counts": _zero_counts(DIAGNOSTIC.MACOS_SANDBOX_OPERATION_FAMILIES),
        "process_counts": _zero_counts(DIAGNOSTIC._MACOS_SANDBOX_PROCESSES),
        "resource_counts": _zero_counts(DIAGNOSTIC.MACOS_SANDBOX_RESOURCE_FAMILIES),
        "denial_rows": [],
    }
    assert children[0].poll() == 0
    assert "private-owner-data" not in json.dumps(summary)


@pytest.mark.skipif(os.name != "posix", reason="macOS diagnostic uses POSIX pipes")
def test_macos_sandbox_log_capture_reads_only_bound_plus_one_and_reaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seen, children = _substitute_macos_log_process(
        monkeypatch,
        script=(
            "import os\n"
            "chunk = b'x' * 65536\n"
            "while True:\n"
            "    os.write(1, chunk)\n"
        ),
    )
    original_read = DIAGNOSTIC.os.read
    captured_bytes = 0

    def tracked_read(descriptor: int, size: int) -> bytes:
        nonlocal captured_bytes
        if not children or descriptor != children[0].stdout.fileno():
            return original_read(descriptor, size)
        assert size == DIAGNOSTIC.MAX_MACOS_SANDBOX_LOG_BYTES + 1 - captured_bytes
        chunk = original_read(descriptor, size)
        captured_bytes += len(chunk)
        return chunk

    monkeypatch.setattr(DIAGNOSTIC.os, "read", tracked_read)
    summary = DIAGNOSTIC._query_macos_sandbox_log()

    assert summary["status"] == "failed-closed"
    assert captured_bytes == DIAGNOSTIC.MAX_MACOS_SANDBOX_LOG_BYTES + 1
    assert len(children) == 1
    assert children[0].poll() == -signal.SIGTERM


@pytest.mark.skipif(os.name != "posix", reason="macOS diagnostic uses POSIX signals")
def test_macos_sandbox_log_timeout_kills_and_reaps_stubborn_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DIAGNOSTIC, "MACOS_SANDBOX_LOG_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(DIAGNOSTIC, "MACOS_SANDBOX_LOG_REAP_TIMEOUT_SECONDS", 0.05)
    _seen, children = _substitute_macos_log_process(
        monkeypatch,
        script="import time; time.sleep(60)",
        ignore_sigterm=True,
    )

    summary = DIAGNOSTIC._query_macos_sandbox_log()

    assert summary["status"] == "failed-closed"
    assert len(children) == 1
    assert children[0].poll() == -signal.SIGKILL


def _canonical_sha256(domain: str, fields: dict[str, object]) -> str:
    encoded = json.dumps(
        {"domain": domain, **fields},
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _path_sha256(domain: str, field: str, path: str) -> str:
    return _canonical_sha256(domain, {field: path})


def _make_complete_fixture(base: Path, *, reverse: bool = False) -> tuple[Path, Path, Path]:
    app = base / "Xcode.app"
    sdk = app / "sdk"
    clang = app / "clang"
    aliases = app / "aliases"
    for directory in (sdk, clang, aliases):
        directory.mkdir(parents=True, exist_ok=True)

    files = (
        (sdk / "alpha", b"alpha"),
        (sdk / "gamma", b"gamma"),
        (clang / "tool", b"tool"),
    )
    for path, payload in reversed(files) if reverse else files:
        path.write_bytes(payload)
    os.link(sdk / "alpha", sdk / "beta")
    os.link(sdk / "alpha", aliases / "alpha")
    os.link(sdk / "gamma", aliases / "gamma")
    os.link(clang / "tool", aliases / "tool")
    return app, sdk, clang


def _run_macos(
    capfd: pytest.CaptureFixture[str],
    *,
    app: Path,
    sdk: Path,
    clang: Path,
) -> list[dict[str, object]]:
    reporter = DIAGNOSTIC._Reporter()
    DIAGNOSTIC._diagnose_macos(
        reporter,
        app=app,
        support_roots=(("xcode-sdk", sdk), ("xcode-clang-17", clang)),
    )
    return [json.loads(line) for line in capfd.readouterr().out.splitlines()]


def _topology(
    events: list[dict[str, object]],
    label: str,
) -> dict[str, object]:
    return next(
        event
        for event in events
        if event["event"] == "macos-support-hardlink-topology" and event["root"] == label
    )


def test_macos_topology_groups_multiple_support_paths_and_is_deterministic(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    first = _make_complete_fixture(tmp_path / "first")
    second = _make_complete_fixture(tmp_path / "second", reverse=True)

    first_events = _run_macos(
        capfd,
        app=first[0],
        sdk=first[1],
        clang=first[2],
    )
    second_events = _run_macos(
        capfd,
        app=second[0],
        sdk=second[1],
        clang=second[2],
    )
    first_sdk = _topology(first_events, "xcode-sdk")
    second_sdk = _topology(second_events, "xcode-sdk")

    support_domain = DIAGNOSTIC.XCODE_SUPPORT_PATH_POLICY_DOMAIN
    alias_domain = DIAGNOSTIC.XCODE_ALIAS_PATH_POLICY_DOMAIN
    group_domain = DIAGNOSTIC.XCODE_POLICY_GROUP_DOMAIN
    policy_domain = DIAGNOSTIC.XCODE_POLICY_DOMAIN
    alpha_group = _canonical_sha256(
        group_domain,
        {
            "support_relative_path_sha256s": sorted(
                _path_sha256(support_domain, "support_relative_path", path)
                for path in ("alpha", "beta")
            ),
            "link_count": 3,
            "alias_count": 3,
            "alias_path_sha256s": sorted(
                _path_sha256(alias_domain, "app_relative_path", path)
                for path in ("aliases/alpha", "sdk/alpha", "sdk/beta")
            ),
        },
    )
    gamma_group = _canonical_sha256(
        group_domain,
        {
            "support_relative_path_sha256s": [
                _path_sha256(support_domain, "support_relative_path", "gamma")
            ],
            "link_count": 2,
            "alias_count": 2,
            "alias_path_sha256s": sorted(
                _path_sha256(alias_domain, "app_relative_path", path)
                for path in ("aliases/gamma", "sdk/gamma")
            ),
        },
    )
    expected_policy = _canonical_sha256(
        policy_domain,
        {"policy_group_sha256s": sorted((alpha_group, gamma_group))},
    )

    assert first_events[0]["event"] == "macos-diagnostic-summary"
    assert first_sdk == second_sdk
    assert first_sdk == {
        "event": "macos-support-hardlink-topology",
        "root": "xcode-sdk",
        "group_count": 2,
        "support_member_count": 3,
        "tracked_support_member_count": 3,
        "alias_count": 5,
        "complete_alias_group_count": 2,
        "alias_count_mismatch_group_count": 0,
        "max_support_members_per_group": 2,
        "max_alias_members_per_group": 3,
        "max_members_per_group": 3,
        "policy_merkle_domain": policy_domain,
        "policy_merkle_sha256": expected_policy,
        "policy_complete": True,
        "topology_truncated": False,
    }
    clang = _topology(first_events, "xcode-clang-17")
    assert clang["root"] == "xcode-clang-17"
    assert clang["group_count"] == 1
    assert clang["policy_complete"] is True
    first_detail_index = next(
        index
        for index, event in enumerate(first_events)
        if event["event"] == "macos-shared-regular-file"
    )
    assert all(
        event["event"] != "macos-shared-regular-file" for event in first_events[:first_detail_index]
    )
    assert first_detail_index >= 3


def test_macos_topology_reports_alias_mismatch_without_policy(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    app = tmp_path / "Xcode.app"
    sdk = app / "sdk"
    clang = app / "clang"
    outside = tmp_path / "outside"
    for directory in (sdk, clang, outside):
        directory.mkdir(parents=True)
    member = sdk / "member"
    member.write_bytes(b"shared")
    os.link(member, outside / "external-alias")

    events = _run_macos(capfd, app=app, sdk=sdk, clang=clang)
    topology = _topology(events, "xcode-sdk")

    assert topology["group_count"] == 1
    assert topology["support_member_count"] == 1
    assert topology["alias_count"] == 1
    assert topology["complete_alias_group_count"] == 0
    assert topology["alias_count_mismatch_group_count"] == 1
    assert topology["topology_truncated"] is False
    assert topology["policy_complete"] is False
    assert topology["policy_merkle_sha256"] is None


def test_macos_topology_reports_relevant_inode_truncation(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DIAGNOSTIC, "MAX_RELEVANT_INODES", 1)
    app = tmp_path / "Xcode.app"
    sdk = app / "sdk"
    clang = app / "clang"
    aliases = app / "aliases"
    for directory in (sdk, clang, aliases):
        directory.mkdir(parents=True)
    for name in ("one", "two"):
        member = sdk / name
        member.write_bytes(name.encode("ascii"))
        os.link(member, aliases / name)

    events = _run_macos(capfd, app=app, sdk=sdk, clang=clang)
    summary = events[0]
    topology = _topology(events, "xcode-sdk")

    assert summary["tracked_group_count"] == 1
    assert summary["topology_truncated"] is True
    assert topology["group_count"] == 1
    assert topology["support_member_count"] == 2
    assert topology["tracked_support_member_count"] == 1
    assert topology["topology_truncated"] is True
    assert topology["policy_complete"] is False
    assert topology["policy_merkle_sha256"] is None


@pytest.mark.parametrize(
    ("member_count", "expected_complete"),
    ((128, True), (129, False)),
)
def test_macos_topology_member_bound_is_fail_closed(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    member_count: int,
    expected_complete: bool,
) -> None:
    assert DIAGNOSTIC.MAX_TOPOLOGY_MEMBERS_PER_GROUP == 128
    app = tmp_path / "Xcode.app"
    sdk = app / "sdk"
    clang = app / "clang"
    sdk.mkdir(parents=True)
    clang.mkdir(parents=True)
    first = sdk / "member-000"
    first.write_bytes(b"shared")
    for index in range(1, member_count):
        os.link(first, sdk / f"member-{index:03d}")

    events = _run_macos(capfd, app=app, sdk=sdk, clang=clang)
    topology = _topology(events, "xcode-sdk")

    assert topology["group_count"] == 1
    assert topology["support_member_count"] == member_count
    assert topology["alias_count"] == member_count
    assert topology["max_members_per_group"] == member_count
    assert topology["topology_truncated"] is not expected_complete
    assert topology["policy_complete"] is expected_complete
    assert (topology["policy_merkle_sha256"] is not None) is expected_complete


def test_macos_topology_keeps_explicit_scan_and_inode_bounds(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert DIAGNOSTIC.MAX_RELEVANT_INODES >= 16_384
    monkeypatch.setattr(DIAGNOSTIC, "MAX_ROOT_SCAN_ENTRIES", 1)
    app = tmp_path / "Xcode.app"
    sdk = app / "sdk"
    clang = app / "clang"
    sdk.mkdir(parents=True)
    clang.mkdir(parents=True)
    (sdk / "one").write_bytes(b"one")
    (sdk / "two").write_bytes(b"two")

    with pytest.raises(DIAGNOSTIC._ScanBoundExceeded):
        _run_macos(capfd, app=app, sdk=sdk, clang=clang)
