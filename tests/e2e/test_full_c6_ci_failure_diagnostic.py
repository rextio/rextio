from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
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
