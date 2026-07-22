from __future__ import annotations

import json

import pytest

from rextio.build import full_c6_host_inputs as host_inputs
from rextio.build.full_c6_host_inputs import FullC6HostInputsError


@pytest.mark.parametrize(
    "payload",
    (
        b'{"url":"https://one.invalid","url":"https://two.invalid"}',
        b'{"dir_info":{"editable":false,"editable":false}}',
        b'{"archive_info":{"hashes":{"sha256":"a","sha256":"b"}}}',
    ),
)
def test_direct_url_rejects_duplicate_keys_at_every_depth(payload: bytes) -> None:
    with pytest.raises(FullC6HostInputsError, match="malformed"):
        host_inputs._validate_installed_rextio_direct_url(payload)


@pytest.mark.parametrize("constant", (b"NaN", b"Infinity", b"-Infinity"))
def test_direct_url_rejects_nonstandard_json_constants(constant: bytes) -> None:
    payload = b'{"value":' + constant + b"}"
    with pytest.raises(FullC6HostInputsError, match="malformed"):
        host_inputs._validate_installed_rextio_direct_url(payload)


def test_direct_url_depth_is_bounded_and_failure_is_sanitized() -> None:
    value: object = "leaf"
    for _ in range(host_inputs._DIRECT_URL_MAX_DEPTH + 1):
        value = {"nested": value}
    payload = json.dumps(value).encode()

    with pytest.raises(FullC6HostInputsError, match="malformed") as captured:
        host_inputs._validate_installed_rextio_direct_url(payload)

    assert "depth" not in str(captured.value)


@pytest.mark.parametrize("editable", (None, 0, 1, "false", [], {}))
def test_direct_url_editable_must_be_an_exact_bool(editable: object) -> None:
    payload = json.dumps({"dir_info": {"editable": editable}}).encode()
    with pytest.raises(FullC6HostInputsError, match="malformed"):
        host_inputs._validate_installed_rextio_direct_url(payload)


def test_direct_url_allows_absent_or_false_editable_but_forbids_true() -> None:
    host_inputs._validate_installed_rextio_direct_url(
        json.dumps({"url": "https://example.invalid/rextio"}).encode()
    )
    host_inputs._validate_installed_rextio_direct_url(
        json.dumps(
            {
                "url": "file:///bound/rextio",
                "dir_info": {"editable": False},
            }
        ).encode()
    )

    with pytest.raises(FullC6HostInputsError, match="editable.*forbidden"):
        host_inputs._validate_installed_rextio_direct_url(
            json.dumps({"dir_info": {"editable": True}}).encode()
        )
