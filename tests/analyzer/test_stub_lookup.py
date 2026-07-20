from __future__ import annotations

from pathlib import Path

import pytest

import rextio.analyzer.stub_inputs as stub_inputs
from rextio.analyzer.stub_inputs import StubInputRecord, StubInputSnapshot, StubInputState


def _snapshot(tmp_path: Path, count: int = 9) -> StubInputSnapshot:
    records = tuple(
        StubInputRecord(
            f"module_{index:04d}.py",
            f"module_{index:04d}.pyi",
            StubInputState.ABSENT,
            False,
        )
        for index in range(count)
    )
    return StubInputSnapshot(tmp_path.resolve(), records)


@pytest.mark.parametrize("index", [0, 4, 8])
def test_for_source_finds_first_middle_and_last_record(tmp_path: Path, index: int) -> None:
    snapshot = _snapshot(tmp_path)
    source = tmp_path / f"module_{index:04d}.py"

    assert snapshot.for_source(source) is snapshot.records[index]


def test_for_source_preserves_missing_key_error(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    source = tmp_path / "module_0045.py"

    with pytest.raises(KeyError) as error:
        snapshot.for_source(source)

    assert error.value.args == (source,)


def test_for_source_uses_bounded_binary_search(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot = _snapshot(tmp_path, count=1_024)
    original_bisect_left = stub_inputs.bisect_left
    key_calls = 0

    def counting_bisect_left(sequence, value, *args, **kwargs):
        nonlocal key_calls
        key = kwargs["key"]

        def counting_key(record):
            nonlocal key_calls
            key_calls += 1
            return key(record)

        return original_bisect_left(sequence, value, *args, key=counting_key)

    monkeypatch.setattr(stub_inputs, "bisect_left", counting_bisect_left)

    assert snapshot.for_source(tmp_path / "module_0777.py").source_path == "module_0777.py"
    assert key_calls <= 11
