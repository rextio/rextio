from __future__ import annotations

import stat
from pathlib import Path

import pytest

from rextio.fallback.nuitka import build_nuitka_fallback


def _fake_nuitka(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake `nuitka` that records its invocations and produces a fake .so."""
    bin_dir = tmp_path / "fake-nuitka-bin"
    bin_dir.mkdir()
    log = tmp_path / "nuitka-calls.log"
    nuitka = bin_dir / "nuitka"
    nuitka.write_text(
        "#!/bin/sh\n"
        "# Answer the preflight version probe without logging or touching files.\n"
        'if [ "$1" = --version ]; then echo 2.4.8; exit 0; fi\n'
        f'echo "$@" >> "{log}"\n'
        "# second argv entry is the --module target path\n"
        'target="$2"\n'
        'touch "${target%.py}.so"\n',
        encoding="utf-8",
    )
    nuitka.chmod(nuitka.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}:{Path('/usr/bin')}", prepend=None)
    return log


def test_numba_modules_are_kept_plain_python(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A fallback module whose functions carry a recognized external-accelerator
    # decorator must NOT be Nuitka-compiled: a compiled sibling would shadow the
    # .py and the tool (e.g. Numba) needs the original bytecode at runtime.
    python_dir = tmp_path / "python"
    (python_dir / "app").mkdir(parents=True)
    (python_dir / "app" / "__init__.py").write_text("", encoding="utf-8")
    (python_dir / "app" / "kernels.py").write_text(
        """
from numba import njit

@njit(cache=True)
def total(n: int) -> int:
    acc = 0
    for i in range(n):
        acc += i
    return acc
""",
        encoding="utf-8",
    )
    (python_dir / "app" / "plain.py").write_text(
        "def double(x):\n    return x * 2\n", encoding="utf-8"
    )
    log = _fake_nuitka(tmp_path, monkeypatch)

    result = build_nuitka_fallback(python_dir)

    assert result.status == "built"
    calls = log.read_text(encoding="utf-8")
    assert "plain.py" in calls  # ordinary module compiled
    assert "kernels.py" not in calls  # accelerated module untouched
    assert (python_dir / "app" / "plain.so").exists()
    assert not (python_dir / "app" / "kernels.so").exists()
    assert "Kept as plain Python for external accelerators" in result.message
    assert "app/kernels.py" in result.message


def test_all_modules_accelerated_still_reports_built(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    python_dir = tmp_path / "python"
    python_dir.mkdir()
    (python_dir / "k.py").write_text(
        "import numba\n\n@numba.njit\ndef f(x: int) -> int:\n    return x\n",
        encoding="utf-8",
    )
    log = _fake_nuitka(tmp_path, monkeypatch)

    result = build_nuitka_fallback(python_dir)

    assert result.status == "built"
    assert not log.exists()  # no compilation was invoked
    assert "Kept as plain Python for external accelerators" in result.message


def test_mixed_module_wrapper_compiles_while_fallback_copy_stays_plain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Mirrors the generated layout for a source module holding BOTH a native
    # function and a numba function: the public module becomes a plain wrapper
    # (no numba import) and the original source moves to `_fallback_<stem>.py`.
    # The wrapper must compile; the fallback copy (bearing the numba decorator)
    # must stay plain so the accelerated function keeps real bytecode.
    python_dir = tmp_path / "python"
    (python_dir / "hb").mkdir(parents=True)
    (python_dir / "hb" / "__init__.py").write_text("", encoding="utf-8")
    (python_dir / "hb" / "mixed.py").write_text(
        """
from hb._fallback_mixed import total

def fast(x):
    return x + 1
""",
        encoding="utf-8",
    )
    (python_dir / "hb" / "_fallback_mixed.py").write_text(
        """
from numba import njit

@njit
def total(n: int) -> int:
    acc = 0
    for i in range(n):
        acc += i
    return acc

def fast(x: int) -> int:
    return x + 1
""",
        encoding="utf-8",
    )
    log = _fake_nuitka(tmp_path, monkeypatch)

    result = build_nuitka_fallback(python_dir)

    assert result.status == "built"
    calls = log.read_text(encoding="utf-8")
    assert "mixed.py" in calls  # wrapper compiled
    assert "_fallback_mixed.py" not in calls  # numba-bearing copy untouched
    assert (python_dir / "hb" / "mixed.so").exists()
    assert not (python_dir / "hb" / "_fallback_mixed.so").exists()
    assert "hb/mixed.py (fallback copy)" in result.message


def test_project_local_numba_module_is_compiled_normally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A project that SHIPS its own `numba.py` shim is not using the external
    # accelerator: nothing may be skipped, and both modules compile.
    python_dir = tmp_path / "python"
    python_dir.mkdir()
    (python_dir / "numba.py").write_text("def njit(func):\n    return func\n", encoding="utf-8")
    (python_dir / "app.py").write_text(
        "import numba\n\n@numba.njit\ndef f(x: int) -> int:\n    return x\n",
        encoding="utf-8",
    )
    log = _fake_nuitka(tmp_path, monkeypatch)

    result = build_nuitka_fallback(python_dir)

    assert result.status == "built"
    calls = log.read_text(encoding="utf-8")
    assert "app.py" in calls
    assert "numba.py" in calls
    assert "Kept as plain Python" not in result.message


def test_pre_2_nuitka_fails_the_fallback_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The Nuitka integration is validated against the 2.x CLI; an older
    # install fails up front with upgrade guidance instead of mid-build.
    bin_dir = tmp_path / "old-nuitka-bin"
    bin_dir.mkdir()
    nuitka = bin_dir / "nuitka"
    nuitka.write_text(
        '#!/bin/sh\nif [ "$1" = --version ]; then echo 1.9.7; exit 0; fi\n', encoding="utf-8"
    )
    nuitka.chmod(nuitka.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")

    python_dir = tmp_path / "python"
    python_dir.mkdir()
    (python_dir / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    result = build_nuitka_fallback(python_dir)

    assert result.status == "failed"
    assert "too old" in result.message
    assert ">= 2.0" in result.message
