from __future__ import annotations

import shutil


def maturin_available() -> bool:
    return shutil.which("maturin") is not None
