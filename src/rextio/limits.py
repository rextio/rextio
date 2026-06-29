"""Shared numeric limits with no internal Rextio dependencies.

Both the build layer (which enforces them at the subprocess boundary in
``rextio.build.subprocess_utils``) and the config layer (which validates
user-supplied values against them) import these from here, so neither layer has to
depend on the other for a constant.
"""

from __future__ import annotations

# Default per-invocation timeout for an external build tool (cargo/maturin/nuitka).
DEFAULT_BUILD_TIMEOUT_SECONDS = 600

# Upper bound on a configured build timeout. 7 days is comfortably below the
# Windows ``WaitForSingleObject`` millisecond ``DWORD`` limit (~49.7 days) and far
# within POSIX ``PyTime_t``, so it is a cross-platform-safe ceiling; beyond it a
# build timeout is a configuration mistake. A finite-but-absurd value (e.g. 1e100)
# would otherwise both disable the bound and overflow the C-level wait/select.
MAX_BUILD_TIMEOUT_SECONDS = 604_800  # 7 days
