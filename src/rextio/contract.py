"""Version of the machine-readable tooling contract.

The tooling contract (docs/specs/tooling-contract.md) is the JSON surface that
external tooling — agent skills, LSP servers, editor extensions — consumes
instead of re-implementing analyzer rules. Its version is SemVer over the
*contract shape*, independent of the rextio package version: additive fields
bump minor, renames/removals bump major. Consumers tolerate unknown fields and
degrade to generic guidance when the major version is ahead of what they know.

Both contract surfaces embed this value: ``rextio check --format json`` (and
the ``.rextio/reports/check.json`` report) today, and the planned
``rextio capabilities`` manifest.
"""

from __future__ import annotations

TOOLING_CONTRACT_VERSION = "1.0.0"
