"""Version of the machine-readable tooling contract.

The tooling contract (docs/specs/tooling-contract.md) is the JSON surface that
external tooling — agent skills, LSP servers, editor extensions — consumes
instead of re-implementing analyzer rules. Its version is SemVer over the
*contract shape and position semantics*, independent of the rextio package
version: additive fields bump minor, renames/removals/semantic changes that
would mislead old consumers bump major. Consumers tolerate unknown fields and
degrade to generic guidance when the major version is outside what they know.

Both contract surfaces embed this value: ``rextio check --format json`` (and
the ``.rextio/reports/check.json`` report) and ``rextio capabilities``.
"""

from __future__ import annotations

# 2.0.0 is a *protocol* contract major (not a package release claim). It breaks
# RXT000 column semantics so every diagnostic column is a 0-based UTF-8 byte
# offset (ast.col_offset convention). Contract 1.x left RXT000 as CPython's
# 1-based Unicode code-point SyntaxError.offset. See
# docs/specs/tooling-contract.md §Contract versioning and §Positions.
TOOLING_CONTRACT_VERSION = "2.0.0"
