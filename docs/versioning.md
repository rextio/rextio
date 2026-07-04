# Versioning policy

Rextio follows [Semantic Versioning 2.0.0](https://semver.org/), with the
explicit pre-1.0 caveats below. The current release is **0.1.0**, an alpha-stage release.

## Pre-1.0 (0.x): what "alpha" means

While Rextio is `0.x`, SemVer permits breaking changes in any release, and Rextio
uses that allowance:

- The **`0.MINOR`** number may carry breaking changes — to the CLI surface, the
  `rextio.toml` schema, diagnostic codes/messages, the public decorators, or which
  Python is accepted as native versus kept on fallback.
- The **`0.MINOR.PATCH`** number is for backward-compatible fixes and additions
  within a minor line.

Every user-facing change — breaking or not — is recorded in
[CHANGELOG.md](../CHANGELOG.md). Read it before upgrading.

## What counts as a public contract

Stability promises apply **only to the Stable tier** in
[docs/stability.md](stability.md) — not to every flag, key, or code that happens to
exist. Concretely, the public contract today is the Stable-tier surface:

- the Stable `rextio` CLI commands and their documented flags;
- the `rextio.native` and `rextio.exempt` decorators;
- the `rextio.toml` configuration keys for Stable features;
- the diagnostic codes (`RXTxxx`) emitted by Stable behavior, and their meaning;
- which supported-subset constructs compile to native versus fall back to Python.

Anything marked **Experimental** in the stability doc — including its flags
(e.g. `--embed-helpers`, `--fallback=nuitka`), its config keys (e.g. `[embedding]`), and its
diagnostic codes (e.g. `RXT080`) — and any underscore-prefixed or otherwise internal
symbol, may change or be removed in any release without a deprecation period.

## Deprecation

When a Stable behavior is slated for removal, we will:

1. mark it deprecated in the CHANGELOG and, where it is reachable at runtime, emit a
   `DeprecationWarning` (the CLI surfaces Rextio's own deprecation warnings);
2. keep it working for at least one subsequent `0.MINOR` release before removal.

Experimental features carry no such guarantee.

## Toward 1.0

`1.0.0` will be cut once the supported subset, the CLI, the config schema, and the
diagnostic set are considered stable enough to commit to under full SemVer. Until
then, pin a version you have tested against.
