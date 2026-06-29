<!--
Title: use a Conventional Commit subject (feat:/fix:/refactor:/test:/docs:/chore:/ci:).
It becomes the squash-merge commit message.
-->

## Summary

<!-- What does this change and why? Link the issue it closes (e.g. "Closes #123"). -->

## Changes

<!-- Bullet the notable changes. -->

-

## Checklist

- [ ] `ruff check src tests` passes
- [ ] `mypy` passes
- [ ] `python -m pytest tests --ignore=tests/e2e -q` passes
- [ ] Tests added/updated for the behavior change (accept **and** reject paths where relevant)
- [ ] `CHANGELOG.md` updated for any user-facing change
- [ ] Public-API or supported-subset impact called out below (or "none")

## Compatibility / scope notes

<!--
Does this change `rextio.native`/`rextio.exempt`, the CLI surface, diagnostics
(RXTxxx codes/messages), config keys, or what compiles to native vs. falls back?
If yes, describe the impact. If no, write "none".
-->
