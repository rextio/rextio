# Contributing to Rextio

Thanks for your interest in Rextio. This guide covers the development setup, the
quality gates your change must pass, and the conventions we follow.

Rextio is **0.1.0 alpha**. The supported subset is intentionally small and the
public surface is still moving; see [docs/stability.md](docs/stability.md) for what
is stable versus experimental, and [docs/versioning.md](docs/versioning.md) for the
versioning policy.

## Development setup

Rextio targets Python 3.11+. Work inside a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e '.[dev]'
```

The `dev` extra pulls in `pytest`, `pytest-cov`, `hypothesis`, `ruff`, and `mypy`.

`rextio build` shells out to external toolchains (Cargo/rustc, optionally `maturin`
and `nuitka`). They are not Python imports — install them only if you work on the
real-build end-to-end tests. `rextio` reports missing tools through its build
preflight check rather than crashing.

## Quality gates

Every change must pass the same gates CI runs. Run them locally before opening a PR:

```bash
ruff check src tests                       # lint
mypy                                       # type-check
python -m pytest tests --ignore=tests/e2e -q   # unit + integration
```

The end-to-end tests under `tests/e2e/` need a real Rust/Cargo toolchain (and, for a
few, Nuitka). They are excluded from the default run and gated in CI behind a label:

```bash
python -m pytest tests/e2e -q              # requires cargo on PATH
```

Guidelines:

- **Add or update tests** for any behavior change. Generated Rust is covered with
  snapshot-style and real-`cargo` tests; analyzer/codegen changes need both the
  accept and reject paths.
- **Diagnostics are part of the contract.** Their codes (`RXTxxx`) and determinism
  are tested; don't change a code or message without updating the tests and, where
  relevant, the docs.
- **Keep the supported subset honest.** If something cannot be lowered correctly, it
  must be *rejected with a diagnostic* or kept on Python fallback — never silently
  mis-compiled.

## Coding conventions

- **Style/format:** `ruff` is the single source of truth. The lint set is ratcheting
  up over time (`E`/`W`/`F` → `I`/`UP`/`B` → `D`); run `ruff check --fix` for the
  autofixable parts. Docstring *format* (pydocstyle `D2`/`D3`/`D4`) is enforced;
  the "missing docstring" family (`D1xx`) is a deliberate future ratchet, not yet
  required on every symbol.
- **Types:** new code is fully typed and must pass `mypy` with no new ignores.
- **Public API:** the public entry points are `rextio.native`, `rextio.exempt`, and
  the `rextio` CLI. Changing their behavior is a compatibility concern — call it out
  in the PR and the changelog.

## Commit and PR conventions

- Use **Conventional Commits** (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`,
  `chore:`, `ci:`). Keep commits small and focused — one logical change each.
- Open a PR against `main`. Fill in the PR template, link any issue, and note
  user-facing changes in `CHANGELOG.md`.
- PRs are squash-merged; the PR title becomes the commit subject, so write it as a
  Conventional Commit.

## Reporting bugs and requesting features

Use the issue templates (Bug report / Feature request). For anything
security-sensitive, **do not open a public issue** — follow
[SECURITY.md](SECURITY.md) instead.
