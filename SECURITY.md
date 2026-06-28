# Security model — Rextio 0.1.0 alpha

Rextio turns typed Python into Rust/PyO3 native artifacts: it analyzes your
source, generates Rust, and invokes external build tools. That makes its trust
surface larger than an ordinary library, so this document states the threat
model and the protections in place.

## Trust boundary

**Rextio trusts the project it is asked to build.** Treat `rextio` like a
compiler or `make`: only run it on source you trust, in an environment you
control. Building an untrusted project can run that project's build logic and the
external toolchain on your machine.

## What executes user code, and when

- **Analysis is static.** `rextio check`, `rextio generate`, and native discovery
  parse your source with `ast.parse` only — they do **not** import, `exec`, or
  `eval` your modules. Dynamic constructs (`eval`/`exec`/`__import__`/`getattr`…)
  are *rejected* from the native subset, not executed by Rextio.
- **Building invokes external tools.** `rextio build` shells out to `cargo`,
  `maturin`, and (optionally) `nuitka`. See the subprocess protections below.
- **Running the artifact executes code.** `rextio bench` and importing a built
  hybrid module load and run the generated/compiled code, as any build tool's
  output does. Run built artifacts with the same trust you'd give any compiled
  program.

## Protections

- **No shell.** Every external tool is invoked with an argument **list**
  (`shell=False`); user-derived paths, identifiers, and string literals are never
  interpolated into a shell command, so there is no shell injection.
- **Bounded execution.** Tool invocations run under a timeout (default 600s) and
  surface stdout/stderr as diagnostics; a hung toolchain fails the build instead
  of blocking indefinitely.
- **Safe code generation.** User-provided string literals are escaped into Rust
  string literals that cannot break out of the string and are always valid Rust
  (including non-ASCII), so a crafted literal cannot inject Rust code. List
  indexing, integer/float arithmetic, and conversions are lowered to checked
  operations that raise catchable Python exceptions rather than panicking.
- **No runtime dependencies.** Rextio itself declares no Python runtime
  dependencies; the external toolchains are optional extras surfaced by the build
  preflight when missing.

## Supply chain

- Generated crates depend on a small, fixed set of crates — `pyo3`, `base64`,
  `chrono`, `log`, and (only with `--jit`) the feature-gated `cranelift-*` crates.
  The generated `Cargo.toml` constrains each to a compatible version range, and
  `cargo build` produces a `Cargo.lock` recording the exact resolved graph for
  reproducible builds.
- Rextio does not fetch or execute network content during analysis. `cargo`
  fetches crates during `build`; run builds in an environment with a trusted
  registry/mirror, and vendor or lock dependencies for air-gapped or
  reproducibility-sensitive builds.

## Reporting

This is a 0.1.0 alpha. To report a security issue, open a GitHub issue marked
`security` (or contact the maintainer privately if the report is sensitive).
There is no formal embargo process yet; please allow time for a fix before public
disclosure.
