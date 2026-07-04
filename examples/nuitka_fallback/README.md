# Nuitka Fallback Example

Builds a hybrid wheel where the typed hot paths become native Rust and the
remaining fallback code is compiled by Nuitka instead of shipping as plain
CPython source. Requires a Rust toolchain and Nuitka (`pip install nuitka`).

```text
rextio check examples/nuitka_fallback
rextio build examples/nuitka_fallback --fallback=nuitka
```

What to look for:

- `nuitka_fallback.kernels.sum_squares` and
  `nuitka_fallback.kernels.weighted_sum` are accepted as direct-Rust native
  candidates.
- `nuitka_fallback.report.describe` uses f-strings and dict formatting, so it
  stays on the fallback path - with `--fallback=nuitka` that fallback module
  is compiled into a C extension instead of plain `.py` source.
- The build report (`.rextio/reports/build.json`) shows
  `fallback_build.backend = "nuitka"`, and the wheel carries a platform tag.

Compare performance (native vs. Python fallback for one function):

```text
rextio bench nuitka_fallback.kernels.sum_squares --project-root examples/nuitka_fallback
```

The printed ratio depends on the machine and toolchain; treat it as a smoke
demonstration rather than a benchmark claim. To compare against the plain
CPython fallback packaging, rebuild with `--fallback=cpython` and diff the
build reports.
