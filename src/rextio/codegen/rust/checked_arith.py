"""Checked-arithmetic Rust helper emission for the code generator.

Emits the ``__rextio_checked_*`` Rust helpers that give i64/f64 arithmetic
Python semantics (catchable OverflowError/ZeroDivisionError/ValueError in the
pyo3 extension, RextioError in the Rust-importable crate). Extracted from
``generator.py`` unchanged; the renderer records which helpers it uses and this
module emits exactly those.
"""

from __future__ import annotations

# Order is fixed so emitted helpers are deterministic regardless of use order.
_CHECKED_BINOP_METHOD = {"add": "checked_add", "sub": "checked_sub", "mul": "checked_mul"}
_CHECKED_HELPER_ORDER = (
    "add", "sub", "mul", "rem", "neg", "abs", "sum", "fdiv", "frem", "f2i",
    "mnonneg", "mpositive", "munit", "mlogbase",
)


def checked_arith_helpers(used: set[str], mode: str) -> list[str]:
    """Emit the ``__rextio_checked_*`` helpers in ``used``.

    ``used`` is the structurally-recorded set of helper names referenced by the
    rendered functions, so a module gains exactly the helpers it calls and no
    dead code. The pyo3 variant raises ``OverflowError`` / ``ZeroDivisionError``;
    the crate variant returns ``RextioError``.
    """

    def overflow_err_msg(message: str) -> str:
        if mode == "pyo3":
            return f'pyo3::exceptions::PyOverflowError::new_err("{message}")'
        return f'RextioError::new("{message}")'

    def overflow_err() -> str:
        return overflow_err_msg("integer overflow")

    def zero_div_err(message: str) -> str:
        if mode == "pyo3":
            return f'pyo3::exceptions::PyZeroDivisionError::new_err("{message}")'
        return f'RextioError::new("{message}")'

    def value_err(message: str) -> str:
        if mode == "pyo3":
            return f'pyo3::exceptions::PyValueError::new_err("{message}")'
        return f'RextioError::new("{message}")'

    ret = "PyResult<i64>" if mode == "pyo3" else "Result<i64, RextioError>"
    fret = "PyResult<f64>" if mode == "pyo3" else "Result<f64, RextioError>"
    lines: list[str] = []
    for name in _CHECKED_HELPER_ORDER:
        if name not in used:
            continue
        fn = f"__rextio_checked_{name}"
        if name in _CHECKED_BINOP_METHOD:
            method = _CHECKED_BINOP_METHOD[name]
            lines.extend(
                [
                    f"fn {fn}(a: i64, b: i64) -> {ret} {{",
                    f"    a.{method}(b).ok_or_else(|| {overflow_err()})",
                    "}",
                    "",
                ]
            )
        elif name == "rem":
            # Python `%` is floored (the result takes the divisor's sign), while
            # Rust's `checked_rem` is truncated (it takes the dividend's sign), so
            # `-7 % 3` is 2 in Python but -1 in Rust. Correct the sign when the
            # truncated remainder and the divisor differ in sign. `a % 0` is a
            # ZeroDivisionError. `checked_rem` returns `None` only for the single
            # overflowing case `i64::MIN % -1`, whose remainder is 0 in both
            # Python and Rust, so `unwrap_or(0)` is exact there (not a catch-all).
            # `|r| < |b|`, so the `r + b` correction cannot overflow.
            lines.extend(
                [
                    f"fn {fn}(a: i64, b: i64) -> {ret} {{",
                    f'    if b == 0 {{ return Err({zero_div_err("integer modulo by zero")}); }}',
                    "    let r = a.checked_rem(b).unwrap_or(0);",
                    "    Ok(if r != 0 && (r ^ b) < 0 { r + b } else { r })",
                    "}",
                    "",
                ]
            )
        elif name == "neg":
            lines.extend(
                [
                    f"fn {fn}(a: i64) -> {ret} {{",
                    f"    a.checked_neg().ok_or_else(|| {overflow_err()})",
                    "}",
                    "",
                ]
            )
        elif name == "abs":
            # `i64::MIN.abs()` overflows (Python `abs(-2**63) == 2**63`).
            lines.extend(
                [
                    f"fn {fn}(a: i64) -> {ret} {{",
                    f"    a.checked_abs().ok_or_else(|| {overflow_err()})",
                    "}",
                    "",
                ]
            )
        elif name == "sum":
            # Python `sum` is arbitrary precision; fold with checked addition so an
            # i64 overflow raises instead of panicking in `Iterator::sum`.
            lines.extend(
                [
                    f"fn {fn}(xs: &[i64]) -> {ret} {{",
                    f"    xs.iter().copied().try_fold(0i64, |acc, x| "
                    f"acc.checked_add(x).ok_or_else(|| {overflow_err()}))",
                    "}",
                    "",
                ]
            )
        elif name == "fdiv":
            # Python raises ZeroDivisionError for `x / 0.0`; Rust returns inf/NaN.
            lines.extend(
                [
                    f"fn {fn}(a: f64, b: f64) -> {fret} {{",
                    f'    if b == 0.0 {{ return Err({zero_div_err("float division by zero")}); }}',
                    "    Ok(a / b)",
                    "}",
                    "",
                ]
            )
        elif name == "f2i":
            # `math.floor`/`ceil`/`trunc` return a Python int (arbitrary
            # precision). A bare `as i64` cast saturates a value outside i64 range
            # to i64::MIN/MAX (a silent wrong value), so guard the conversion:
            # NaN -> ValueError, infinity/out-of-range -> OverflowError (a
            # catchable error rather than a silent saturation; full arbitrary
            # precision is a separate future item). The bounds use 2^63 exactly
            # (representable in f64); i64's valid range is [-2^63, 2^63 - 1].
            lines.extend(
                [
                    f"fn {fn}(x: f64) -> {ret} {{",
                    f'    if x.is_nan() {{ return Err({value_err("cannot convert float NaN to integer")}); }}',
                    "    if x >= -9223372036854775808.0 && x < 9223372036854775808.0 {",
                    "        Ok(x as i64)",
                    "    } else {",
                    f'        Err({overflow_err_msg("float out of range for conversion to integer")})',
                    "    }",
                    "}",
                    "",
                ]
            )
        elif name == "frem":
            # Python raises ZeroDivisionError for `x % 0.0` (message "float
            # modulo"), and float `%` is floored (the result takes the divisor's
            # sign) like the integer case, whereas Rust `%` is truncated. Mirror
            # CPython's `float_rem`: when the remainder is exactly zero, the result
            # is zero with the *divisor's* sign (`copysign(0.0, b)`), not the
            # dividend's sign that Rust's `fmod` would keep.
            lines.extend(
                [
                    f"fn {fn}(a: f64, b: f64) -> {fret} {{",
                    f'    if b == 0.0 {{ return Err({zero_div_err("float modulo")}); }}',
                    "    let r = a % b;",
                    "    Ok(if r == 0.0 { (0.0_f64).copysign(b) }",
                    "       else if (r < 0.0) != (b < 0.0) { r + b }",
                    "       else { r })",
                    "}",
                    "",
                ]
            )
        elif name in {"mnonneg", "mpositive", "munit"}:
            # Math domain guards validate the *input* (a nan/inf input returns
            # nan/inf in CPython, so an output-finiteness check would wrongly
            # raise — and could not even distinguish sqrt(-1)=NaN from
            # sqrt(nan)=NaN). Each returns the validated value or raises
            # ValueError, and the caller then applies the math method.
            #   mnonneg  -> sqrt        (CPython raises for x < 0)
            #   mpositive-> log/log2/log10 (CPython raises for x <= 0)
            #   munit    -> acos/asin   (CPython raises for |x| > 1)
            condition = {
                "mnonneg": "value < 0.0",
                "mpositive": "value <= 0.0",
                "munit": "value < -1.0 || value > 1.0",
            }[name]
            lines.extend(
                [
                    f"fn {fn}(value: f64) -> {fret} {{",
                    f"    if {condition} {{",
                    f'        Err({value_err("math domain error")})',
                    "    } else {",
                    "        Ok(value)",
                    "    }",
                    "}",
                    "",
                ]
            )
        elif name == "mlogbase":
            # `math.log(x, base)` base domain: CPython raises ZeroDivisionError
            # for base == 1 (log(1) is 0) and ValueError for base <= 0. A nan/inf
            # base is valid (returns nan / 0.0), so it passes through.
            lines.extend(
                [
                    f"fn {fn}(value: f64) -> {fret} {{",
                    "    if value == 1.0 {",
                    f'        Err({zero_div_err("float division by zero")})',
                    "    } else if value <= 0.0 {",
                    f'        Err({value_err("math domain error")})',
                    "    } else {",
                    "        Ok(value)",
                    "    }",
                    "}",
                    "",
                ]
            )
    return lines
