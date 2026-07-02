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
    "mnonneg", "mpositive", "munit", "mlogbase", "repr_float", "repr_str", "fixed6",
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
        return f'RextioError::new("OverflowError", "{message}")'

    def overflow_err() -> str:
        return overflow_err_msg("integer overflow")

    def zero_div_err(message: str) -> str:
        if mode == "pyo3":
            return f'pyo3::exceptions::PyZeroDivisionError::new_err("{message}")'
        return f'RextioError::new("ZeroDivisionError", "{message}")'

    def value_err(message: str) -> str:
        if mode == "pyo3":
            return f'pyo3::exceptions::PyValueError::new_err("{message}")'
        return f'RextioError::new("ValueError", "{message}")'

    ret = "PyResult<i64>" if mode == "pyo3" else "Result<i64, RextioError>"
    fret = "PyResult<f64>" if mode == "pyo3" else "Result<f64, RextioError>"
    lines: list[str] = []
    for name in _CHECKED_HELPER_ORDER:
        if name not in used:
            continue
        if name == "fixed6":
            # CPython "%f" formatting: fixed six decimals, but non-finite
            # spellings are lowercase ("nan"; Rust {:.6} prints "NaN").
            # inf/-inf agree between the two.
            lines.extend(
                [
                    "fn __rextio_fixed6(value: f64) -> String {",
                    '    if value.is_nan() { return "nan".to_string(); }',
                    '    format!("{:.6}", value)',
                    "}",
                    "",
                ]
            )
            continue
        if name == "repr_str":
            # CPython str repr (container printing, %r, list.index
            # messages): single-quoted unless
            # the string contains a single quote and no double quote; escapes
            # backslash, the chosen quote, and newline/carriage-return/tab.
            # Other control characters pass through (adequate for messages).
            lines.extend(
                [
                    'fn __rextio_repr_str(value: &str) -> String {',
                    '    let quote = if value.contains(\'\\\'\') && !value.contains(\'"\') { \'"\' } else { \'\\\'\' };',
                    '    let mut out = String::with_capacity(value.len() + 2);',
                    '    out.push(quote);',
                    '    for ch in value.chars() {',
                    '        match ch {',
                    '            \'\\\\\' => out.push_str("\\\\\\\\"),',
                    '            \'\\n\' => out.push_str("\\\\n"),',
                    '            \'\\r\' => out.push_str("\\\\r"),',
                    '            \'\\t\' => out.push_str("\\\\t"),',
                    '            c if c == quote => {',
                    "                out.push('\\\\');",
                    '                out.push(c);',
                    '            }',
                    '            c if (c as u32) < 0x20 || ((c as u32) >= 0x7f && (c as u32) <= 0xa0) => {',
                    '                // CPython repr escapes the remaining C0 controls, DEL,',
                    '                // the C1 range, and U+00A0 NO-BREAK SPACE as \\xNN (NBSP is',
                    '                // not a control but CPython does escape it). Non-printable',
                    '                // characters ABOVE U+00A0 (e.g. U+2028) pass through: exact',
                    '                // classification needs Unicode tables std does not carry -',
                    '                // documented limitation in unsupported-features.md.',
                    r'                out.push_str(&format!("\\x{:02x}", c as u32));',
                    '            }',
                    '            c => out.push(c),',
                    '        }',
                    '    }',
                    '    out.push(quote);',
                    '    out',
                    '}',
                    '',
                ]
            )
            continue
        if name == "repr_float":
            # CPython float repr, for print/logging of floats: shortest
            # roundtrip digits (Rust {:?} provides them), positional form for
            # -4 <= decimal exponent < 16, otherwise scientific with a signed
            # >=2-digit exponent, and lowercase nan/inf spellings. This is what
            # str()/repr() of a float produce in CPython.
            lines.extend(
                [
                    "fn __rextio_repr_float(value: f64) -> String {",
                    '    if value.is_nan() { return "nan".to_string(); }',
                    "    if value.is_infinite() {",
                    '        return if value > 0.0 { "inf".to_string() } else { "-inf".to_string() };',
                    "    }",
                    "    if value == 0.0 {",
                    '        return if value.is_sign_negative() { "-0.0".to_string() } else { "0.0".to_string() };',
                    "    }",
                    "    let magnitude = value.abs();",
                    "    // Shortest correctly-rounded digits, CPython's repr rule: the",
                    "    // smallest precision whose round-half-even rendering parses back",
                    "    // to the same f64. (Rust's {:?} also emits shortest-roundtrip",
                    "    // digits, but its tie-breaking can pick a different last digit",
                    "    // than CPython's - found by fuzzing - so derive the digits the",
                    "    // same way CPython does instead.)",
                    "    let mut sig = String::new();",
                    "    let mut e10: i32 = 0;",
                    "    for precision in 0..=17 {",
                    '        let candidate = format!("{:.*e}", precision, magnitude);',
                    "        if candidate.parse::<f64>() == Ok(magnitude) {",
                    "            let (mantissa, exp) = candidate.split_once('e').expect(\"exp form\");",
                    "            e10 = exp.parse::<i32>().expect(\"exp digits\");",
                    "            let digits: String = mantissa.chars().filter(|c| *c != '.').collect();",
                    "            let trimmed = digits.trim_end_matches('0');",
                    '            sig = if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() };',
                    "            break;",
                    "        }",
                    "    }",
                    "    if sig.is_empty() {",
                    "        // Defensive: 18 significant digits always roundtrip an f64,",
                    "        // so this is unreachable; never panic in a print path.",
                    '        return format!("{:e}", value);',
                    "    }",
                    "    let sig = sig.as_str();",
                    '    let sign = if value < 0.0 { "-" } else { "" };',
                    "    if (-4..16).contains(&e10) {",
                    "        if e10 >= 0 {",
                    "            let int_len = (e10 + 1) as usize;",
                    "            if sig.len() > int_len {",
                    '                format!("{}{}.{}", sign, &sig[..int_len], &sig[int_len..])',
                    "            } else {",
                    '                format!("{}{}{}.0", sign, sig, "0".repeat(int_len - sig.len()))',
                    "            }",
                    "        } else {",
                    '            format!("{}0.{}{}", sign, "0".repeat((-e10 - 1) as usize), sig)',
                    "        }",
                    "    } else {",
                    "        let mantissa_out = if sig.len() > 1 {",
                    '            format!("{}.{}", &sig[..1], &sig[1..])',
                    "        } else {",
                    "            sig.to_string()",
                    "        };",
                    '        format!("{}{}e{}{:02}", sign, mantissa_out, if e10 < 0 { "-" } else { "+" }, e10.abs())',
                    "    }",
                    "}",
                    "",
                ]
            )
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
            # for base == 1 (log(1) is 0) and ValueError for base <= 0 (which
            # includes -inf). A nan or +inf base is valid (returns nan / 0.0), so
            # those pass through.
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
