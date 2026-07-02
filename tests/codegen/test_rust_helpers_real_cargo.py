from __future__ import annotations

import math
import random
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from rextio.codegen.rust.checked_arith import checked_arith_helpers


def _rust_f64_literal(value: float) -> str:
    if math.isnan(value):
        return "f64::NAN"
    if value == math.inf:
        return "f64::INFINITY"
    if value == -math.inf:
        return "f64::NEG_INFINITY"
    return f"{value!r}_f64"


def _rust_str_literal(value: str) -> str:
    out = []
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif code < 0x20 or code == 0x7F or 0x80 <= code <= 0xA0:
            out.append(f"\\u{{{code:x}}}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


@pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is required for helper e2e")
def test_text_helpers_match_cpython(tmp_path: Path) -> None:
    # Compiles the emitted __rextio_repr_float / __rextio_repr_str /
    # __rextio_fixed6 helpers standalone and runs value batteries against
    # CPython-computed expectations. This pins the helper SEMANTICS (repr
    # thresholds, tie-breaking, control-char escaping, %f nan spelling) so an
    # emission change cannot silently regress them - the codegen unit tests
    # only assert that the helpers are referenced.
    helper = "\n".join(
        checked_arith_helpers({"repr_float", "repr_str", "fixed6"}, "crate")
    )

    float_cases = [
        0.0, -0.0, 1.0, -1.5, 0.1, 1e15, 9999999999999998.0, 1e16,
        1.2345678901234567e17, 1e100, 0.0001, 0.00001, 1.5e-5, 5e-324,
        -2.5e-10, 3.14159, 1e308, -1e-308,
        2.7907518603480913e14,  # Ryu/Gay shortest-repr tie-break case
        math.nan, math.inf, -math.inf,
    ]
    rng = random.Random(39)
    while len(float_cases) < 220:
        value = struct.unpack("<d", struct.pack("<Q", rng.getrandbits(64)))[0]
        if not math.isnan(value):
            float_cases.append(value)

    str_cases = [
        "plain", "it's", 'say "hi"', "both ' and \"", "tab\there",
        "line\nbreak", "back\\slash", "ctrl\x01x", "null\x00", "\x1b[31m",
        "del\x7f", "c1\x85", "nbsp\xa0", "유니코드", "",
    ]
    fixed6_cases = [1.5, 0.0, -0.0, 1e10, -2.25, 1e-8, math.nan, math.inf, -math.inf]

    repr_float_rows = "\n".join(
        f'        ({_rust_f64_literal(v)}, {_rust_str_literal(repr(v))}),'
        for v in float_cases
    )
    repr_str_rows = "\n".join(
        f'        ({_rust_str_literal(v)}, {_rust_str_literal(repr(v))}),'
        for v in str_cases
    )
    fixed6_rows = "\n".join(
        f'        ({_rust_f64_literal(v)}, {_rust_str_literal("%f" % v)}),'
        for v in fixed6_cases
    )

    main_rs = f"""{helper}
fn main() {{
    let mut failures = 0u32;
    let float_cases: &[(f64, &str)] = &[
{repr_float_rows}
    ];
    for (value, expected) in float_cases {{
        let got = __rextio_repr_float(*value);
        if got != *expected {{
            println!("repr_float MISMATCH: {{:e}} got {{}} want {{}}", value, got, expected);
            failures += 1;
        }}
    }}
    let str_cases: &[(&str, &str)] = &[
{repr_str_rows}
    ];
    for (value, expected) in str_cases {{
        let got = __rextio_repr_str(value);
        if got != *expected {{
            println!("repr_str MISMATCH: {{:?}} got {{}} want {{}}", value, got, expected);
            failures += 1;
        }}
    }}
    let fixed6_cases: &[(f64, &str)] = &[
{fixed6_rows}
    ];
    for (value, expected) in fixed6_cases {{
        let got = __rextio_fixed6(*value);
        if got != *expected {{
            println!("fixed6 MISMATCH: {{:e}} got {{}} want {{}}", value, got, expected);
            failures += 1;
        }}
    }}
    if failures > 0 {{
        std::process::exit(1);
    }}
    println!(
        "ALL MATCH: {{}} repr_float, {{}} repr_str, {{}} fixed6",
        float_cases.len(), str_cases.len(), fixed6_cases.len()
    );
}}
"""
    crate = tmp_path / "helpers_battery"
    (crate / "src").mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "helpers_battery"\nversion = "0.1.0"\nedition = "2021"\n',
        encoding="utf-8",
    )
    (crate / "src" / "main.rs").write_text(main_rs, encoding="utf-8")

    completed = subprocess.run(
        ["cargo", "run", "--quiet"],
        cwd=crate,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "ALL MATCH" in completed.stdout
