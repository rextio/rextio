"""Real-Cargo fixture: one RAII guard per invocation; Drop on return and error.

Skips only when ``cargo`` is unavailable locally. Compiles a minimal crate that
mirrors Core's let-bound guard emission shape and asserts Drop order.
"""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from rextio.plugins.function_scope import core_owned_guard_binding_name

pytestmark = pytest.mark.skipif(
    shutil.which("cargo") is None,
    reason="cargo is required for function-scope guard Drop e2e",
)


def test_one_guard_per_invocation_and_drop_on_return_and_error(tmp_path: Path) -> None:
    binding = core_owned_guard_binding_name("rextio-demo")
    crate = tmp_path / "scope_guard_fixture"
    crate.mkdir()
    (crate / "Cargo.toml").write_text(
        textwrap.dedent(
            """\
            [package]
            name = "scope_guard_fixture"
            version = "0.1.0"
            edition = "2021"
            """
        ),
        encoding="utf-8",
    )
    src = crate / "src"
    src.mkdir()
    # Mirror Core emission: let-bind at function start; Drop covers Ok and Err
    # paths without an explicit epilogue.
    (src / "main.rs").write_text(
        textwrap.dedent(
            f"""\
            use std::cell::RefCell;
            use std::rc::Rc;

            thread_local! {{
                static LOG: RefCell<Vec<&'static str>> = const {{ RefCell::new(Vec::new()) }};
            }}

            fn push(msg: &'static str) {{
                LOG.with(|log| log.borrow_mut().push(msg));
            }}

            struct ScopeGuard {{
                label: &'static str,
            }}

            impl ScopeGuard {{
                fn enter(label: &'static str) -> Self {{
                    push("enter");
                    Self {{ label }}
                }}
            }}

            impl Drop for ScopeGuard {{
                fn drop(&mut self) {{
                    let _ = self.label;
                    push("drop");
                }}
            }}

            fn accepted_ok(x: i64) -> Result<i64, String> {{
                let {binding} = ScopeGuard::enter("ok");
                let _ = &{binding};
                if x < 0 {{
                    return Err("neg".into());
                }}
                Ok(x + 1)
            }}

            fn accepted_err(x: i64) -> Result<i64, String> {{
                let {binding} = ScopeGuard::enter("err");
                let _ = &{binding};
                if x >= 0 {{
                    return Err("early".into());
                }}
                Ok(x)
            }}

            fn main() {{
                LOG.with(|log| log.borrow_mut().clear());
                assert_eq!(accepted_ok(1).unwrap(), 2);
                LOG.with(|log| {{
                    assert_eq!(log.borrow().as_slice(), ["enter", "drop"]);
                }});

                LOG.with(|log| log.borrow_mut().clear());
                assert!(accepted_err(1).is_err());
                LOG.with(|log| {{
                    assert_eq!(log.borrow().as_slice(), ["enter", "drop"]);
                }});

                // Two invocations => two enter/drop pairs (one guard per call).
                LOG.with(|log| log.borrow_mut().clear());
                assert_eq!(accepted_ok(2).unwrap(), 3);
                assert_eq!(accepted_ok(3).unwrap(), 4);
                LOG.with(|log| {{
                    assert_eq!(
                        log.borrow().as_slice(),
                        ["enter", "drop", "enter", "drop"]
                    );
                }});

                // Keep Rc import from being optimized away in some toolchains.
                let _ = Rc::new(0);
            }}
            """
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        ["cargo", "run", "--quiet"],
        cwd=crate,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"cargo run failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
