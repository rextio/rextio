"""Rust source for the executable's subprocess-hybrid IPC client.

Rendered into the generated Rust binary crate when the executable delegates
non-native calls to an external CPython process (Phase 2 of the Rust-``main``
backend). The client lazily launches the generated dispatcher
(``rextio.codegen.subprocess_dispatcher``), talks to it over stdio using the
newline-delimited JSON wire protocol, and maps a Python exception back to a
``RextioError`` carrying the CPython exception type name.
"""

from __future__ import annotations

# The runtime directory (dispatcher + fallback Python tree) is placed next to the
# executable as ``<exe>.runtime`` by the build; the client resolves it from the
# executable's own path so the binary is relocatable.
RUNTIME_DIR_SUFFIX = ".runtime"


def _rust_string_literal(value: str) -> str:
    """Escape a plain string (an interpreter path) for a Rust string literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


# The Nuitka-compiled dispatcher is a self-contained executable shipped in the
# runtime directory under this name; the binary launches it directly (no Python).
NUITKA_DISPATCHER_NAME = "dispatcher"


def render_subprocess_client(python_command: str = "python3", *, nuitka_dispatcher: bool = False) -> str:
    """Return the Rust source for the ``__rextio_call_python`` IPC client.

    In the default (source) mode the binary launches ``python3`` on
    ``<exe>.runtime/dispatcher.py``; ``python_command`` sets that interpreter (a
    bare name on ``PATH``, an absolute path, or a relative path resolved against
    the runtime directory) and ``REXTIO_PYTHON`` overrides it at run time. When
    ``nuitka_dispatcher`` is set the runtime ships a Nuitka-compiled, self-contained
    dispatcher executable instead, which the binary launches directly (no Python).
    """
    baked = _rust_string_literal(python_command)
    if nuitka_dispatcher:
        spawn_block = (
            f'let mut child = Command::new(runtime_dir.join("{NUITKA_DISPATCHER_NAME}"))'
        )
    else:
        spawn_block = (
            'let python = std::env::var("REXTIO_PYTHON")'
            '.unwrap_or_else(|_| "{PYTHON_COMMAND}".to_string());\n'
            '        let python_path = __rextio_resolve_python(&runtime_dir, &python);\n'
            '        let mut child = Command::new(python_path).arg(runtime_dir.join("dispatcher.py"))'
        )
    return '''
// ---- Rextio subprocess-hybrid IPC client ----------------------------------
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};

struct RextioBridge {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

fn __rextio_runtime_dir() -> Result<std::path::PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("Rextio: cannot resolve current executable path: {}", e))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "Rextio: executable has no parent directory".to_string())?
        .to_path_buf();
    let file = exe
        .file_name()
        .ok_or_else(|| "Rextio: executable has no file name".to_string())?
        .to_string_lossy()
        .into_owned();
    // The build names the runtime dir after the binary without any `.exe`
    // extension; strip it on Windows so `<name>.exe` still finds `<name>.runtime`.
    #[cfg(windows)]
    let name = file.strip_suffix(".exe").map(str::to_string).unwrap_or(file);
    #[cfg(not(windows))]
    let name = file;
    Ok(dir.join(format!("{}{RUNTIME_DIR_SUFFIX}", name)))
}

#[allow(dead_code)]
fn __rextio_finite(x: f64) -> Result<f64, RextioError> {
    if x.is_finite() {
        Ok(x)
    } else {
        Err(RextioError::new(
            "ValueError",
            "cannot delegate a non-finite float (NaN/Infinity) across the subprocess boundary",
        ))
    }
}

#[allow(dead_code)]
fn __rextio_resolve_python(runtime_dir: &std::path::Path, python: &str) -> std::path::PathBuf {
    let path = std::path::Path::new(python);
    // A relative path with a separator is resolved against the runtime directory
    // (a bundled interpreter shipped under `<exe>.runtime`); a bare name is a PATH
    // lookup and an absolute path is used as-is.
    if !path.is_absolute() && (python.contains('/') || python.contains('\\\\')) {
        runtime_dir.join(path)
    } else {
        path.to_path_buf()
    }
}

fn __rextio_bridge() -> Result<&'static Mutex<RextioBridge>, RextioError> {
    static BRIDGE: OnceLock<Result<Mutex<RextioBridge>, String>> = OnceLock::new();
    let cell = BRIDGE.get_or_init(|| {
        let runtime_dir = __rextio_runtime_dir()?;
        {SPAWN_BLOCK}
            // The dispatcher imports the fallback modules from this directory.
            .current_dir(&runtime_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!(
                "Rextio: failed to launch the Python dispatcher ({}); is the interpreter available?", e
            ))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "Rextio: dispatcher stdin unavailable".to_string())?;
        let stdout = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| "Rextio: dispatcher stdout unavailable".to_string())?,
        );
        Ok(Mutex::new(RextioBridge { _child: child, stdin, stdout }))
    });
    cell.as_ref()
        .map_err(|e| RextioError::new("RuntimeError", e.as_str()))
}

fn __rextio_call_python(
    qualname: &str,
    args: Vec<serde_json::Value>,
) -> Result<serde_json::Value, RextioError> {
    let mut guard = __rextio_bridge()?
        .lock()
        .map_err(|_| RextioError::new("RuntimeError", "Rextio dispatcher mutex was poisoned"))?;
    let bridge = &mut *guard;

    let request = serde_json::json!({ "call": qualname, "args": args });
    let mut line = serde_json::to_string(&request)
        .map_err(|e| RextioError::new("RuntimeError", e.to_string()))?;
    line.push('\\n');
    bridge
        .stdin
        .write_all(line.as_bytes())
        .map_err(|e| RextioError::new("RuntimeError", e.to_string()))?;
    bridge
        .stdin
        .flush()
        .map_err(|e| RextioError::new("RuntimeError", e.to_string()))?;

    let mut response_line = String::new();
    let read = bridge
        .stdout
        .read_line(&mut response_line)
        .map_err(|e| RextioError::new("RuntimeError", e.to_string()))?;
    if read == 0 {
        return Err(RextioError::new("RuntimeError", "the Python dispatcher exited unexpectedly"));
    }
    let response: serde_json::Value = serde_json::from_str(response_line.trim())
        .map_err(|e| RextioError::new("RuntimeError", e.to_string()))?;
    if let Some(ok) = response.get("ok") {
        return Ok(ok.clone());
    }
    if let Some(error) = response.get("error") {
        let kind = error.get("type").and_then(|v| v.as_str()).unwrap_or("RuntimeError");
        let message = error.get("message").and_then(|v| v.as_str()).unwrap_or("");
        return Err(RextioError::new(kind, message));
    }
    Err(RextioError::new("RuntimeError", "malformed response from the Python dispatcher"))
}
// ---- end IPC client -------------------------------------------------------
'''.replace("{SPAWN_BLOCK}", spawn_block).replace("{RUNTIME_DIR_SUFFIX}", RUNTIME_DIR_SUFFIX).replace("{PYTHON_COMMAND}", baked)
