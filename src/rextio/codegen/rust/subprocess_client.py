"""Rust source for the executable's subprocess-hybrid IPC client.

Rendered into the generated Rust binary crate when the executable delegates
non-native calls to an external CPython process (Phase 2 of the Rust-``main``
backend). The client lazily launches the generated dispatcher
(``rextio.codegen.subprocess_dispatcher``), talks to it over stdio using the
newline-delimited JSON wire protocol, and maps a Python exception back to a
``RextioError`` carrying the CPython exception type name.
"""

from __future__ import annotations

from rextio.codegen.subprocess_dispatcher import DISPATCHER_STEM, PROTOCOL_VERSION

# The runtime directory (dispatcher + fallback Python tree) is placed next to the
# executable as ``<exe>.runtime`` by the build; the client resolves it from the
# executable's own path so the binary is relocatable.
RUNTIME_DIR_SUFFIX = ".runtime"


def _rust_string_literal(value: str) -> str:
    """Escape a plain string (an interpreter path) for a Rust string literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


# The Nuitka-compiled dispatcher is a self-contained executable shipped in the
# runtime directory under this name; the binary launches it directly (no Python).
NUITKA_DISPATCHER_NAME = DISPATCHER_STEM


def render_subprocess_client(python_command: str = "python3", *, nuitka_dispatcher: bool = False) -> str:
    """Return the Rust source for the ``__rextio_call_python`` IPC client.

    In the default (source) mode the binary launches ``python3`` on
    ``<exe>.runtime/_rextio_dispatcher.py``; ``python_command`` sets that interpreter (a
    bare name on ``PATH``, an absolute path, or a relative path resolved against
    the runtime directory) and ``REXTIO_RUNTIME_PYTHON`` overrides it at run time. When
    ``nuitka_dispatcher`` is set the runtime ships a Nuitka-compiled, self-contained
    dispatcher executable instead, which the binary launches directly (no Python).
    """
    baked = _rust_string_literal(python_command)
    if nuitka_dispatcher:
        # Nuitka appends the OS executable extension, so add `EXE_SUFFIX` (``.exe`` on
        # Windows, empty elsewhere) to find the compiled dispatcher.
        spawn_block = (
            f'let mut child = Command::new(runtime_dir.join('
            f'format!("{NUITKA_DISPATCHER_NAME}{{}}", std::env::consts::EXE_SUFFIX)))'
        )
    else:
        spawn_block = (
            'let python = std::env::var("REXTIO_RUNTIME_PYTHON")'
            '.unwrap_or_else(|_| "{PYTHON_COMMAND}".to_string());\n'
            '        let python_path = __rextio_resolve_python(&runtime_dir, &python);\n'
            '        let mut child = Command::new(python_path).arg(runtime_dir.join("'
            + f'{DISPATCHER_STEM}.py"))'
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

enum __RextioExchange {
    // The dispatcher died mid-exchange; the caller drops the bridge so the
    // NEXT delegated call re-spawns a fresh dispatcher (council round 8).
    Dead,
    Failed(RextioError),
}

fn __rextio_spawn_bridge() -> Result<RextioBridge, String> {
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
    let mut stdout = BufReader::new(
        child
            .stdout
            .take()
            .ok_or_else(|| "Rextio: dispatcher stdout unavailable".to_string())?,
    );
    // Protocol handshake: the dispatcher's first frame declares its version so a
    // binary/runtime version mismatch fails clearly instead of as cryptic JSON
    // errors on the first real call (council round 8).
    let mut handshake = String::new();
    let read = stdout
        .read_line(&mut handshake)
        .map_err(|e| format!("Rextio: dispatcher handshake read failed: {}", e))?;
    if read == 0 {
        return Err("Rextio: the Python dispatcher exited before the protocol handshake".to_string());
    }
    let frame: serde_json::Value = serde_json::from_str(handshake.trim())
        .map_err(|e| format!("Rextio: malformed dispatcher handshake frame: {}", e))?;
    let version = frame.get("protocol").and_then(|v| v.as_u64());
    if version != Some({PROTOCOL_VERSION}) {
        return Err(format!(
            "Rextio: dispatcher protocol mismatch (binary expects {}, dispatcher reported {:?}); rebuild the binary and its runtime together",
            {PROTOCOL_VERSION}, version
        ));
    }
    Ok(RextioBridge { _child: child, stdin, stdout })
}

fn __rextio_bridge() -> &'static Mutex<Option<RextioBridge>> {
    static BRIDGE: OnceLock<Mutex<Option<RextioBridge>>> = OnceLock::new();
    BRIDGE.get_or_init(|| Mutex::new(None))
}

fn __rextio_exchange(
    bridge: &mut RextioBridge,
    qualname: &str,
    args: &[serde_json::Value],
) -> Result<serde_json::Value, __RextioExchange> {
    let request = serde_json::json!({ "call": qualname, "args": args });
    let mut line = serde_json::to_string(&request)
        .map_err(|e| __RextioExchange::Failed(RextioError::new("RuntimeError", e.to_string())))?;
    line.push('\\n');
    if bridge.stdin.write_all(line.as_bytes()).is_err() || bridge.stdin.flush().is_err() {
        return Err(__RextioExchange::Dead);
    }
    let mut response_line = String::new();
    let read = bridge
        .stdout
        .read_line(&mut response_line)
        .map_err(|_| __RextioExchange::Dead)?;
    if read == 0 || !response_line.ends_with('\\n') {
        // A frame without a trailing newline means the dispatcher died
        // mid-write; treat it as Dead so the bridge is dropped and the next
        // call re-spawns, instead of surfacing a confusing JSON parse error
        // (council round 9).
        return Err(__RextioExchange::Dead);
    }
    let response: serde_json::Value = serde_json::from_str(response_line.trim())
        .map_err(|e| __RextioExchange::Failed(RextioError::new("RuntimeError", e.to_string())))?;
    if let Some(ok) = response.get("ok") {
        return Ok(ok.clone());
    }
    if let Some(error) = response.get("error") {
        let kind = error.get("type").and_then(|v| v.as_str()).unwrap_or("RuntimeError");
        let message = error.get("message").and_then(|v| v.as_str()).unwrap_or("");
        return Err(__RextioExchange::Failed(RextioError::new(kind, message)));
    }
    Err(__RextioExchange::Failed(RextioError::new(
        "RuntimeError",
        "malformed response from the Python dispatcher",
    )))
}

fn __rextio_call_python(
    qualname: &str,
    args: Vec<serde_json::Value>,
) -> Result<serde_json::Value, RextioError> {
    let mut guard = __rextio_bridge()
        .lock()
        .map_err(|_| RextioError::new("RuntimeError", "Rextio dispatcher mutex was poisoned"))?;
    if guard.is_none() {
        *guard = Some(
            __rextio_spawn_bridge().map_err(|e| RextioError::new("RuntimeError", e.as_str()))?,
        );
    }
    let outcome = {
        let bridge = guard.as_mut().expect("bridge just spawned");
        __rextio_exchange(bridge, qualname, &args)
    };
    match outcome {
        Ok(value) => Ok(value),
        Err(__RextioExchange::Dead) => {
            // Drop the dead bridge; the next delegated call spawns a fresh one.
            *guard = None;
            Err(RextioError::new("RuntimeError", "the Python dispatcher exited unexpectedly"))
        }
        Err(__RextioExchange::Failed(error)) => Err(error),
    }
}
// ---- end IPC client -------------------------------------------------------
'''.replace("{SPAWN_BLOCK}", spawn_block).replace("{RUNTIME_DIR_SUFFIX}", RUNTIME_DIR_SUFFIX).replace("{PYTHON_COMMAND}", baked).replace("{PROTOCOL_VERSION}", str(PROTOCOL_VERSION))
