# Rextio

[English](README.md) | [한국어](README.ko.md) | [简体中文](README.zh-hans.md) | [日本語](README.ja.md)

Rextio 0.1.0 是 alpha 階段的本機 Python 建置工具。

它會找出可以安全 lowering 到 Rust 的 Python 函式，提前編譯這些函式，並讓其餘程式碼
繼續透過 Python fallback 執行。

```text
typed Python project
  -> 分析 native 候選
  -> 拒絕不支援或不安全的函式
  -> 為 accepted 函式產生 Rust + PyO3
  -> 為其餘程式碼產生 Python fallback wrapper
  -> 建置可 import 的 hybrid artifact
```

Rextio 不是 Python 替代品，也不是 whole-project Rust migration 工具。Native 編譯只是
最佳化；Python fallback 行為是正確性基準。

## 提供什麼

| 產物 | 用途 |
| --- | --- |
| `.rextio/generated/rust/` | accepted native 函式的 Rust/PyO3 原始碼 |
| `.rextio/generated/python/` | Python wrapper 與 fallback module |
| `.rextio/build/python/` | 可 import 的 hybrid package tree |
| `dist/*.whl` | 包含 fallback 程式碼和 native extension 的 wheel |
| `dist/<name>.pyz` | Python entrypoint 的 zipapp 可執行 artifact |
| `dist/<name>.dist/` 或 `dist/<name>` | Nuitka standalone/onefile 可執行 artifact |
| `dist/<crate>-rust-crate/` | Rust 專案可作為 path dependency 使用的 crate |

產生的 Python wrapper 會優先嘗試 native；當 native 被停用、無法載入、分析拒絕，或超過
boundary threshold 時會使用 Python fallback。

```text
REXTIO_DISABLE_NATIVE=1
```

## 快速範例

```python
# src/myapp/math_ops.py
def sum_squares(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += x * x
    return total

def format_result(value: int) -> str:
    return f"score={value}"  # 不屬於 direct Rust subset
```

```text
python -m pip install -e .
rextio check .
rextio build . --fallback=cpython
```

Rextio 可以把 `sum_squares` 編譯為 Rust，並讓 `format_result` 保持 Python fallback。
Python import 路徑保持不變。

```python
from myapp.math_ops import sum_squares, format_result

assert sum_squares([1, 2, 3]) == 14
assert format_result(14) == "score=14"
```

## 常用流程

```text
rextio init --project-root path/to/project
rextio check path/to/project
rextio generate path/to/project --fallback=cpython
rextio build path/to/project --fallback=cpython
rextio bench myapp.math_ops.sum_squares --project-root path/to/project
rextio clean path/to/project
```

`rextio generate` 只寫出產生的原始碼，不執行 Cargo、maturin、Nuitka、wheel 建置或
executable 封裝。`rextio build` 會執行產生、編譯和封裝。

## 指令

| 指令 | 作用 |
| --- | --- |
| `rextio init` | 建立 `rextio.toml`、`REXTIO.md`、`.rextioignore` |
| `rextio check` | 分析 native 候選並輸出 diagnostics |
| `rextio generate` | 不編譯，只產生 Rust/Python 原始碼 |
| `rextio build` | 產生、編譯、封裝，並寫出 build report |
| `rextio bench` | 對一個函式比較 Python fallback 與 Rust native 時間 |
| `rextio clean` | 刪除 `.rextio/build`、`.rextio/generated`、`.rextio/reports` |

常用 build 形式：

```text
rextio build . --fallback=cpython
rextio build . --fallback=nuitka
rextio build . --fallback-threshold=1000
rextio build . --jit
rextio build . --entrypoint=myapp.cli:main
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
rextio build . --rust-importable --rust-crate-name=my_native
```

## Native 選擇

預設使用自動 native discovery：

```toml
[policy]
native_marker = "auto"
```

當函式型別可解析並符合 direct Rust subset 時，Rextio 可以自動把 module-level 函式作為
native 候選。也可以切換為只接受明確 marker：

```toml
[policy]
native_marker = "decorator"
```

```python
import rextio

@rextio.native
def score(x: float) -> float:
    return x * 2.0
```

未來多 target 場景可以指定 target：

```python
@rextio.native(target="rust")
def score(x: float) -> float:
    return x * 2.0
```

必須留在 Python fallback 的函式使用 `@rextio.exempt`：

```python
@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1
```

exempt 函式永遠不會產生到 Rust 中。native 候選如果呼叫 exempt 或 fallback-only 函式，也會
轉為 fallback。

## 安全模型

- direct Rust native 函式只能呼叫 accepted native 函式、支援的 builtin 和支援的標準函式庫函式。
- 呼叫 fallback-only 程式碼的 native 函式會被拒絕。
- Python fallback 程式碼可以呼叫 native 函式。
- Python loop 重複呼叫 native 函式時會產生 boundary warning。
- wrapper crossing 超過閾值後，產生的 wrapper 可以把該函式切回 fallback。
- Python/Rust ownership 差異會明確處理：唯讀重用會在需要時 clone；mutable collection alias
  mutation 保留在 Python fallback。

相關執行階段設定：

```text
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
REXTIO_NATIVE_MODE=auto|fallback|native
```

## direct Rust subset

0.1.0 alpha 只支援一個小 subset。這是能獲得實際 Rust speedup 的路徑。

支援型別包括 `int`、`float`、`bool`、`str`、`bytes`、`None`、`list[T]`、
`list[list[T]]`、fixed `tuple[...]`、fixed `dict[K, V]`、有限 `set[...]`、
`Optional[T]` 和 `T | None`。

支援語法包括 local assignment、typed local annotation、算術、比較、`if`、`while`、
`for x in xs`、支援形式的 `range`/`enumerate`/`zip`、`break`、`continue`、`return`、
有限 list/dict/set comprehension、有限 `list.append`、dict read/write、indexing，以及
accepted native helper 呼叫。

有限 lowering 的 builtin/標準函式庫包括 `len`、`abs`、`min`、`max`、`sum`、`all`、
`any`、`sorted`、`reversed`、部分 `math`、部分 `str`/`bytes`/`list` method、`print`、
`logging`、`datetime`、`time`、`hashlib.sha256`、`base64.b64encode`。
（`statistics.mean`/`fmean`、`json.dumps`/`json.loads`、`base64.b64decode`
沒有與 CPython 精確一致的 native 實作，保留在 Python fallback 或 runtime shim。）

不支援或語意不明確的程式碼會留在 fallback，或在支援時透過 Python runtime semantics shim
保留行為。詳細邊界見 [0.1.0 alpha 不支援的功能](docs/unsupported-features.md)。

## Python runtime semantics shim

有些 Python 功能無法安全變成 typed Rust statement。對明確標記的 native 程式碼，Rextio 可以
產生一個呼叫 Python fallback 實作的 PyO3 shim。

這個 compatibility 路徑可用於保留 class/object、instance method、exception、context
manager、`async`/`await`、generator、dynamic attribute access 等行為，並報告 `RXT080`。
它是行為保留路徑，不是 Rust speedup 路徑。

## Rust-importable crate

如果 direct Rust 函式也要給 Rust 應用使用，可以額外產生 Cargo library crate：

```text
rextio build . --rust-importable --rust-crate-name=my_native
```

```toml
[dependencies]
my_native = { path = "../dist/my_native-rust-crate" }
```

```rust
fn main() -> Result<(), my_native::RextioError> {
    let value = my_native::myapp__math_ops__sum_squares(vec![1, 2, 3])?;
    assert_eq!(value, 14);
    Ok(())
}
```

該 crate 只 export 直接 lowering 到 typed Rust 的函式。fallback-only 函式和 runtime
semantics shim 仍是 Python-facing 路徑。

## 實驗性 scalar helper 內嵌（embedding）

Rextio 可以把非常窄的 scalar helper（型別確定、單一算術 return 運算式的 unmarked
函式）以 AOT 方式內嵌進 native 函式。預設關閉。

```toml
[jit]
enabled = true
```

同樣的設定也可以透過 `rextio build . --jit` 或 `REXTIO_JIT=true` 指定。
（`[jit]` 這個鍵名只是為相容而保留，此功能並非 JIT —— 全部編譯在建置時（AOT）
完成，建置產物內部不存在任何執行時 JIT 編譯器。）內嵌的
helper 走正常的 checked 路徑編譯：overflow 正確地 raise OverflowError，除以零
raise ZeroDivisionError，且不會作為 PyO3 函式匯出。不存在執行時編譯。（過去的
Cranelift 執行時 JIT 及其 `backend`/`hot_threshold` 設定經基準測試證明始終慢於
AOT 路徑，已被移除；被移除的環境變數會立即報錯並給出遷移提示。）

## Numba 外部加速器

帶有 `numba.jit`/`njit`/`vectorize`/`guvectorize`/`cuda.jit` 裝飾器的函式會刻意
留在 Python fallback（無診斷噪音），並在報告中標記為
`external_accelerator: numba`。這類函式依 Numba 的語義執行（例如 nopython 模式
int overflow 會 wrap），在 Rextio 的 CPython 精確性契約之外 — 與 `@rextio.exempt`
相同的 opt-in 哲學。`--fallback=nuitka` 自動共存：使用加速器的模組被排除在編譯
之外、保持為 plain `.py`；wheel 會排除已被 Nuitka 編譯模組的 `.py` 原始碼並帶上
平台標籤。Nuitka *執行檔* 與 `--hybrid-runtime=nuitka` 在存在加速模組時會帶指引
提前失敗（請改用 `--hybrid-runtime=source`）。建置時掃描的涵蓋面比報告標籤
更廣：`rextio check` 標籤只處理直線式 import，因此沒有標籤的函式所在模組
在建置中仍可能被正確地保持為 plain。

## 可執行 artifact

```text
rextio build . --entrypoint=myapp.cli:main --executable-name=myapp
```

這會寫出 `dist/myapp.pyz`。目標機器仍需要相容的 Python interpreter。Native extension 不會
直接從 zipapp 內 import，因此 `_rextio_native` 不可用時 wrapper 會保持 fallback 行為。

Nuitka executable 封裝是實驗性的，並要求安裝 Nuitka：

```text
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=standalone
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
```

## 設定

```text
CLI parameter > environment variable > rextio.toml > built-in default
```

主要設定：

| `rextio.toml` key | CLI parameter | Environment variable |
| --- | --- | --- |
| `[build] native_backend` | `--native-backend` / `--target-language` | `REXTIO_TARGET_LANGUAGE` / `REXTIO_NATIVE_BACKEND` |
| `[build] fallback_backend` | `--fallback` | `REXTIO_FALLBACK_BACKEND` |
| `[build] fallback_threshold` | `--fallback-threshold` | `REXTIO_BOUNDARY_FALLBACK_THRESHOLD` |
| `[rust] binding` | `--rust-binding` | `REXTIO_RUST_BINDING` |
| `[rust] build_tool` | `--rust-build-tool` | `REXTIO_RUST_BUILD_TOOL` |
| `[rust] importable` | `--rust-importable` / `--no-rust-importable` | `REXTIO_RUST_IMPORTABLE` |
| `[rust] crate_name` | `--rust-crate-name` | `REXTIO_RUST_CRATE_NAME` |
| `[fallback] nuitka` | `--nuitka-fallback` | `REXTIO_NUITKA_FALLBACK` |
| `[target] version` | `--target-version` | `REXTIO_TARGET_VERSION` |
| `[target.build_options]` | `--target-build-option KEY=VALUE` | `REXTIO_TARGET_BUILD_OPTIONS` |
| `[plugins] enabled` | `--enable-plugin` | `REXTIO_PLUGINS_ENABLED` |
| `[imports] default_external_policy` | `--default-external-policy` | `REXTIO_IMPORTS_DEFAULT_EXTERNAL_POLICY` |
| `[imports.packages]` | `--package-import-policy PACKAGE=POLICY` | `REXTIO_IMPORTS_PACKAGES` |
| `[jit] enabled` | `--jit` / `--no-jit` | `REXTIO_JIT` |
| `[executable] entrypoint` | `--entrypoint` | `REXTIO_EXECUTABLE_ENTRYPOINT` |
| `[executable] name` | `--executable-name` | `REXTIO_EXECUTABLE_NAME` |
| `[executable] backend` | `--executable-backend` | `REXTIO_EXECUTABLE_BACKEND` |
| `[executable] nuitka_mode` | `--nuitka-mode` | `REXTIO_NUITKA_MODE` |
| `[policy] native_marker` | `--native-marker` | `REXTIO_NATIVE_MARKER` |
| `[policy] boundary_warnings` | `--boundary-warnings` / `--no-boundary-warnings` | `REXTIO_BOUNDARY_WARNINGS` |
| `[policy] native_top_level` | `--native-top-level` / `--no-native-top-level` | `REXTIO_NATIVE_TOP_LEVEL` |

目前實作的 native target 只有 Rust。`mojo` 和 `julia` 只是未來 backend 的 planning 值。
Rextio plugin 是透過 `pip` 或 `uv` 安裝的一般 Python package，並透過 `rextio.plugins`
entry point group 暴露 metadata。專案透過 `[plugins] enabled` 或 `--enable-plugin`
宣告要使用的 plugin id。沒有 plugin 的外部 Python package 預設 fallback。可以透過
`[imports.packages]` 或 `--package-import-policy` 對明確允許的 pure-Python dependency
設定 `try-native`，但如果沒有安全的 direct lowering，Rextio 仍會使用 fallback。
0.1.0 alpha 不內建具體第三方 plugin 轉換。

## 範例

```text
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math

rextio check examples/boundary_demo
rextio build examples/fallback_demo --entrypoint=fallback_demo.run_demo:main
```

- `examples/pure_math`: typed math hot path 的 direct Rust lowering
- `examples/fallback_demo`: native 停用或缺失時的 fallback 行為
- `examples/boundary_demo`: native-to-fallback boundary rejection 和 warning
- `examples/app_shell`: application shell 保持 Python，scoring hot path 可 native
