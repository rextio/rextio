# Rextio

[English](README.md) | [한국어](README.ko.md) | [简体中文](README.zh-hans.md) | [日本語](README.ja.md)

**在可證明安全的地方用 Rust 的速度，其餘一切仍是 Python。絕不悄悄出錯。**

Rextio 0.1.0 是面向 Python 專案的 alpha 階段本地建置工具。它找出可以安全
下沉到 Rust 的帶型別 Python 函式，用 PyO3 提前（ahead-of-time）編譯它們，
其餘部分全部繼續透過產生的 Python fallback 程式碼運行 — import 路徑與
行為保持不變。

```text
帶型別的 Python 專案
  -> 分析受支援的 native 候選
  -> 拒絕不安全或不受支援的函式
  -> 為被接受的函式產生 Rust + PyO3
  -> 為其餘部分產生 Python fallback wrapper
  -> 建置 import 相容的 artifact
```

契約是嚴格的: 函式要麼以與 CPython 等價的語義編譯為 native 程式碼，要麼
帶著診斷被拒絕、留在 Python fallback 上。Rextio 拿不準時不會猜測 —
它選擇 fallback。

Rextio 不是 Python 的替代品，也不是整個專案遷移到 Rust 的工具。Native
編譯是一種最佳化，Python fallback 行為始終是正確性的基準線。

## 提供什麼

Rextio 可以從同一個 Python 專案產出多種 artifact:

| 產出 | 用途 |
| --- | --- |
| `.rextio/generated/rust/` | 被接受的 native 函式的 Rust/PyO3 產生原始碼。 |
| `.rextio/generated/python/` | 產生的 Python wrapper 與 fallback 模組。 |
| `.rextio/build/python/` | import 相容的 hybrid 套件樹。 |
| `dist/*.whl` | 含 fallback 程式碼以及（建置成功時）native 擴充的 wheel。 |
| `dist/<name>.pyz` | 為設定的 Python entrypoint 產生的 zipapp 可執行檔（可選）。 |
| `dist/<name>.dist/` 或 `dist/<name>` | Nuitka standalone/onefile 可執行檔（可選）。 |
| `dist/<name>` | 獨立的 native Rust 二進位（`--executable-backend=rust`），無需 Python 執行時（可選）。 |
| `dist/<crate>-rust-crate/` | 供 Rust 專案 import 的 Rust 函式庫 crate（可選）。 |

產生的 Python wrapper 會先嘗試 native 程式碼；當 native 被停用、不可用、
被分析拒絕、或超過設定的 boundary threshold 時回落到 Python。

```text
REXTIO_NATIVE_MODE=fallback
```

設定 `REXTIO_DEBUG_NATIVE=1` 可以在建置出的 native 模組載入失敗時拋出
完整 traceback（而不是警告後回落）— 除錯 ABI 不匹配或 wrapper/codegen
命名不一致時很有用。

## 環境需求

| 元件 | 版本 | 說明 |
| --- | --- | --- |
| CPython | >= 3.11（在 3.11-3.14 上驗證） | 分析器使用建置直譯器的 `ast`；產生的擴充固定 PyO3 0.29（最高支援 CPython 3.14）。更新的直譯器可能可用，但未經驗證。wheel 帶有建置直譯器 minor 版本標籤。 |
| Rust toolchain | MSRV 1.83（在最新 stable 上驗證） | 產生的 crate 使用 edition 2021 + PyO3 0.29。請透過 [rustup](https://rustup.rs) 安裝。 |
| Nuitka（可選） | >= 2.0 | 僅用於 `--fallback=nuitka`/`--executable-backend=nuitka`/`--hybrid-runtime=nuitka`。前兩者由建置 preflight 預先拒絕；hybrid runtime 則在被委託的 fallback 呼叫確實需要 Nuitka dispatcher 時檢查。 |
| Numba（可選，experimental） | 隨直譯器: 3.11→>=0.57, 3.12→>=0.59, 3.13→>=0.61, 3.14→>=0.63 | Rextio 只識別 Numba 裝飾器；該套件是使用者專案的執行時依賴，而非 Rextio 的依賴。下限遵循 [Numba 版本支援表](https://numba.readthedocs.io/en/stable/user/installing.html#version-support-information)。 |

工具位置與版本 pin 可配置: 透過 `rextio.toml` 的 `[toolchain]`（或
`REXTIO_*` 環境變數 / CLI 旗標）選擇建置所用的 cargo、maturin、Nuitka
和 CPython，並可驗證其版本。參見
[REXTIO.md](./REXTIO.md#toolchain-selection-and-version-pins)。

## 快速範例

從普通的 Python 程式碼開始:

```python
# src/myapp/math_ops.py
def sum_squares(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += x * x
    return total

def format_result(value: int) -> str:
    return f"score={value}"  # 不在 direct Rust subset 內
```

建置:

```text
python -m pip install -e .
rextio check .
rextio build . --fallback=cpython
```

Rextio 可以把 `sum_squares` 編譯為 Rust，讓 `format_result` 留在 Python
fallback。import 路徑保持 Python 原樣:

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

只需要產生原始碼時用 `rextio generate`。它不會執行 Cargo、maturin、
Nuitka、wheel 建置或可執行檔打包。

需要產生原始碼加上編譯/打包產物時用 `rextio build`。

## 指令

| 指令 | 作用 |
| --- | --- |
| `rextio init` | 建立 `rextio.toml`、`REXTIO.md` 和 `.rextioignore`。 |
| `rextio check` | 分析 native 候選並輸出診斷。 |
| `rextio generate` | 只寫出產生的 Rust/Python 原始碼，不編譯。 |
| `rextio build` | 產生、編譯、打包並寫出建置報告。 |
| `rextio bench` | 比較一個函式的 Python fallback 與 Rust native 耗時。 |
| `rextio clean` | 刪除 `.rextio/build`、`.rextio/generated`、`.rextio/reports`。 |

常用建置變體:

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

預設使用自動 native 探索:

```toml
[policy]
native_marker = "auto"
```

在該模式下，Rextio 可能把型別可解析且符合受支援 direct Rust subset 的
模組級函式視為 native 候選。

也可以要求顯式標記:

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

為未來的多目標支援，標記可以固定目標:

```python
@rextio.native(target="rust")
def score(x: float) -> float:
    return x * 2.0
```

函式必須留在 Python fallback 時用 `@rextio.exempt`:

```python
@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1
```

exempt 函式絕不會進入產生的 Rust。如果一個 native 候選呼叫了 exempt 或
僅 fallback 的函式，該候選也會回落。

## 安全模型

Rextio 讓 native 編譯保持保守:

- direct Rust native 函式只能呼叫被接受的 native 函式、受支援的 builtin
  和受支援的標準函式庫函式。
- 呼叫僅 fallback 程式碼的 native 函式會被拒絕 — 除非呼叫者被顯式標記且
  callee 的簽名從頭到尾都是不可變純量（`int`/`float`/`bool`/`str`/`None`）:
  該呼叫將成為 in-process 純量 boundary call（`RXT075`）。callee 繼續在
  直譯器中執行，因此值與例外都 CPython-精確，monkeypatch 也被尊重；容器
  絕不跨越邊界，native 迴圈內的 boundary call 會讓呼叫者留在 fallback
  （`RXT076`）。
- Python fallback 程式碼可以呼叫 native 函式。
- 反覆呼叫 native 函式的 Python 迴圈會產生 boundary 警告。
- 產生的 wrapper 可以在邊界穿越反覆發生後把該函式切回 fallback —
  Python→native 的 wrapper 進入與 native 純量 boundary call 計入同一個
  按函式閾值。
- Python/Rust 的所有權差異被顯式處理。持有值的唯讀重用在需要時用 Rust
  clone 下沉，可變集合的別名修改則留在 Python fallback。

boundary fallback 由以下控制:

```text
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
REXTIO_NATIVE_MODE=auto|fallback|native
```

## direct Rust subset

Rextio 0.1.0 alpha 刻意支援一個小的 subset。這是能提供真實 Rust 加速的
路徑。

支援的型別:

- `int`、`float`、`bool`、`str`、`bytes`、`None`
- 元素型別受支援的 `list[T]`（含 `list[list[T]]`）
- 固定 `tuple[...]`
- 鍵為受支援純量鍵型別的固定 `dict[K, V]`
- 受限的 `set[int]`、`set[bool]`、`set[str]`（`set[float]` 留在 Python
  fallback: NaN-identity 去重沒有忠實的 Rust 下沉；native 程式碼也從不
  *迭代* set — 雜湊順序與 CPython 不同）
- `Optional[T]`、`T | None`

支援的語法:

- 區域指派與帶型別註記的區域變數
- 算術、布林運算、比較、`if`、`while`
- `for x in xs`
- 受支援的迴圈/推導式形式中的 `range(...)`、`enumerate(xs)`、`zip(xs, ys)`
- `break`、`continue`、`return`
- 受支援形式的 list/dict/set 推導式
- 受限的 `list.append`、dict 讀寫、索引
- 呼叫被接受的 native 輔助函式

builtin 與標準函式庫下沉（受限形式）:

- `len`、`abs`、`min`、`max`、`sum`、`all`、`any`、`sorted`、`reversed`
- 部分 `math` 函式與常數
- 部分 `str`、`bytes`、`list` 方法
- `print`、`logging.debug/info/warning/error`
- `datetime`、`time`、`hashlib.sha256`、`base64.b64encode`
  （`statistics.mean`/`fmean`、`json.dumps`/`json.loads`、
  `base64.b64decode` 沒有忠實的 direct-native 等價物: 顯式標記的函式走
  RXT080 runtime shim，自動探索的函式留在 Python fallback）

不支援或含糊的程式碼留在 fallback 上，或在受支援時透過 Python runtime
semantics shim 暴露。詳細邊界見
[0.1.0 alpha 不支援的特性](docs/unsupported-features.md)。

## Python runtime semantics shim

一些 Python 特性無法安全翻譯為帶型別的 Rust 敘述。對顯式標記的 native
程式碼，Rextio 可能產生一個 PyO3 shim，轉而呼叫產生的 Python fallback
實作。

該相容路徑可以保留 class/物件行為、實例方法、例外、context manager、
`async`/`await`、generator、動態屬性存取等特性。回報為 `RXT080`。

該路徑保留行為，不應被當作 Rust 加速路徑。

## 實驗性 scalar helper 內嵌（embedding）

Rextio 可以選擇性地把一組非常窄的未標記純量 helper 作為內部 native 函式
內嵌。預設關閉。雖然設定鍵名叫 `[jit]`，但這不是 JIT: 一切都提前編譯，
建置出的 artifact 內不存在也不執行任何 JIT 編譯器。

啟用後，合格的未標記 helper（純量參數與回傳值、單一算術 return 運算式）
會被編譯成產生 native artifact 中的普通內部函式 — 可被 native 程式碼
呼叫，不匯出給 Python。內嵌的 helper 走常規 checked 路徑下沉，因此整數
溢位拋 OverflowError、除零拋 ZeroDivisionError，與任何 native 函式完全
一致。在 Rust 可執行檔 backend 中，內嵌 helper 直接編譯進二進位，而不是
每次呼叫委託給 CPython dispatcher。

```toml
[jit]
enabled = true
```

等價的命令列與環境變數控制:

```text
rextio build . --jit
REXTIO_JIT=true rextio build .
```

## Numba 外部加速器（experimental）

Numba 支援在 0.1.0 alpha 中是 EXPERIMENTAL 的: 識別、回報和 Nuitka 共存
行為在第一個 non-alpha 版本之前可能改變。Rextio 把 Numba 裝飾器
（`numba.jit`、`numba.njit`、`numba.vectorize`、`numba.guvectorize`）識別
為 Python fallback 程式碼的外部加速器（experimental）— 與 Nuitka 打包
backend 相同的「外部受支援工具」模式。被裝飾的函式乾淨地留在 Python
fallback（排除出自動探索與 helper 內嵌），在報告中標註
`external_accelerator: numba`，`rextio check` 會列出這些函式。識別透過
模組的 import 解析（attribute、from-import、別名、呼叫形式；含
`numba.cuda.jit`）。`rextio check` 的報告標籤只涵蓋直線式 import，而
Nuitka 建置期掃描更寬（star import、可選依賴守衛、函式內的延遲 import），
因此即使函式沒有標籤，建置也能正確地把模組保持為 plain。

契約邊界很重要: `@rextio.native` 函式擁有 Rextio 驗證過的 CPython-精確
語義，而 `@numba.*` 函式按 **Numba 的**語義執行（例如 nopython 模式整數
運算溢位時回繞而不是拋例外）— 這個取捨是使用者的顯式 opt-in，在 Rextio
native 契約之外，與 `@rextio.exempt` 一樣。`@rextio.native` 與 numba
裝飾器的組合會被明確拒絕。

相容性: wheel 與 zipapp 部署在把 numba 安裝為專案依賴後可用；Rust 可執行
檔的 source 模式 hybrid runtime 可用（dispatcher 執行真實 CPython）。
`--fallback=nuitka` backend 自動共存: 使用已識別外部加速器的模組保持為
plain Python（`.py` 繼續被 import），樹的其餘部分用 Nuitka 編譯，建置
報告列出它們。產生的 wheel 只把 Nuitka 編譯模組作為擴充裝載 — 被遮蔽的
`.py` 原始碼被排除（既是死重又會暴露原始碼）— 並帶平台標籤；加速模組
保留其 `.py`。Nuitka *可執行檔*（`--executable-backend=nuitka`）與
`--hybrid-runtime=nuitka` dispatcher 無法服務加速函式（編譯後的函式不
暴露 bytecode，加速器也不被捆綁）— 這些建置會帶指引提前失敗，而不是死
在第一次呼叫。帶型別的純量程式碼優先用 `@rextio.native`，NumPy/陣列核心
用 Numba，並注意非常小的函式在任何加速器下都會輸給呼叫邊界成本。

內嵌不會給產生的 Cargo 專案增加 crate 依賴。內嵌關閉時，合格的 helper
呼叫仍透過執行時純量 boundary call 運作 — 內嵌是移除每次呼叫直譯器往返
的快速路徑。

## Rust-importable crate

當 Rust 應用需要使用 direct Rust 函式時，建置一個額外的 Cargo 函式庫
crate:

```text
rextio build . --rust-importable --rust-crate-name=my_native
```

在 Rust 中使用產生的 crate:

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

只有直接下沉為帶型別 Rust 的函式透過該 crate 匯出。僅 fallback 的函式、
runtime semantics shim、以及使用純量 boundary call 的函式（都需要直譯器）
仍是面向 Python 的路徑。

## 可執行 artifact

Zipapp:

```text
rextio build . --entrypoint=myapp.cli:main --executable-name=myapp
```

寫出 `dist/myapp.pyz`。目標機器仍需要相容的 Python 直譯器。native 擴充
不會從 zipapp 內部 import，因此 `_rextio_native` 不可用時 wrapper 保持
fallback 行為。

Nuitka:

```text
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=standalone
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
```

Nuitka 可執行檔打包是 experimental 的，需要安裝 Nuitka。

Native Rust 二進位:

```text
rextio build . --entrypoint=myapp.cli:main --executable-backend=rust
```

編譯一個 `main` 在 Rust 中執行的 native 二進位（`dist/<name>`）。
entrypoint 必須是被接受的 direct-native `def main(argv: list[str]) -> int`:
`argv` 對應 `sys.argv`（index 0 是程式路徑），回傳的 `int` 是行程結束碼，
拋出的錯誤以 CPython 風格（`OverflowError: ...`）列印到 stderr 並以非零
結束。需要 Cargo。

當 entrypoint 呼叫留在 Python fallback 的專案函式（Rust subset 之外的
程式碼）時，Rextio 把該呼叫委託給外部 CPython 子行程: 建置會附帶
`dist/<name>.runtime/` 目錄（dispatcher + 專案原始碼），二進位透過 stdio
驅動它，難以編譯的邏輯可以留作 Python。這樣的 hybrid 二進位在執行時需要
Python 直譯器；呼叫圖完全 direct-native 的二進位則是無 Python 依賴的
獨立程式。被委託呼叫的參數與結果都必須是不可變純量
（`int`/`float`/`bool`/`str`/`None`）；`list`/`dict`/`set` 在任一方向都
不被委託（它們按值過線，切斷 CPython 保持的別名關係，被修改的參數或被
修改的別名回傳值會悄悄偏離），非有限 float（`NaN`/`Infinity`）會被拒絕
而不是悄悄丟棄。被委託函式自身的 stdout/stderr 出現在二進位的 stderr 上
（二進位的 stdout 承載線協定）。RXT080 runtime shim 上的函式不被委託:
依賴它的 entry 會被拒絕而非建置。

`--executable-python` 固定二進位啟動的直譯器（`PATH` 上的名字、絕對
路徑、或相對 `<binary>.runtime` 的路徑以便捆綁）。`REXTIO_RUNTIME_PYTHON`
在目標機器上於執行時覆蓋它。`--hybrid-runtime=nuitka` 則把被委託的
Python 編譯成隨 runtime 目錄一起交付的自包含 dispatcher 可執行檔，使
hybrid 二進位無需單獨安裝 Python（建置時需要 Nuitka）。

## 設定

建置/分析設定按此順序解析:

```text
CLI 參數 > 環境變數 > rextio.toml > 內建預設值
```

常用設定:

| `rextio.toml` 鍵 | CLI 參數 | 環境變數 |
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
| `[executable] python` | `--executable-python` | `REXTIO_EXECUTABLE_PYTHON` |
| `[executable] hybrid_runtime` | `--hybrid-runtime` | `REXTIO_HYBRID_RUNTIME` |
| `[toolchain] cargo` | `--cargo` | `REXTIO_CARGO` |
| `[toolchain] maturin` | `--maturin` | `REXTIO_MATURIN` |
| `[toolchain] nuitka` | `--nuitka` | `REXTIO_NUITKA` |
| `[toolchain] python` | `--python` | `REXTIO_PYTHON` |
| `[toolchain] rust_toolchain` | `--rust-toolchain` | `REXTIO_RUST_TOOLCHAIN` |
| `[toolchain] *_version` pin | `--cargo-version` 等 | `REXTIO_CARGO_VERSION` 等 |
| `[policy] native_marker` | `--native-marker` | `REXTIO_NATIVE_MARKER` |
| `[policy] boundary_warnings` | `--boundary-warnings` / `--no-boundary-warnings` | `REXTIO_BOUNDARY_WARNINGS` |
| `[policy] native_top_level` | `--native-top-level` / `--no-native-top-level` | `REXTIO_NATIVE_TOP_LEVEL` |

0.1.0 alpha 中唯一實作的 native 目標是 Rust。`mojo` 與 `julia` 作為未來
backend 的規劃值被接受，但在這些 backend 存在之前程式碼產生會明確失敗。

Rextio 外掛是用 `pip` 或 `uv` 等工具安裝的普通 Python 套件。外掛套件透過
`rextio.plugins` entry point 群組暴露中繼資料，包括它涵蓋的 Python 套件
名。專案用 `[plugins] enabled` 或 `--enable-plugin` 啟用特定外掛 id。

沒有啟用 Rextio 外掛的外部 Python 套件預設保守處理: Rextio 不會悄悄把
第三方套件原始碼翻譯成 Rust。除非新增外掛，或對已知純 Python 套件顯式
opt-in 實驗性依賴分析，對這些套件的呼叫會讓周圍的 native 候選留在
fallback:

```toml
[imports]
default_external_policy = "fallback"

[imports.packages]
"some_pure_python_pkg" = { policy = "try-native", max_depth = 1 }
"legacy_dynamic_pkg" = "fallback"
"known_pkg" = { policy = "plugin", plugin = "known-rust" }
```

支援的套件策略是 `fallback`、`analyze`、`try-native`、`plugin`。具體的
第三方外掛變換和一般依賴下沉不隨 0.1.0 alpha 捆綁；`try-native` 是顯式的
規劃策略，沒有安全的 direct 下沉時仍會 fallback。

## 範例

```text
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math

rextio check examples/boundary_demo
rextio build examples/fallback_demo --entrypoint=fallback_demo.run_demo:main
```

範例專案:

- `examples/pure_math`: 帶型別數學熱路徑的 direct Rust 下沉。
- `examples/fallback_demo`: native 關閉或缺失時的 fallback 行為。
- `examples/boundary_demo`: native→fallback boundary 的拒絕與警告。
- `examples/app_shell`: 應用外殼保持 Python，只有評分熱路徑可以 native。

## 開發與驗證

執行測試套件:

```text
python -m pytest
```

真實的 Cargo、Nuitka 和可執行檔測試在對應 toolchain 不可用時會跳過。

完整的開發環境與品質門檻見 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 專案資訊

- [特性穩定性](docs/stability.md) — 0.1.0 alpha 中哪些是 stable、哪些是 experimental。
- [版本策略](docs/versioning.md) — 帶 pre-1.0 注意事項的 SemVer。
- [不支援的特性](docs/unsupported-features.md) — 0.1.0 alpha subset 的邊界。
- [安全模型](SECURITY.md) — 信任邊界與漏洞回報方式。
- [貢獻指南](CONTRIBUTING.md) — 環境、門檻與慣例。
- [變更日誌](CHANGELOG.md)。
