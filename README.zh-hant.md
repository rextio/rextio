# Rextio

<p align="center"><strong>將符合條件的帶型別 Python 函式預先編譯為 Rust/PyO3。<br>其餘程式碼繼續使用安全的 Python fallback。</strong></p>

<p align="center">
  <a href="https://github.com/rextio/rextio/blob/main/README.md">English</a> · <a href="https://github.com/rextio/rextio/blob/main/README.ko.md">한국어</a> ·
  <a href="https://github.com/rextio/rextio/blob/main/README.zh-hans.md">简体中文</a> · <a href="https://github.com/rextio/rextio/blob/main/README.zh-hant.md">繁體中文</a> ·
  <a href="https://github.com/rextio/rextio/blob/main/README.ja.md">日本語</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/rextio/"><img alt="PyPI 版本" src="https://img.shields.io/pypi/v/rextio"></a>
  <a href="https://pypi.org/project/rextio/"><img alt="支援的 Python 版本" src="https://img.shields.io/pypi/pyversions/rextio"></a>
  <a href="https://github.com/rextio/rextio/blob/main/LICENSE"><img alt="MIT 授權" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

Rextio 是面向 Python 開發者的 **Alpha 本機建置工具**：不必重寫應用程式，即可讓選定的帶型別熱點以原生 Rust 執行。保守的分析器只接受能依文件語意安全 lowering 的程式碼。無法支援或存在歧義的程式碼會留在產生的 Python fallback wrapper；原生執行被停用，或在預設 `auto` 模式下原生程式碼無法使用時，相同匯入路徑仍透過這些 wrapper 運作。

```bash
python -m pip install rextio
rextio check .
```

這是最短且有用的第一步：建置前先確認哪些函式獲准進入原生路徑。

Core **0.1.8** 已於 2026-07-27 發布，包含 plugin API **1.7** 與 tooling contract **3.0.0**。版本歷史請見[變更記錄](CHANGELOG.md)。

> **Tooling 遷移：**contract 3.0 將 milestone 衍生的 artifact identity 替換為語意化的 `artifact-*` 名稱。精確的 0.1.7 identity 僅保留為 legacy 讀取/驗證輸入；僅支援 2.x 的 consumer 在 major 3 上必須降級。

## 證據：已量測的 CPU 工作負載

在 **Mac16,11 / Apple M4 Pro**、**2026-07-26**、CPython **3.11.9** 上三次執行的中位數：

| 工作負載 | source/native 中位加速比 |
| --- | ---: |
| Core hybrid | 57.729× |
| NumPy mixed fusion | 2.523× |
| NetworkX Dijkstra | 3.679× |
| pandas `Series.map` | 66.143× |
| PyTorch CPU deep MLP | 1.017× |
| TensorFlow CPU eager chain | 1.040× |

這些是**特定工作負載的觀測結果**，不是整個函式庫的效能承諾。接近 1× 代表大致持平，保留的部分診斷案例慢於 Python。未量測 CUDA。可稽核的 [rextio-benchmark](https://github.com/rextio/rextio-benchmark) 儲存庫包含精確 revision、source/fallback/native lane、原始證據、穩定性政策、診斷，以及較慢/持平結果。

## 運作方式

```text
typed Python
  → 解析型別並檢查支援子集
  → 拒絕不安全的 native/fallback 呼叫圖
  → 將獲准函式 lowering 為 Rust + PyO3
  → 產生相容原匯入路徑的 Python wrapper
  → 在保留 fallback 的前提下建置原生產物
```

正確性的基準始終是 Python。Rextio 不是 Python 替代品、通用 Python-to-Rust 轉換器、JIT，也不是整個專案的遷移工具。

## 第一次建置

預設自動模式下 decorator 是選用的，直接從一般帶型別 Python 開始：

```python
# src/myapp/math_ops.py
def sum_squares(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += x * x
    return total

def format_result(value: int) -> str:
    return f"score={value}"  # 保留在 Python fallback
```

```bash
rextio check .
rextio build . --fallback=cpython
```

Rextio 可以 lowering `sum_squares`，並讓 `format_result` 繼續 fallback。呼叫端維持一般 Python 匯入：

```python
from myapp.math_ops import format_result, sum_squares

assert sum_squares([1, 2, 3]) == 14
assert format_result(14) == "score=14"
```

可隨時強制已建置套件使用 fallback：

```bash
REXTIO_NATIVE_MODE=fallback python -m myapp
```

常用命令包括 `rextio init`、`rextio capabilities`、`rextio check`、`rextio generate`、`rextio build`、`rextio bench`、`rextio clean`。

## 需求

| 元件 | 支援邊界 |
| --- | --- |
| CPython | `>=3.11`；已驗證 3.11–3.14。產生的 extension 固定使用支援至 CPython 3.14 的 PyO3 0.29。更新的 interpreter 尚未驗證，wheel 依建置 interpreter 的次版本標記。 |
| Rust | MSRV 1.83；測試近期 stable。產生的 crate 使用 Rust 2021。請透過 [rustup](https://rustup.rs) 安裝。 |
| Nuitka | 選用，`>=2.0`；只有所選 Nuitka fallback、執行檔或 dispatcher 路徑需要。這些路徑皆為 Experimental。 |
| Numba | 選用且為 Experimental；各 interpreter 最低版本為 0.57（3.11）、0.59（3.12）、0.61（3.13）、0.63（3.14）。它仍是你的專案相依套件。 |

工具位置與版本可透過 `[toolchain]`、環境變數或 CLI 選項固定；請見 [REXTIO.md](./REXTIO.md#toolchain-selection-and-version-pins)。

## 選擇與 fallback 安全性

預設啟用自動探索：

```toml
[policy]
native_marker = "auto"
```

使用 `native_marker = "decorator"` 強制要求 `@rextio.native`，或用 `@rextio.exempt` 將函式固定在 Python。現在唯一實作的原生目標是 Rust。

```python
import rextio

@rextio.native
def score(x: float) -> float:
    return x * 2.0

@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1
```

會影響應用設計的安全規則：

- 直接原生函式只能呼叫獲准的原生函式，以及支援的 builtin/標準函式庫操作。
- 呼叫僅 fallback 程式碼會拒絕原生呼叫者，除非明確標記的呼叫者符合 immutable scalar 邊界路徑。容器絕不穿越該邊界，迴圈或 comprehension 內的邊界呼叫會留在 fallback。
- Python 迴圈呼叫原生函式時會產生靜態跨界診斷 `RXT073`。只有符合條件的直接原生函式才會把 wrapper 進入與 scalar 邊界進入計入每個函式的執行期 fallback 門檻；plugin 路徑函式不參與計數。
- 在 `auto` 模式下，原生匯入無法使用或超過門檻時會使用 Python fallback，分析器拒絕的函式也會留在 fallback。`fallback` 模式明確停用原生執行。`native` 模式要求已升級的原生程式碼；其原生匯入無法使用時會拋出例外。`REXTIO_DEBUG_NATIVE=1` 會把原生載入警告改為 traceback 供診斷。
- `native-shim`/`RXT080` 透過 PyO3 呼叫 Python fallback 以保持動態 Python 語意。這是相容路徑，**不是 Rust 加速路徑**。
- 若 Rust ownership 會改變行為，可變 collection alias 會留在 Python。Rextio 不會只因「看似可以翻譯」就產生原生候選。

執行期控制：

```text
REXTIO_NATIVE_MODE=auto|fallback|native
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
REXTIO_DEBUG_NATIVE=1
```

## 支援的直接 Rust 程式形態

刻意維持狹窄的直接路徑涵蓋以下受支援組合：

- scalar `int`、`float`、`bool`、`str`、`bytes`、`None`；
- list（含巢狀）、固定 tuple、使用 scalar key 的固定 dict、有限的 `set[int|bool|str]`，以及 `Optional[T]` / `T | None`；
- 帶型別區域變數、算術、比較、`if`、`while`、支援的 `for`/`range`/`enumerate`/`zip`、comprehension 與獲准原生 helper；
- 有限的 builtin、`math`、字串/bytes/list 方法、日誌/輸出、`datetime`、`time`、`hashlib.sha256`、`base64.b64encode`。

重要排除項也很明確：`set[float]` 與 set 迭代無法保持 CPython 的 NaN identity/hash 順序；`statistics.mean/fmean`、`json.dumps/loads`、`base64.b64decode` 沒有直接原生路徑；檔案/網路/資料庫/ORM 操作與動態物件行為留在 fallback 或明確標記的相容 shim。完整的版本化邊界請見[不支援的功能](docs/unsupported-features.md)與[功能穩定性](docs/stability.md)。

## 建置輸出

| 要求 | 結果與邊界 |
| --- | --- |
| 預設建置 | 相容匯入的套件目錄，以及選用的、包含原生程式碼與 Python fallback 的 wheel。 |
| `--entrypoint=…` | Zipapp；目標機器仍需相容 Python，且不會從 zipapp 內匯入原生 extension。 |
| `--executable-backend=nuitka` | Experimental standalone/onefile 執行檔；需要 Nuitka。不宣稱能任意跨平台封裝第三方相依套件。 |
| `--executable-backend=rust` | 原生 Rust entrypoint。封閉呼叫圖可獨立執行；`python-subprocess` 只委派受限 immutable scalar 呼叫且需要 CPython，`nuitka-sidecar` 需要 Nuitka。runtime shim 與容器跨界會被拒絕。為可攜式程序狀態，建議結束碼 `0..255`。 |
| `--rust-importable` | Experimental Cargo path dependency crate，只包含直接 Rust 函式。fallback、shim、scalar 邊界函式仍面向 Python。 |

`rextio build` 與 `generate` 每次都會重新分析與產生；0.1.x 沒有增量建置快取。subprocess hybrid runtime 將原始碼複製至 `<binary>.runtime/`，因此委派程式碼看到的是副本的 `__file__`；依賴原檔案相對路徑尋找資料的程式碼需要其他方案。

## Plugin、裝置與外部原始碼

Plugin 是獨立 Python 發行套件，必須在專案設定中明確啟用。沒有 active plugin 的套件預設保守處理；`try-native` 是 Experimental 規劃政策，不是通用相依套件轉換承諾。

Device Provider API 1 的選擇同樣明確且為 Experimental。只設定 provider 不會讓 CPU-only Torch/TensorFlow 路徑取得 CUDA 能力。混合或衝突裝置 domain、缺少 provider、不支援的 GPU ordinal、錯誤 capability 都會 fail closed。Provider preflight 報告 `support_claim: false`；Core 不宣稱經認證的 CUDA 執行。

外部 pure-Python 原始碼清單是針對恰好一個已固定、已驗證 depth-1 `py3-none-any` 發行套件的非建置預覽。它不匯入套件、不把詞彙候選連接到專案呼叫，也不 lowering、複製、再散布或授權建置。缺少/無效 SourceLock 會阻擋；僅有驗證通過的 lock 仍不授予建置或散布權。

獨立的 `strict-evidence` **Alpha/Experimental** 設定嚴格限定為 macOS arm64 或 Linux x86_64 上的 CPython 3.11 host-extension 建置、一個 SourceLock 授權相依套件、scalar leaf 呼叫、擁有者固定的離線輸入、兩次隔離建置及外部 Ed25519 簽章。它排除 plugin、執行檔、Rust crate、embedding、原生 top-level 初始化、Windows、廣泛套件 lowering 與通用再散布。其 sandbox/support lock 只保護擁有者控制程序中的證據完整性；不代表安全開機、抵禦惡意同 UID 程序或已遭入侵 OS、通用 hermeticity、registry 身分驗證或跨平台認證。

> **法律邊界：**翻譯或再散布相依原始碼可能產生授權與衍生作品義務，尤其是 GNU/copyleft 條款。Rextio 的清單與 SourceLock 檢查不是法律建議或法律核准。

依賴這些進階功能前，請閱讀 [host source-AOT 與原生執行檔](docs/source-aot-and-executables.md)、[Device Provider API 1](docs/specs/device-provider.md) 與 [tooling contract](docs/specs/tooling-contract.md)。

## Numba 與 Nuitka

辨識到的 `@numba.*` decorator 表示明確選擇在 fallback 使用 **Numba 的**語意，而不是 Rextio 的 CPython 等價原生契約。請勿與 `@rextio.native` 組合。安裝 Numba 後，wheel/zipapp 與 source-hybrid 路徑可以運作；Nuitka 執行檔與 Nuitka hybrid dispatcher 會提早拒絕加速函式，因為編譯函式不暴露 bytecode 且 accelerator 未封裝。任何 accelerator 下，小函式都可能因邊界開銷而變慢。

## 範例與專案資訊

```bash
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math
```

在 [`examples/`](examples/) 中可查看直接數學運算、fallback 與邊界行為、wheel、zipapp、Nuitka、Numba、Rust 執行檔/crate 與嵌入 helper。Embedding 為 Experimental，預設關閉，僅 AOT、僅 scalar，並會改變原生呼叫者看到 monkeypatch 的方式；它不是執行期 JIT。

- [安全模型](SECURITY.md)
- [貢獻指南](CONTRIBUTING.md)
- [版本政策](docs/versioning.md)
- [變更記錄](CHANGELOG.md)
- [授權](LICENSE) — MIT

作者：Steve Si-young Song · [@RextioDev](https://x.com/RextioDev)
