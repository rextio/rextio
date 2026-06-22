# Rextio

[English](README.md) | [한국어](README.ko.md) | [简体中文](README.zh-hans.md) | [日本語](README.ja.md)

Rextio 0.1.0 是 alpha 階段的混合建置工具。它會把符合條件、可靜態解析型別的 Python
函式編譯為 Rust 原生模組，並把其餘程式碼封裝為安全的 Python fallback。

0.1.0 alpha 的範圍刻意保持很窄。它是面向可靜態解析型別的 Python 熱路徑專案的本機 CLI 和
建置工具 MVP。Rextio 預設會自動發現型別來自 annotation、同名 `.pyi` stub 或保守本機
上下文推斷的符合條件函式；專案也可以選擇停用自動發現，並要求使用 `@rextio.native`
標記。Rextio 不宣稱提供完整 Python 相容性、內建第三方套件涵蓋、框架遷移、JIT 行為，
或完整的執行階段邊界成本最佳化器。

0.1.0 alpha 包含保守的靜態邊界檢查。它會拒絕呼叫 fallback-only 程式碼的 native 函式，
當 Python 迴圈反覆呼叫 native 函式時發出警告，並且在重複的 Python/Rust 邊界
crossing 超過簡單執行階段閾值後，讓產生的 wrapper 將該 native 函式切換到 fallback。

## 目前命令

```text
rextio init
rextio check
rextio generate
rextio build
rextio bench
rextio clean
```

初始實作著重於專案初始化、native 候選發現、subset 診斷、靜態邊界診斷、執行階段
停用旗標，以及確定性的 check report。

典型本機流程：

```text
python -m pip install -e .
rextio init --project-root path/to/project
rextio check path/to/project
rextio generate path/to/project --fallback=cpython
rextio build path/to/project --fallback=cpython
rextio build path/to/project --fallback=cpython --rust-importable --rust-crate-name=my_native
rextio build path/to/project --fallback=cpython --entrypoint=myapp.cli:main
rextio bench myapp.scoring.compute_score --project-root path/to/project
rextio clean path/to/project
```

## 0.1.0 alpha 範圍

0.1.0 alpha 支援一個面向模組層級函式的小型靜態型別 subset。當 Rextio 能從 source
annotation、同名 `.pyi` stub 或保守本機上下文推斷解析所有參數和返回型別時，符合條件的
函式預設會成為 native 候選。不支援的語法、未解析的型別、動態特性、不安全的
native-to-fallback 呼叫，以及無法解析的外部呼叫，都會從 native 編譯中被拒絕，並在可能時
保留為 Python fallback。

關於支援的 subset、邊界限制、診斷和非目標，請參閱
[0.1.0 alpha 不支援的功能](docs/unsupported-features.md)。

目前 native 候選支援包含 `bytes` 的 scalar、`list[...]` 與 `list[list[T]]`、fixed `tuple[...]`、有限的
固定 `dict[K, V]`、有限的 `set[int|float|bool|str]`，以及 `Optional[T]` / `T | None` 型別。支援的語法包括算術、
比較、`if`、`while`、`for x in xs`、`range(...)` 迴圈、
`for i, x in enumerate(xs)`、`for x, y in zip(xs, ys)`、`break`、`continue`、
augmented assignment、帶型別的區域 annotation、簡單索引、list literal、fixed tuple
literal、有限的 dict read/write、有限的 list/dict/set comprehension、comprehension 內的
assignment expression，以及支援的 list item 型別上的 `list.append(...)`。
Builtin 支援刻意限制為 `len`、`abs`、兩個參數的 `min`/`max`、
`sum(list[int|float])`、`all`/`any`，以及有限的 `sorted`/`reversed`。
支援的 `math` subset 包含三角函式、對數、rounding、finite/NaN 檢查，以及
`math.pi`/`math.e`。常見 side-effect 和標準函式庫 lowering 包含 `print(...)`、
`logging.debug/info/warning/error(...)`、由 `logging.getLogger(...)` 指派的
logger 變數、`datetime`/`time`、`statistics`、選定的 `str`/`bytes`/`list`
method，以及有限的 `hashlib.sha256`、`base64`、`json` pattern。

這些擴充形式仍保持保守：空 list literal 需要受支援的 `list[...]` 區域 annotation，
且 `range(start, stop, step)` 目前要求 `step` 是正的 int literal。`enumerate` 和
`zip` 僅支援作為 list 變數上的 batch loop 或 comprehension iterable。Native subset
現在支援有限的 list/dict/set comprehension、comprehension 內的 assignment expression、
`list[list[T]]`、固定 `dict[K, V]`，以及 `set[int|float|bool|str]` comprehension。
dataclass 仍不在 direct Rust lowering 範圍內。

Rextio 會保守處理 Python/Rust ownership 差異。對於 `str`、`bytes`、`list`、`dict`、
`set` 等 Rust owned value 的唯讀重用，Rextio 會在需要的位置產生明確 clone。相反，
`ys = xs` 這類 mutable collection alias 後再 mutate 任一 alias 的 Python pattern 會保留在
Python fallback，因為 Rust ownership 與 Python reference aliasing 的語意並不相同。

對於無法安全 lowering 為 direct Rust 的 Python semantics，Rextio 可以產生 Python runtime
semantics native shim。該 shim 是呼叫產生的 Python fallback 實作的 Rust/PyO3 函式，因此可以
保留 class/object 行為、標記為 `@rextio.native` 的一般 instance method、exception handling、
context manager、`async`/`await`、generator/`yield`，以及 `getattr` 或 `obj.attr` 等 dynamic
attribute access。該路徑會報告 `RXT080`，它是 compatibility 路徑，不是 Rust speedup 路徑。
該路徑的 automatic discovery 保持保守；較寬的 object-runtime 程式碼應明確標記
`@rextio.native`。

型別推斷刻意保持窄範圍。Rextio 可以從常數、算術、比較、`if` test、loop、indexing、
comprehension 和受支援 builtin 推斷簡單 scalar 與 collection signature。缺少 source
annotation 時，會優先參考同名 `.pyi` 檔案的 signature。型別仍然模糊時，該函式保留在
Python fallback。

模組頂層邏輯預設保留在 Python fallback。設定 `[policy] native_top_level = true` 或
`--native-top-level` 後，Rextio 會嘗試產生受限的 native initializer。支援範圍包括
assignment、annotated assignment、augmented assignment、受支援 expression，以及只更新已
提前賦值模組變數的 `if`/`while` block。匯出的模組變數必須共享一個受支援 value 型別；
native 被停用或不可用時會使用原始 fallback 模組。

## 建置前提

Native 建置需要 Rust 和 Cargo。設定 `[rust] build_tool = "maturin"` 時，Rextio 也可以
使用 `maturin`；如果 maturin 不可用，Rextio 會在可能時 fallback 到 Cargo。

Nuitka fallback 封裝是實驗性的。如果在未安裝 Nuitka 的情況下要求
`--fallback=nuitka`，Rextio 會回報明確的 `RXT060` 錯誤並建議使用
`--fallback=cpython`。安裝 Nuitka 後，Rextio 會對產生的 Python fallback 模組執行
Nuitka，同時仍在建置產物中保留 CPython fallback 檔案。

省略 `--fallback` 時，`rextio build` 會使用 `rextio.toml` 中的
`[build] fallback_backend`。傳入 `--fallback=cpython` 或 `--fallback=nuitka` 會覆寫
本次執行的專案設定。

## 設定來源

建置和分析設定按以下優先順序解析：

```text
CLI parameter > environment variable > rextio.toml > built-in default
```

`project_root`、bench target、`init --force`、`check --json` 等決定命令執行方式或輸出
形式的參數仍然只屬於 command line。專案行為設定可以從以下任一來源設定：

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
| `[mappers] paths` | `--mapper-path` | `REXTIO_MAPPER_PATHS` |
| `[mappers] enabled` | `--enable-mapper` | `REXTIO_MAPPERS_ENABLED` |
| `[mappers] repository` | `--mapper-repository` | `REXTIO_MAPPER_REPOSITORY` |
| `[executable] entrypoint` | `--entrypoint` | `REXTIO_EXECUTABLE_ENTRYPOINT` |
| `[executable] name` | `--executable-name` | `REXTIO_EXECUTABLE_NAME` |
| `[executable] backend` | `--executable-backend` | `REXTIO_EXECUTABLE_BACKEND` |
| `[executable] nuitka_mode` | `--nuitka-mode` | `REXTIO_NUITKA_MODE` |
| `[policy] native_marker` | `--native-marker` | `REXTIO_NATIVE_MARKER` |
| `[policy] require_type_hints` | `--require-type-hints` / `--no-require-type-hints` | `REXTIO_REQUIRE_TYPE_HINTS` |
| `[policy] allow_dynamic_features` | `--allow-dynamic-features` / `--no-allow-dynamic-features` | `REXTIO_ALLOW_DYNAMIC_FEATURES` |
| `[policy] boundary_warnings` | `--boundary-warnings` / `--no-boundary-warnings` | `REXTIO_BOUNDARY_WARNINGS` |
| `[policy] native_top_level` | `--native-top-level` / `--no-native-top-level` | `REXTIO_NATIVE_TOP_LEVEL` |

0.1.0 alpha 仍會保守地驗證取值。目前已實作的 native target 只有 Rust。
`native_backend = "mojo"` 和 `native_backend = "julia"` 會作為未來的 target-language
選擇被接受，因此可以設定 versioned mapper 和 build-option metadata；但在對應 backend
實作前，source generation 會明確失敗。

Mapper plugin 可從 local metadata folder 或 public Git repository 載入。Local folder
透過 `[mappers] paths` 和選用的 `[mappers] enabled` 設定；每個 folder 必須包含
`rextio-mapper.toml` 或 `mapper.toml`。`[mappers] repository`、`--mapper-repository`
或 `REXTIO_MAPPER_REPOSITORY` 可設定為 public Git URL；Rextio 會將其 clone 到
`.rextio/mappers/repositories/` 並遞迴發現 mapper manifest。

## 產生的產物

Rextio 會把產生的檔案寫入 `.rextio/` 下，不會就地修改使用者原始檔。

```text
.rextio/
  build/
    python/
      rextio/
        runtime/
  generated/
    <target-language>/
    rust_crate/
    python/
  reports/
    check.json
    build.json
    bench.json
dist/
  <project>-0.1.0-<tag>.whl
  <rust-crate-name>-rust-crate/
  <executable-name>.pyz
  <executable-name>
  <executable-name>.dist/
```

`rextio check` 會寫入 `.rextio/reports/check.json`。`rextio build` 會同時寫入 check 和
build report。`rextio bench` 會寫入 `.rextio/reports/bench.json`，其中包含結構化的
fallback/native 計時比較。

`rextio generate` 會執行分析，並在 `.rextio/generated/` 下寫入產生的 Rust/PyO3 和
Python wrapper/fallback 原始碼；它不會呼叫 Cargo、maturin 或 Nuitka，也不會建立
`.rextio/build/` 或 `dist/`。使用 `--rust-importable` 時，它還會在
`.rextio/generated/rust_crate/` 下寫入 Rust library crate 原始碼，但仍不會編譯該 crate。

`rextio build` 成功後，還會在 `dist/` 下寫入產生的 hybrid artifact wheel。純
fallback wheel 使用 `py3-none-any`；包含產生 native extension 的 wheel 使用本機
CPython/platform tag。測試套件會把該 wheel 安裝到全新環境中，並用
`REXTIO_DISABLE_NATIVE=1` 驗證封裝後的 fallback import 仍能運作。

`rextio build --rust-importable --rust-crate-name=my_native` 還會產生可從 Rust 直接使用的
library crate，並用 Cargo 編譯。Source artifact 會複製到 `dist/my_native-rust-crate/`，
Rust 專案可以透過 path dependency 使用它。

```toml
[dependencies]
my_native = { path = "../dist/my_native-rust-crate" }
```

產生的 crate 函式使用 Rextio deterministic native 名稱，並返回
`Result<T, RextioError>`。

```rust
fn main() -> Result<(), my_native::RextioError> {
    let value = my_native::myapp__math_ops__sum_squares(vec![1, 2, 3])?;
    assert_eq!(value, 14);
    Ok(())
}
```

Rust-importable crate 只包含直接 lowering 到 typed Rust 的函式。Python runtime semantics
shim 和 fallback-only 函式仍保留為 Python-facing compatibility 路徑，不會 export 到該 crate。

`rextio build --entrypoint=module:function` 還會在 `dist/` 下產生 zipapp 可執行
artifact。可以使用 `--executable-name=name` 控制輸出檔名；否則 Rextio 會從
entrypoint 模組推導名稱。結果是 Python zipapp（`.pyz`），因此目標機器仍需要相容的
Python 直譯器。Native extension 模組不能直接從 zipapp 內部 import，所以產生的
wrapper 會保留 fallback 安全性，並在 native 模組不可用時使用 Python fallback。

安裝 Nuitka 後，也可以產生 Nuitka executable artifact：

```text
rextio build path/to/project \
  --entrypoint=myapp.cli:main \
  --executable-backend=nuitka \
  --nuitka-mode=standalone

rextio build path/to/project \
  --entrypoint=myapp.cli:main \
  --executable-backend=nuitka \
  --nuitka-mode=onefile
```

standalone 模式會在 `dist/` 下寫入 Nuitka `.dist` 應用程式目錄。onefile 模式會在
`dist/` 下寫入單一 Nuitka 可執行檔。Nuitka executable 封裝仍依賴本機 toolchain。
如果 Nuitka 不可用，Rextio 會回報明確的 `RXT060` 錯誤並建議使用 zipapp backend。

## 策略設定

0.1.0 alpha 會保守地驗證 `rextio.toml`，並拒絕未知 section、未知 key、不支援的 backend，
以及超出 0.1.0 alpha 範圍的策略值。

邊界警告預設啟用。希望只保留嚴格安全錯誤、不要 Python-loop 邊界警告的專案可以設定：

```toml
[policy]
boundary_warnings = false
```

自動 native discovery 預設啟用：

```toml
[policy]
native_marker = "auto"
```

只希望使用明確 native 候選的專案可以停用 auto discovery：

```toml
[policy]
native_marker = "decorator"
```

在 decorator-only 模式下，只有用 `@rextio.native` 標記的函式才會成為 native 候選。

顯式 marker 也可以固定目標 native 語言。例如
`@rextio.native(target="rust")` 只會在 active `--target-language` /
`[build] native_backend` 為 Rust 時生效。`target="mojo"` 和 `target="julia"` 會作為
未來 backend 的 planning 值保留，但 0.1.0 alpha 只實作 Rust source generation。

即使啟用了自動 native discovery，也可以使用 `@rextio.exempt` 讓某個函式保留在
Python fallback。exempt 函式永遠不會被 emit 到產生的 Rust；呼叫它們的 native 候選
會依正常的 native-to-fallback 邊界規則被拒絕。

## Fallback 安全性

產生的 wrapper 會在可用且安全時使用 native 函式。當 native import 失敗，或 native
執行被停用時，它們會 fallback 到 Python。

```text
REXTIO_DISABLE_NATIVE=1
```

當專案需要明確的執行階段行為時，可以設定 `REXTIO_NATIVE_MODE`：

```text
REXTIO_NATIVE_MODE=auto      # 預設：可用時使用 native，否則 fallback
REXTIO_NATIVE_MODE=fallback  # 強制 Python fallback
REXTIO_NATIVE_MODE=native    # 要求產生的 native 函式可用
```

重複的 Python-to-native wrapper 呼叫一開始是允許的。如果某個函式的 wrapper crossing
次數超過 `REXTIO_BOUNDARY_FALLBACK_THRESHOLD`，後續呼叫會使用該函式產生的 Python
fallback。預設閾值為 `1000`。`rextio generate --fallback-threshold=N` 和
`rextio build --fallback-threshold=N`、`REXTIO_BOUNDARY_FALLBACK_THRESHOLD`、
`[build] fallback_threshold = N` 都可以為該 artifact 設定產生程式碼預設值。執行階段
`REXTIO_BOUNDARY_FALLBACK_THRESHOLD` 會覆寫這個 embed 的預設值。將閾值設為 `0`，或設定
`REXTIO_DISABLE_BOUNDARY_FALLBACK=1`，可以停用此自動 fallback。`REXTIO_NATIVE_MODE=native`
會繞過該閾值。

使用 `.rextioignore` 可以讓 Rextio 分析忽略產生檔案或無關的 Python 檔案。

## 邊界診斷

0.1.0 alpha 的邊界檢查是靜態且保守的：

- `RXT070`：native 函式呼叫了 fallback-only Python 程式碼。
- `RXT072`：native 函式依賴被拒絕的 native 函式。
- `RXT073`：fallback Python 在迴圈中呼叫 native 函式。
- `RXT080`：native 函式使用 Python runtime semantics shim。

`RXT070` 和 `RXT072` 會拒絕 native 候選。`RXT073` 是警告；該函式仍然符合條件，並且
一開始可以使用 native，但當重複的執行階段 crossing 超過設定閾值後，產生的 wrapper
會 fallback 到 CPython/Nuitka fallback 路徑。`RXT080` 是 warning；產生的 Rust 函式會呼叫
Python fallback 函式以保留 Python semantics。

## 範例

0.1.0 alpha 包含聚焦的本機範例：

- `examples/pure_math`：編譯為 native hot path 的簡單 typed 數學函式。
- `examples/fallback_demo`：當 native 缺失或設定 `REXTIO_DISABLE_NATIVE=1` 時，產生的 wrapper 使用 Python fallback。
- `examples/boundary_demo`：透過 `@rextio.exempt` 展示保守邊界拒絕，以及 Python-loop 邊界警告。

試一試：

```text
rextio check examples/pure_math
rextio generate examples/pure_math --fallback=cpython
rextio build examples/pure_math --fallback=cpython
rextio build examples/fallback_demo --entrypoint=fallback_demo.run_demo:main
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math
rextio check examples/boundary_demo
```
