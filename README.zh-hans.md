# Rextio

[English](README.md) | [한국어](README.ko.md) | [繁體中文](README.zh-hant.md) | [日本語](README.ja.md)

Rextio 0.1.0 是 alpha 阶段的本地 Python 构建工具。

它会找出可以安全降低到 Rust 的 Python 函数，提前编译这些函数，并让其余代码继续通过
Python fallback 运行。

```text
typed Python project
  -> 分析 native 候选
  -> 拒绝不支持或不安全的函数
  -> 为 accepted 函数生成 Rust + PyO3
  -> 为其余代码生成 Python fallback wrapper
  -> 构建可 import 的 hybrid artifact
```

Rextio 不是 Python 替代品，也不是 whole-project Rust migration 工具。Native 编译只是优化；
Python fallback 行为是正确性基线。

## 提供什么

| 产物 | 用途 |
| --- | --- |
| `.rextio/generated/rust/` | accepted native 函数的 Rust/PyO3 源码 |
| `.rextio/generated/python/` | Python wrapper 与 fallback module |
| `.rextio/build/python/` | 可 import 的 hybrid package tree |
| `dist/*.whl` | 包含 fallback 代码和 native extension 的 wheel |
| `dist/<name>.pyz` | Python entrypoint 的 zipapp 可执行 artifact |
| `dist/<name>.dist/` 或 `dist/<name>` | Nuitka standalone/onefile 可执行 artifact |
| `dist/<crate>-rust-crate/` | Rust 项目可作为 path dependency 使用的 crate |

生成的 Python wrapper 会优先尝试 native；当 native 被禁用、无法加载、分析拒绝，或超过
boundary threshold 时会使用 Python fallback。

```text
REXTIO_DISABLE_NATIVE=1
```

## 快速示例

```python
# src/myapp/math_ops.py
def sum_squares(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += x * x
    return total

def format_result(value: int) -> str:
    return f"score={value}"  # 不属于 direct Rust subset
```

```text
python -m pip install -e .
rextio check .
rextio build . --fallback=cpython
```

Rextio 可以把 `sum_squares` 编译为 Rust，并让 `format_result` 保持 Python fallback。
Python import 路径保持不变。

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

`rextio generate` 只写出生成源码，不运行 Cargo、maturin、Nuitka、wheel 构建或 executable
打包。`rextio build` 会执行生成、编译和打包。

## 命令

| 命令 | 作用 |
| --- | --- |
| `rextio init` | 创建 `rextio.toml`、`REXTIO.md`、`.rextioignore` |
| `rextio check` | 分析 native 候选并输出 diagnostics |
| `rextio generate` | 不编译，只生成 Rust/Python 源码 |
| `rextio build` | 生成、编译、打包，并写出 build report |
| `rextio bench` | 对一个函数比较 Python fallback 和 Rust native 时间 |
| `rextio clean` | 删除 `.rextio/build`、`.rextio/generated`、`.rextio/reports` |

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

## Native 选择

默认使用自动 native discovery：

```toml
[policy]
native_marker = "auto"
```

当函数类型可解析并符合 direct Rust subset 时，Rextio 可以自动把 module-level 函数作为
native 候选。也可以切换为只接受显式 marker：

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

未来多 target 场景可以指定 target：

```python
@rextio.native(target="rust")
def score(x: float) -> float:
    return x * 2.0
```

必须留在 Python fallback 的函数使用 `@rextio.exempt`：

```python
@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1
```

exempt 函数永远不会生成到 Rust 中。native 候选如果调用 exempt 或 fallback-only 函数，也会
转为 fallback。

## 安全模型

- direct Rust native 函数只能调用 accepted native 函数、支持的 builtin 和支持的标准库函数。
- 调用 fallback-only 代码的 native 函数会被拒绝。
- Python fallback 代码可以调用 native 函数。
- Python loop 重复调用 native 函数时会产生 boundary warning。
- wrapper crossing 超过阈值后，生成 wrapper 可以把该函数切回 fallback。
- Python/Rust ownership 差异会显式处理：只读复用会在需要时 clone；mutable collection alias
  mutation 保留在 Python fallback。

相关运行时设置：

```text
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
REXTIO_NATIVE_MODE=auto|fallback|native
```

## direct Rust subset

0.1.0 alpha 只支持一个小 subset。这是能获得实际 Rust speedup 的路径。

支持类型包括 `int`、`float`、`bool`、`str`、`bytes`、`None`、`list[T]`、
`list[list[T]]`、fixed `tuple[...]`、fixed `dict[K, V]`、有限 `set[...]`、
`Optional[T]` 和 `T | None`。

支持语法包括 local assignment、typed local annotation、算术、比较、`if`、`while`、
`for x in xs`、支持形式的 `range`/`enumerate`/`zip`、`break`、`continue`、`return`、
有限 list/dict/set comprehension、有限 `list.append`、dict read/write、indexing，以及
accepted native helper 调用。

有限降低的 builtin/标准库包括 `len`、`abs`、`min`、`max`、`sum`、`all`、`any`、
`sorted`、`reversed`、部分 `math`、部分 `str`/`bytes`/`list` method、`print`、`logging`、
`datetime`、`time`、`statistics`、`hashlib.sha256`、`base64`、`json`。

不支持或语义不明确的代码会留在 fallback，或在支持时通过 Python runtime semantics shim
保留行为。详细边界见 [0.1.0 alpha 不支持的功能](docs/unsupported-features.md)。

## Python runtime semantics shim

有些 Python 功能无法安全变成 typed Rust statement。对显式标记的 native 代码，Rextio 可以
生成一个调用 Python fallback 实现的 PyO3 shim。

这个 compatibility 路径可用于保留 class/object、instance method、exception、context
manager、`async`/`await`、generator、dynamic attribute access 等行为，并报告 `RXT080`。
它是行为保留路径，不是 Rust speedup 路径。

## Rust-importable crate

如果 direct Rust 函数也要给 Rust 应用使用，可以额外生成 Cargo library crate：

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

该 crate 只 export 直接降低到 typed Rust 的函数。fallback-only 函数和 runtime semantics
shim 仍是 Python-facing 路径。

## 实验性 scalar helper 内嵌（embedding）

Rextio 可以把非常窄的 scalar helper（类型确定、单一算术 return 表达式的 unmarked
函数）以 AOT 方式内嵌进 native 函数。默认关闭。

```toml
[jit]
enabled = true
```

同样的设置也可以通过 `rextio build . --jit` 或 `REXTIO_JIT=true` 指定。内嵌的
helper 走正常的 checked 路径编译：overflow 正确地 raise OverflowError，除零
raise ZeroDivisionError，且不会作为 PyO3 函数导出。不存在运行时编译。（过去的
Cranelift 运行时 JIT 及其 `backend`/`hot_threshold` 配置经基准测试证明始终慢于
AOT 路径，已被移除；被移除的环境变量会立即报错并给出迁移提示。）

## Numba 外部加速器

带有 `numba.jit`/`njit`/`vectorize`/`guvectorize`/`cuda.jit` 装饰器的函数会有意
留在 Python fallback（无诊断噪音），并在报告中标记为
`external_accelerator: numba`。这类函数按 Numba 的语义执行（例如 nopython 模式
int overflow 会 wrap），在 Rextio 的 CPython 精确性契约之外 — 与 `@rextio.exempt`
相同的 opt-in 哲学。`--fallback=nuitka` 自动共存：使用加速器的模块被排除在编译
之外、保持为 plain `.py`；wheel 会排除已被 Nuitka 编译模块的 `.py` 源码并带上
平台标签。Nuitka *可执行文件* 与 `--hybrid-runtime=nuitka` 在存在加速模块时会
带指引提前失败（请改用 `--hybrid-runtime=source`）。构建时扫描的覆盖面比
报告标签更广：`rextio check` 标签只处理直线式 import，因此没有标签的函数
所在模块在构建中仍可能被正确地保持为 plain。

## 可执行 artifact

```text
rextio build . --entrypoint=myapp.cli:main --executable-name=myapp
```

这会写出 `dist/myapp.pyz`。目标机器仍需要兼容的 Python interpreter。Native extension 不会
直接从 zipapp 内 import，因此 `_rextio_native` 不可用时 wrapper 会保持 fallback 行为。

Nuitka executable 打包是实验性的，并要求安装 Nuitka：

```text
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=standalone
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
```

## 配置

```text
CLI parameter > environment variable > rextio.toml > built-in default
```

主要设置：

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

当前实现的 native target 只有 Rust。`mojo` 和 `julia` 只是未来 backend 的 planning 值。
Rextio plugin 是通过 `pip` 或 `uv` 安装的普通 Python package，并通过 `rextio.plugins`
entry point group 暴露 metadata。项目通过 `[plugins] enabled` 或 `--enable-plugin`
声明要使用的 plugin id。没有 plugin 的外部 Python package 默认 fallback。可以通过
`[imports.packages]` 或 `--package-import-policy` 对明确允许的 pure-Python dependency
设置 `try-native`，但如果没有安全的 direct lowering，Rextio 仍会使用 fallback。
0.1.0 alpha 不内置具体第三方 plugin 变换。

## 示例

```text
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math

rextio check examples/boundary_demo
rextio build examples/fallback_demo --entrypoint=fallback_demo.run_demo:main
```

- `examples/pure_math`: typed math hot path 的 direct Rust lowering
- `examples/fallback_demo`: native 禁用或缺失时的 fallback 行为
- `examples/boundary_demo`: native-to-fallback boundary rejection 和 warning
- `examples/app_shell`: application shell 保持 Python，scoring hot path 可 native
