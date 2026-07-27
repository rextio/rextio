# Rextio

[English](README.md) | [한국어](README.ko.md) | [繁體中文](README.zh-hant.md) | [日本語](README.ja.md)

**把符合条件的 typed Python 函数编译为 Rust，其余一切保留在 Python fallback 上。**

Rextio 是 alpha 阶段的本地 Python 构建工具。它找出可以安全下沉到 Rust
的带类型 Python 函数，用 PyO3 提前（ahead-of-time）编译它们，其余部分
全部继续通过生成的 Python fallback 代码运行 — import 路径与行为保持不变。

各版本变更请见 [CHANGELOG.md](CHANGELOG.md)。

```text
带类型的 Python 项目
  -> 分析受支持的 native 候选
  -> 拒绝不安全或不受支持的函数
  -> 为被接受的函数生成 Rust + PyO3
  -> 为其余部分生成 Python fallback wrapper
  -> 构建 import 兼容的 artifact
```

契约是严格的: 函数要么以与 CPython 等价的语义编译为 native 代码，要么
带着诊断被拒绝、留在 Python fallback 上。Rextio 拿不准时不会猜测 —
它选择 fallback。

Rextio 不是 Python 的替代品，也不是整个项目迁移到 Rust 的工具。Native
编译是一种优化，Python fallback 行为始终是正确性的基准线。

## 快速开始

从带类型注解的普通 Python 代码开始:

```python
# src/myapp/math_ops.py
def sum_squares(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += x * x
    return total

def format_result(value: int) -> str:
    return f"score={value}"  # 不在 direct Rust subset 内
```

安装并分析/构建（从源码检出请改用
`python -m pip install -e .`）:

```text
python -m pip install rextio
rextio check .
rextio build . --fallback=cpython
```

Rextio 可以把 `sum_squares` 编译为 Rust，让 `format_result` 留在 Python
fallback。import 路径保持 Python 原样:

```python
from myapp.math_ops import sum_squares, format_result

assert sum_squares([1, 2, 3]) == 14
assert format_result(14) == "score=14"
```

Native 是优化，不是必需。即使 native 模块缺失、被禁用或加载失败，包仍会
通过 Python fallback 运行。运行时强制 fallback:

```text
REXTIO_NATIVE_MODE=fallback
```

首个项目常用命令: `rextio init`、`rextio check`、
`rextio generate`（只写出生成源码、不编译）、`rextio build`、
`rextio bench`、`rextio clean`。

<!-- rextio-benchmark:start -->
## 已验证的 CPU 基准结果

在 **Mac16,11 / Apple M4 Pro**、**2026-07-26**、CPython **3.11.9** 上的三次运行中位数。

| 工作负载 | 三次运行中位加速比 |
| --- | ---: |
| Core hybrid | 57.729× |
| NumPy mixed fusion | 2.523× |
| NetworkX Dijkstra | 3.679× |
| pandas Series.map | 66.143× |
| PyTorch CPU deep MLP | 1.017× |
| TensorFlow CPU eager chain | 1.040× |

结果仅针对对应工作负载。接近 1× 表示性能相当（parity），而非实质性加速；未测量 CUDA。

**完整方法、确切版本修订的来源、原始证据、诊断与详细结果，请使用 [rextio-benchmark](https://github.com/rextio/rextio-benchmark) 仓库。**
<!-- rextio-benchmark:end -->

## 环境要求

| 组件 | 版本 | 说明 |
| --- | --- | --- |
| CPython | >= 3.11（在 3.11-3.14 上验证） | 分析器使用构建解释器的 `ast`；生成的扩展固定 PyO3 0.29（最高支持 CPython 3.14）。更新的解释器可能可用，但未经验证。wheel 带有构建解释器 minor 版本标签。 |
| Rust toolchain | MSRV 1.83（在最新 stable 上验证） | 生成的 crate 使用 edition 2021 + PyO3 0.29。请通过 [rustup](https://rustup.rs) 安装。 |
| Nuitka（可选） | >= 2.0 | 仅用于 `--fallback=nuitka`/`--executable-backend=nuitka`/`--hybrid-runtime=nuitka`。前两者由构建 preflight 预先拒绝；hybrid runtime 则在被委托的 fallback 调用确实需要 Nuitka dispatcher 时检查。 |
| Numba（可选，experimental） | 随解释器: 3.11→>=0.57, 3.12→>=0.59, 3.13→>=0.61, 3.14→>=0.63 | Rextio 只识别 Numba 装饰器；该包是用户项目的运行时依赖，而非 Rextio 的依赖。下限遵循 [Numba 版本支持表](https://numba.readthedocs.io/en/stable/user/installing.html#version-support-information)。 |

工具位置与版本 pin 可配置: 通过 `rextio.toml` 的 `[toolchain]`（或
`REXTIO_*` 环境变量 / CLI 标志）选择构建所用的 cargo、maturin、Nuitka
和 CPython，并可校验其版本。参见
[REXTIO.md](./REXTIO.md#toolchain-selection-and-version-pins)。

## 构建 target

Rextio 可以从同一个 Python 项目产出多种 artifact:

| 产出 | 用途 |
| --- | --- |
| `.rextio/generated/rust/` | 被接受的 native 函数的 Rust/PyO3 生成源码。 |
| `.rextio/generated/python/` | 生成的 Python wrapper 与 fallback 模块。 |
| `.rextio/build/python/` | import 兼容的 hybrid 包树。 |
| `dist/*.whl` | 含 fallback 代码以及（构建成功时）native 扩展的 wheel。 |
| `dist/<name>.pyz` | 为配置的 Python entrypoint 生成的 zipapp 可执行文件（可选）。 |
| `dist/<name>.dist/` 或 `dist/<name>` | Nuitka standalone/onefile 可执行文件（可选）。 |
| `dist/<name>` | 独立的 native Rust 二进制（`--executable-backend=rust`），无需 Python 运行时（可选）。 |
| `dist/<crate>-rust-crate/` | 供 Rust 项目 import 的 Rust 库 crate（可选）。 |

生成的 Python wrapper 会先尝试 native 代码；当 native 被禁用、不可用、被
分析拒绝、或超过配置的 boundary threshold 时回落到 Python。

```text
REXTIO_NATIVE_MODE=fallback
```

设置 `REXTIO_DEBUG_NATIVE=1` 可以在构建出的 native 模块加载失败时抛出完整
traceback（而不是警告后回落）— 调试 ABI 不匹配或 wrapper/codegen 命名不
一致时很有用。

Zipapp:

```text
rextio build . --entrypoint=myapp.cli:main --executable-name=myapp
```

写出 `dist/myapp.pyz`。目标机器仍需要兼容的 Python 解释器。native 扩展
不会从 zipapp 内部 import，因此 `_rextio_native` 不可用时 wrapper 保持
fallback 行为。

Nuitka:

```text
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=standalone
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
```

Nuitka 可执行文件打包是 experimental 的，需要安装 Nuitka。

Native Rust 二进制:

```text
rextio build . --entrypoint=myapp.cli:main --executable-backend=rust
```

编译一个 `main` 在 Rust 中运行的 native 二进制（`dist/<name>`）。
entrypoint 必须是被接受的 direct-native `def main(argv: list[str]) -> int`:
`argv` 对应 `sys.argv`（index 0 是程序路径），返回的 `int` 是进程退出码，
抛出的错误以 CPython 风格（`OverflowError: ...`）打印到 stderr 并以非零
退出。需要 Cargo。

当 entrypoint 调用留在 Python fallback 的项目函数（Rust subset 之外的
代码）时，Rextio 把该调用委托给外部 CPython 子进程: 构建会附带
`dist/<name>.runtime/` 目录（dispatcher + 项目源码），二进制通过 stdio
驱动它，难以编译的逻辑可以留作 Python。这样的 hybrid 二进制在运行时需要
Python 解释器；调用图完全 direct-native 的二进制则是无 Python 依赖的
独立程序。被委托调用的参数与结果都必须是不可变标量
（`int`/`float`/`bool`/`str`/`None`）；`list`/`dict`/`set` 在任一方向都
不被委托（它们按值过线，切断 CPython 保持的别名关系，被修改的参数或被
修改的别名返回值会悄悄偏离），非有限 float（`NaN`/`Infinity`）会被拒绝
而不是悄悄丢弃。被委托函数自身的 stdout/stderr 出现在二进制的 stderr 上
（二进制的 stdout 承载线协议）。RXT080 runtime shim 上的函数不被委托:
依赖它的 entry 会被拒绝而非构建。

`--executable-python` 固定二进制启动的解释器（`PATH` 上的名字、绝对路径、
或相对 `<binary>.runtime` 的路径以便捆绑）。`REXTIO_RUNTIME_PYTHON` 在
目标机器上于运行时覆盖它。`--hybrid-runtime=nuitka` 则把被委托的 Python
编译成随 runtime 目录一起交付的自包含 dispatcher 可执行文件，使 hybrid
二进制无需单独安装 Python（构建时需要 Nuitka）。

当 Rust 应用需要使用 direct Rust 函数时，构建一个额外的 Cargo 库 crate:

```text
rextio build . --rust-importable --rust-crate-name=my_native
```

在 Rust 中使用生成的 crate:

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

只有直接下沉为带类型 Rust 的函数通过该 crate 导出。仅 fallback 的函数、
runtime semantics shim、以及使用标量 boundary call 的函数（都需要解释器）
仍是面向 Python 的路径。

## 配置

构建/分析设置按此顺序解析:

```text
CLI 参数 > 环境变量 > rextio.toml > 内置默认值
```

常用设置:

| `rextio.toml` 键 | CLI 参数 | 环境变量 |
| --- | --- | --- |
| `[build] native_backend` | `--native-backend` / `--target-language` | `REXTIO_TARGET_LANGUAGE` / `REXTIO_NATIVE_BACKEND` |
| `[build] fallback_backend` | `--fallback` | `REXTIO_FALLBACK_BACKEND` |
| `[build] fallback_threshold` | `--fallback-threshold` | `REXTIO_BOUNDARY_FALLBACK_THRESHOLD` |
| `[build] build_timeout_seconds` | `--build-timeout` | `REXTIO_BUILD_TIMEOUT` |
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
| `[embedding] enabled` | `--embed-helpers` / `--no-embed-helpers` | `REXTIO_EMBED_HELPERS` |
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

0.1.7 中唯一实现的 native 目标是 Rust。

Rextio 插件是用 `pip` 或 `uv` 等工具安装的普通 Python 包。插件包通过
`rextio.plugins` entry point 组暴露元数据，包括它覆盖的 Python 包名。
项目用 `[plugins] enabled` 或 `--enable-plugin` 启用特定插件 id。

没有激活 Rextio 插件的外部 Python 包默认保守处理: Rextio 不会悄悄把第三
方包源码翻译成 Rust。除非添加插件，或对已知纯 Python 包显式 opt-in 实验
性依赖分析，对这些包的调用会让周围的 native 候选留在 fallback:

```toml
[imports]
default_external_policy = "fallback"

[imports.packages]
"some_pure_python_pkg" = { policy = "try-native", max_depth = 1 }
"legacy_dynamic_pkg" = "fallback"
"known_pkg" = { policy = "plugin", plugin = "known-rust" }
```

支持的包策略是 `fallback`、`analyze`、`try-native`、`plugin`。从 0.1.1
起，插件还可以描述并直接*下沉*其覆盖的构造（plugin API 1.1 — 参见
[plugin lowering 规范](docs/specs/plugin-lowering.md)）；0.1.2 增加向后
兼容的 plugin API **1.2**（静态字面量/有序关键字元数据、结构化
`ClaimExpr` 树、leaves 模式下沉）。first-party 的
[rextio-numpy](https://github.com/rextio/rextio-numpy) 插件需单独安装
（core 无反向依赖）：已发布的 **PyPI 0.1.1** 扩展了 literal-axis/fusion，
并需要 **core >= 0.1.2**（初始认证 float64 1-D 表面为 0.1.0）。相关包已按
**严格发布顺序** rextio-lsp 0.1.1 → core 0.1.2 → rextio-numpy 0.1.1 发布
（见 [tooling contract](docs/specs/tooling-contract.md)）。Core **0.1.3** 于
2026-07-17 发布，附带 plugin API 1.3 与 tooling contract **2.1.0**（相对
core 0.1.2 发出的 **2.0.0** 形状为 additive；支持 dual-map 的 `2.x` 消费者
保持兼容）。
Core **0.1.4** 在 rextio-lsp 0.1.2 之后于 2026-07-18 发布，按严格的
consumer-first 顺序完成 Release Train B。它保留 plugin API 1.3，并发出
tooling contract **2.2.0**；在不改变既有 route/status/rejection 含义的
前提下，加入独立的 promotion assessment、可信 marker 意图及函数/名称范围。
Core **0.1.5** 于 2026-07-23 发布，使用 plugin API **1.4**、tooling
contract **2.24.0** 和 readiness policy **11**。Train C 的 host source-AOT、
可执行文件与严格的 artifact-evidence 功能仍属 Experimental/Alpha。
Core **0.1.6** 于 2026-07-26 发布，使用 plugin API **1.6** 和 tooling
contract **2.27.0**。它加入有限的插件比较表达式、Device Provider API 1
选择/preflight/构建接线，以及静态 device-domain lowering 授权；Core 本身
并不声称 CUDA framework 支持或加速器执行认证。
Core **0.1.7** 于 2026-07-27 发布，使用 plugin API **1.7** 和 tooling
contract **2.28.0**，加入可选的 plugin function-scope RAII 守卫。
一般依赖下沉不随发行版捆绑；`try-native` 是显式的规划策略，没有安全的
direct 下沉时仍会 fallback。

## Native 选择

默认使用自动 native 发现:

```toml
[policy]
native_marker = "auto"
```

在该模式下，Rextio 可能把类型可解析且符合受支持 direct Rust subset 的模块
级函数视为 native 候选。

也可以要求显式标记:

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

为未来的多目标支持，标记可以固定目标:

```python
@rextio.native(target="rust")
def score(x: float) -> float:
    return x * 2.0
```

函数必须留在 Python fallback 时用 `@rextio.exempt`:

```python
@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1
```

exempt 函数绝不会进入生成的 Rust。如果一个 native 候选调用了 exempt 或
仅 fallback 的函数，该候选也会回落。

## 安全模型

Rextio 让 native 编译保持保守:

- direct Rust native 函数只能调用被接受的 native 函数、受支持的 builtin
  和受支持的标准库函数。
- 调用仅 fallback 代码的 native 函数会被拒绝 — 除非调用者被显式标记且
  callee 的签名从头到尾都是不可变标量（`int`/`float`/`bool`/`str`/`None`）:
  该调用将成为 in-process 标量 boundary call（`RXT075`）。callee 继续在
  解释器中运行，因此值与异常都 CPython-精确，monkeypatch 也被尊重；标量
  按值跨越边界，因此实参的 identity（`is`）不被保留（`None`/`bool`
  单例除外）；容器绝不跨越边界，native 循环（包括推导式主体）内的
  boundary call 会让调用者留在 fallback（`RXT076`）。
- Python fallback 代码可以调用 native 函数。
- 反复调用 native 函数的 Python 循环会产生 boundary 警告。
- 生成的 wrapper 可以在边界穿越反复发生后把该函数切回 fallback —
  Python→native 的 wrapper 进入与 native 标量 boundary call 计入同一个
  按函数阈值。
- Python/Rust 的所有权差异被显式处理。持有值的只读复用在需要时用 Rust
  clone 下沉，可变集合的别名修改则留在 Python fallback。

boundary fallback 由以下控制:

```text
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
REXTIO_NATIVE_MODE=auto|fallback|native
```

## direct Rust subset

Rextio 0.1.7 刻意支持一个小的 subset。这个 subset 就是以 native
Rust 运行的代码。

支持的类型:

- `int`、`float`、`bool`、`str`、`bytes`、`None`
- 元素类型受支持的 `list[T]`（含 `list[list[T]]`）
- 固定 `tuple[...]`
- 键为受支持标量键类型的固定 `dict[K, V]`
- 受限的 `set[int]`、`set[bool]`、`set[str]`（`set[float]` 留在 Python
  fallback: NaN-identity 去重没有忠实的 Rust 下沉；native 代码也从不*迭代*
  set — 哈希顺序与 CPython 不同）
- `Optional[T]`、`T | None`

支持的语法:

- 局部赋值与带类型注解的局部变量
- 算术、布尔运算、比较、`if`、`while`
- `for x in xs`
- 受支持的循环/推导式形式中的 `range(...)`、`enumerate(xs)`、`zip(xs, ys)`
- `break`、`continue`、`return`
- 受限的实验性 `try`/`except`/`finally` 子集（仅限内置异常处理器；
  参见[稳定性层级](docs/stability.md)）
- 受支持形式的 list/dict/set 推导式
- 受限的 `list.append`、dict 读写、索引
- 调用被接受的 native 辅助函数

builtin 与标准库下沉（受限形式）:

- `len`、`abs`、`min`、`max`、`sum`、`all`、`any`、`sorted`、`reversed`
- 部分 `math` 函数与常量
- 部分 `str`、`bytes`、`list` 方法
- `print`、`logging.debug/info/warning/error`
- `datetime`、`time`、`hashlib.sha256`、`base64.b64encode`
  （`statistics.mean`/`fmean`、`json.dumps`/`json.loads`、
  `base64.b64decode` 没有忠实的 direct-native 等价物: 显式标记的函数走
  RXT080 runtime shim，自动发现的函数留在 Python fallback）

不支持或含糊的代码留在 fallback 上，或在受支持时通过 Python runtime
semantics shim 暴露。详细边界见
[0.1.0 不支持的特性](docs/unsupported-features.md)。

## 编写适合 Rextio 的 Python

native 提升与 boundary 行为直接由代码形状决定。要充分发挥 Rextio:

- 热点函数从头到尾加注解 - 参数与返回类型都用受支持的 scalar/list 类型。
  类型无法解析的函数会留在 fallback。
- 热点路径保持在受支持的 subset 内，并尽早运行 `rextio check`;
  每条拒绝都会指明导致它的构造。
- 把循环移进 native: 调用 native 函数的 Python 循环每次迭代都跨越边界
  （boundary 警告），而内部循环的 native 函数每次调用只跨越一次。
- 让 native 调用图保持 native: native-to-native 调用留在 Rust 内。调用
  仅 fallback 的 helper 要么使调用者被拒绝，要么变成每次调用发生、并计入
  降级 threshold 的 scalar boundary call。
- 让 boundary call 远离循环和推导式主体（`RXT076`）; 把它提升到循环外，
  或在 callee 符合 subset 时标记 `@rextio.native`。
- 跨边界只传不可变标量; 容器绝不跨越边界。
- 必须留在 Python 的函数用 `@rextio.exempt` 标记，混合函数应拆分，
  让带类型的热点核心成为独立函数。
- 用 `rextio bench` 测量: 非常小的函数可能输给调用开销，
  所以每次 native 调用要聚合足够的工作量。

## Python runtime semantics shim

一些 Python 特性无法安全翻译为带类型的 Rust 语句。对显式标记的 native
代码，Rextio 可能生成一个 PyO3 shim，转而调用生成的 Python fallback 实现。

该兼容路径可以保留 class/对象行为、实例方法、异常、上下文管理器、
`async`/`await`、生成器、动态属性访问等特性。报告为 `RXT080`。

该路径保留行为，不应被当作 Rust 加速路径。

## 实验性 scalar helper 内嵌（embedding）

Rextio 可以选择性地把一组非常窄的未标记标量 helper 作为内部 native 函数
内嵌 — 与其他一切一样提前（ahead-of-time）编译。默认关闭。

启用后，合格的未标记 helper（标量参数与返回值、单个算术 return 表达式）
会被编译成生成 native artifact 中的普通内部函数 — 可被 native 代码调用，
不导出给 Python。内嵌的 helper 走常规 checked 路径下沉，因此整数溢出抛
OverflowError、除零抛 ZeroDivisionError，与任何 native 函数完全一致。在
Rust 可执行文件 backend 中，内嵌 helper 直接编译进二进制，而不是每次调用
委托给 CPython dispatcher。

```toml
[embedding]
enabled = true
```

等价的命令行与环境变量控制:

```text
rextio build . --embed-helpers
REXTIO_EMBED_HELPERS=true rextio build .
```

内嵌不会给生成的 Cargo 项目增加 crate 依赖。内嵌关闭时，合格的 helper
调用仍通过运行时标量 boundary call 工作 — 内嵌是移除每次调用解释器往返
的快速路径。与 boundary call 不同，内嵌的 helper 是构建时编译进 native
产物的副本，因此对 helper 的运行时替换（monkeypatch）对 native 调用方
不可见。

## Numba 外部加速器（experimental）

Numba 支持在 0.1.0 中是 EXPERIMENTAL 的: 识别、报告和 Nuitka 共存
行为在第一个 non-alpha 版本之前可能改变。Rextio 把 Numba 装饰器
（`numba.jit`、`numba.njit`、`numba.vectorize`、`numba.guvectorize`）识别
为 Python fallback 代码的外部加速器（experimental）— 与 Nuitka 打包
backend 相同的"外部受支持工具"模式。被装饰的函数干净地留在 Python
fallback（排除出自动发现与 helper 内嵌），在报告中标注
`external_accelerator: numba`，`rextio check` 会列出这些函数。识别通过
模块的 import 解析（attribute、from-import、别名、调用形式；含
`numba.cuda.jit`）。`rextio check` 的报告标签只覆盖直线式 import，而
Nuitka 构建期扫描更宽（star import、可选依赖守卫、函数内的延迟 import），
因此即使函数没有标签，构建也能正确地把模块保持为 plain。

契约边界很重要: `@rextio.native` 函数拥有 Rextio 验证过的 CPython-精确
语义，而 `@numba.*` 函数按 **Numba 的**语义运行（例如 nopython 模式整数
运算溢出时回绕而不是抛异常）— 这个取舍是用户的显式 opt-in，在 Rextio
native 契约之外，与 `@rextio.exempt` 一样。`@rextio.native` 与 numba
装饰器的组合会被明确拒绝。

兼容性: wheel 与 zipapp 部署在把 numba 安装为项目依赖后可用；Rust 可执行
文件的 source 模式 hybrid runtime 可用（dispatcher 运行真实 CPython）。
`--fallback=nuitka` backend 自动共存: 使用已识别外部加速器的模块保持为
plain Python（`.py` 继续被 import），树的其余部分用 Nuitka 编译，构建报告
列出它们。生成的 wheel 只把 Nuitka 编译模块作为扩展装载 — 被遮蔽的 `.py`
源被排除（既是死重又会暴露源码）— 并带平台标签；加速模块保留其 `.py`。
Nuitka *可执行文件*（`--executable-backend=nuitka`）与
`--hybrid-runtime=nuitka` dispatcher 无法服务加速函数（编译后的函数不暴露
字节码，加速器也不被捆绑）— 这些构建会带指引提前失败，而不是死在第一次
调用。带类型的标量代码优先用 `@rextio.native`，NumPy/数组内核用 Numba，
并注意非常小的函数在任何加速器下都会输给调用边界成本。

first-party 的 [rextio-numpy](https://github.com/rextio/rextio-numpy) 插件
将覆盖的 NumPy 转换为 AOT 编译的 native Rust。**已发布 rextio-numpy 0.1.1**
把初始 0.1.0 的认证 float64 1-D 表面扩展到 F64/F32/I64 rank-1/rank-2
broadcasting、literal-axis reduction 与 2–8 操作逐元素 fusion。它使用 core
plugin API 1.2（**core >= 0.1.2**）；rank-2 `dot`/matmul 仍走 fallback。
dual-map **rextio-lsp 0.1.1** → **core 0.1.2** → **rextio-numpy 0.1.1**
的必要发布顺序已于 2026-07-14 完成。因此 NumPy 代码有两条路径: 对已覆盖表面用 Rextio
插件做 AOT 编译，或在 Python fallback 内用 Numba 做 JIT。当两者都适用时，
显式的 `@numba.*` 装饰器优先，analyzer 会输出信息性的 RXT091 注记; 关于
路径取舍的更完整指南将随插件表面的成长而逐步明确。

## 示例

```text
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math

rextio check examples/boundary_demo
rextio build examples/fallback_demo --entrypoint=fallback_demo.run_demo:main
```

示例项目:

- `examples/pure_math`: 带类型数学热路径的 direct Rust 下沉。
- `examples/fallback_demo`: native 关闭或缺失时的 fallback 行为。
- `examples/boundary_demo`: native→fallback boundary 的拒绝与警告。
- `examples/app_shell`: 应用外壳保持 Python，只有评分热路径可以 native。
- `examples/wheel_package`: 默认 hybrid wheel，安装到全新环境并以不变的
  import 使用。
- `examples/nuitka_fallback`: 含 Nuitka 编译 fallback 的 hybrid wheel。
- `examples/numba_accelerator`: Rextio native 与 Numba-JIT NumPy 内核并用。
- `examples/nuitka_numba`: 一次构建中同时有 Rust native、Nuitka fallback
  与保持 plain Python 的 Numba 模块。
- `examples/zipapp_app`: 单文件 `.pyz` 可执行文件。
- `examples/nuitka_executable`: onefile Nuitka 可执行文件。
- `examples/rust_executable`: 独立 native Rust 二进制。
- `examples/rust_crate`: 供 Rust 调用方使用的 Cargo 库 crate。
- `examples/embedding_helpers`: scalar boundary call 与内嵌 helper 的对比。

## 开发与验证

运行测试套件:

```text
python -m pytest
```

真实的 Cargo、Nuitka 和可执行文件测试在对应 toolchain 不可用时会跳过。

完整的开发环境与质量门禁见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 后续计划

这是计划而非承诺，优先级可能随 alpha 反馈调整:

1. 稳定化优先: 在扩大表面之前，先基于真实使用夯实 0.1.0 的表面。
2. 面向 agentic coding 的 skill/plugin，教编码代理如何编写适合 Rextio
   的 Python。
3. VS Code 扩展，在编辑时直接显示当前代码是否符合受支持的 native subset。
4. Rextio 插件 - 插件定义把使用特定包的 Python 代码转换为 Rust 加
   fallback 代码的规则。我们计划从 NumPy 开始，为常用数值计算与 AI 包
   自行开发第一方插件; 插件表面稳定后，任何人都可以开发并发布 Rextio
   插件。
5. 长期来看，可能增加 Rust 之外的 native target backend，但目前没有
   具体计划。

## 项目信息

- [特性稳定性](docs/stability.md) — 0.1.0 中哪些是 stable、哪些是 experimental。
- [版本策略](docs/versioning.md) — 带 pre-1.0 注意事项的 SemVer。
- [不支持的特性](docs/unsupported-features.md) — 0.1.0 subset 的边界。
- [安全模型](SECURITY.md) — 信任边界与漏洞报告方式。
- [贡献指南](CONTRIBUTING.md) — 环境、门禁与惯例。
- [变更日志](CHANGELOG.md)。
- 开发者: 宋始永 <rextio.co@gmail.com> — X (Twitter): [@RextioDev](https://x.com/RextioDev)。
