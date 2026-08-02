# Rextio

<p align="center">
  <img src="./assets/readme/rextio-icon.png" width="112" alt="Rextio 图标">
</p>

<p align="center">
  <strong>将符合条件的带类型 Python 函数预先编译为 Rust/PyO3。<br>其余代码继续使用安全的 Python 回退路径。</strong>
</p>

<p align="center">
  <a href="https://github.com/rextio/rextio/blob/main/README.md">English</a> · <a href="https://github.com/rextio/rextio/blob/main/README.ko.md">한국어</a> ·
  <a href="https://github.com/rextio/rextio/blob/main/README.zh-hans.md">简体中文</a> · <a href="https://github.com/rextio/rextio/blob/main/README.zh-hant.md">繁體中文</a> ·
  <a href="https://github.com/rextio/rextio/blob/main/README.ja.md">日本語</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/rextio/"><img alt="PyPI 版本" src="https://img.shields.io/pypi/v/rextio"></a>
  <a href="https://pypi.org/project/rextio/"><img alt="支持的 Python 版本" src="https://img.shields.io/pypi/pyversions/rextio"></a>
  <a href="https://github.com/rextio/rextio/blob/main/LICENSE"><img alt="MIT 许可证" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

Rextio 是面向 Python 开发者的 **Alpha 本地构建工具**：无需重写应用，即可让选定的带类型热点路径以原生 Rust 运行。保守的分析器只接受能够按文档语义安全降低的代码。无法支持或存在歧义的代码会留在生成的 Python 回退包装器上；原生执行被禁用，或在默认 `auto` 模式下原生代码不可用时，相同导入路径仍通过这些包装器工作。

```bash
python -m pip install rextio
rextio check .
```

这是最短且有用的第一步：在构建前先查看哪些函数获准进入原生路径。

Core **0.1.8** 已于 2026-07-27 发布，包含 plugin API **1.7** 和 tooling contract **3.0.0**。版本历史见[更新日志](CHANGELOG.md)。

> **Tooling 迁移：**contract 3.0 将 milestone 派生的 artifact identity 替换为语义化的 `artifact-*` 名称。精确的 0.1.7 identity 仅保留为 legacy 读取/验证输入；仅支持 2.x 的 consumer 在 major 3 上必须降级。

## 证据：已测量的 CPU 工作负载

在 **Mac16,11 / Apple M4 Pro**、**2026-07-26**、CPython **3.11.9** 上三次运行的中位数：

| 工作负载 | source/native 中位加速比 |
| --- | ---: |
| Core hybrid | 57.729× |
| NumPy mixed fusion | 2.523× |
| NetworkX Dijkstra | 3.679× |
| pandas `Series.map` | 66.143× |
| PyTorch CPU deep MLP | 1.017× |
| TensorFlow CPU eager chain | 1.040× |

这些是**特定工作负载的观测结果**，不是整个库的性能承诺。接近 1× 表示大致持平，保留的部分诊断用例慢于 Python。未测量 CUDA。可审计的 [rextio-benchmark](https://github.com/rextio/rextio-benchmark) 仓库包含精确修订、source/fallback/native 通道、原始证据、稳定性政策、诊断以及慢速/持平结果。

## 工作原理

```text
typed Python
  → 解析类型并检查受支持子集
  → 拒绝不安全的 native/fallback 调用图
  → 将获准函数降低为 Rust + PyO3
  → 生成兼容原导入路径的 Python 包装器
  → 在保留 fallback 的前提下构建原生产物
```

正确性基线始终是 Python。Rextio 不是 Python 替代品、通用 Python-to-Rust 转换器、JIT，也不是整项目迁移工具。

## 第一次构建

默认自动模式下装饰器是可选的，直接从普通的带类型 Python 开始：

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

Rextio 可以降低 `sum_squares`，并让 `format_result` 继续回退。调用方保持普通 Python 导入：

```python
from myapp.math_ops import format_result, sum_squares

assert sum_squares([1, 2, 3]) == 14
assert format_result(14) == "score=14"
```

随时强制已构建包使用回退：

```bash
REXTIO_NATIVE_MODE=fallback python -m myapp
```

常用命令包括 `rextio init`、`rextio capabilities`、`rextio check`、`rextio generate`、`rextio build`、`rextio bench` 和 `rextio clean`。

## 要求

| 组件 | 支持边界 |
| --- | --- |
| CPython | `>=3.11`；已验证 3.11–3.14。生成扩展固定使用支持至 CPython 3.14 的 PyO3 0.29。更新解释器未经验证，wheel 按构建解释器的次版本标记。 |
| Rust | MSRV 1.83；测试近期 stable。生成 crate 使用 Rust 2021。通过 [rustup](https://rustup.rs) 安装。 |
| Nuitka | 可选，`>=2.0`；仅所选 Nuitka 回退、可执行文件或 dispatcher 路径需要。这些路径均为 Experimental。 |
| Numba | 可选且为 Experimental；各解释器最低版本为 0.57（3.11）、0.59（3.12）、0.61（3.13）、0.63（3.14）。它仍是你的项目依赖。 |

工具位置和版本可通过 `[toolchain]`、环境变量或 CLI 选项固定；见 [REXTIO.md](./REXTIO.md#toolchain-selection-and-version-pins)。

## 选择与回退安全

默认启用自动发现：

```toml
[policy]
native_marker = "auto"
```

使用 `native_marker = "decorator"` 强制要求 `@rextio.native`，或用 `@rextio.exempt` 将函数固定在 Python。当前唯一实现的原生目标是 Rust。

```python
import rextio

@rextio.native
def score(x: float) -> float:
    return x * 2.0

@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1
```

影响应用设计的安全规则：

- 直接原生函数只能调用获准的原生函数，以及受支持的内置/标准库操作。
- 调用仅回退代码会拒绝原生调用者，除非显式标记的调用者符合不可变标量边界路径。容器绝不穿越该边界，循环或推导式内的边界调用会留在回退路径。
- Python 循环调用原生函数时会产生静态跨界诊断 `RXT073`。只有符合条件的直接原生函数才会把包装器入口和标量边界入口计入每函数运行时回退阈值；plugin 路由的函数不参与计数。
- 在 `auto` 模式下，原生导入不可用或超过阈值时使用 Python 回退，分析器拒绝的函数也会留在回退路径。`fallback` 模式显式禁用原生执行。`native` 模式要求已提升的原生代码；其原生导入不可用时会抛出异常。`REXTIO_DEBUG_NATIVE=1` 会把原生加载警告改为 traceback，便于诊断。
- `native-shim`/`RXT080` 通过 PyO3 调用 Python 回退以保持动态 Python 语义。它是兼容路径，**不是 Rust 加速路径**。
- 若 Rust 所有权会改变行为，可变集合别名会留在 Python。Rextio 不会因为“看起来能翻译”就生成原生候选。

运行时控制：

```text
REXTIO_NATIVE_MODE=auto|fallback|native
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
REXTIO_DEBUG_NATIVE=1
```

## 支持的直接 Rust 代码形态

刻意保持狭窄的直接路径覆盖以下受支持组合：

- 标量 `int`、`float`、`bool`、`str`、`bytes`、`None`；
- 列表（含嵌套）、固定元组、使用标量键的固定字典、有限的 `set[int|bool|str]`，以及 `Optional[T]` / `T | None`；
- 带类型局部变量、算术、比较、`if`、`while`、受支持的 `for`/`range`/`enumerate`/`zip`、推导式和获准原生 helper；
- 有限的内置函数、`math`、字符串/bytes/list 方法、日志/输出、`datetime`、`time`、`hashlib.sha256`、`base64.b64encode`。

重要排除项同样明确：`set[float]` 和 set 迭代无法保持 CPython 的 NaN identity/hash 顺序；`statistics.mean/fmean`、`json.dumps/loads`、`base64.b64decode` 没有直接原生路径；文件/网络/数据库/ORM 操作和动态对象行为留在回退或显式标记的兼容 shim。完整的版本化边界见[不支持的功能](docs/unsupported-features.md)和[功能稳定性](docs/stability.md)。

## 构建输出

| 请求 | 结果与边界 |
| --- | --- |
| 默认构建 | 兼容导入的包目录，以及可选的包含原生代码与 Python 回退的 wheel。 |
| `--entrypoint=…` | Zipapp；目标机器仍需兼容 Python，且不会从 zipapp 内导入原生扩展。 |
| `--executable-backend=nuitka` | Experimental standalone/onefile 可执行文件；需要 Nuitka。不声称能任意跨平台打包第三方依赖。 |
| `--executable-backend=rust` | 原生 Rust entrypoint。闭合调用图可独立运行；`python-subprocess` 只委托受限不可变标量调用且需要 CPython，`nuitka-sidecar` 需要 Nuitka。运行时 shim 和容器跨界会被拒绝。为可移植进程状态，建议退出码 `0..255`。 |
| `--rust-importable` | Experimental Cargo 路径依赖 crate，只包含直接 Rust 函数。回退、shim、标量边界函数仍面向 Python。 |

`rextio build` 与 `generate` 每次都会重新分析和生成；0.1.x 没有增量构建缓存。subprocess hybrid runtime 将源码复制到 `<binary>.runtime/`，因此委托代码看到的是副本的 `__file__`；依赖原文件相对路径寻找数据的代码需要其他方案。

## 插件、设备与外部源码

插件是独立的 Python 发行包，必须在项目配置中显式启用。没有活动插件的包默认保守处理；`try-native` 是 Experimental 规划政策，不是通用依赖转换承诺。

Device Provider API 1 的选择同样是显式且 Experimental 的。仅配置 provider 不会让 CPU-only Torch/TensorFlow 路径获得 CUDA 能力。混合或冲突设备域、缺失 provider、不支持的 GPU ordinal、错误 capability 都会 fail closed。Provider preflight 报告 `support_claim: false`；Core 不声称经过认证的 CUDA 执行。

外部 pure-Python 源码清单是针对恰好一个已固定、已验证的 depth-1 `py3-none-any` 发行包的非构建预览。它不导入包，不把词法候选连接到项目调用，也不降低、复制、再分发或授权构建。缺失/无效 SourceLock 会阻断；仅有验证通过的 lock 仍不授予构建或分发权。

独立的 `strict-evidence` **Alpha/Experimental** 配置严格限定为 macOS arm64 或 Linux x86_64 上的 CPython 3.11 host-extension 构建、一个 SourceLock 授权依赖、标量叶调用、所有者固定的离线输入、两次隔离构建以及外部 Ed25519 签名。它排除插件、可执行文件、Rust crate、embedding、原生顶层初始化、Windows、广泛包降低和通用再分发。其 sandbox/support lock 仅保护所有者控制进程中的证据完整性；不代表安全启动、抵御恶意同 UID 进程或已攻陷 OS、通用 hermeticity、registry 身份验证或跨平台认证。

> **法律边界：**翻译或再分发依赖源码可能产生许可证和衍生作品义务，尤其是 GNU/copyleft 条款。Rextio 的清单和 SourceLock 检查不是法律建议或法律批准。

依赖这些高级功能前，请阅读 [host source-AOT 与原生可执行文件](docs/source-aot-and-executables.md)、[Device Provider API 1](docs/specs/device-provider.md) 和 [tooling contract](docs/specs/tooling-contract.md)。

## Numba 与 Nuitka

识别到的 `@numba.*` 装饰器表示显式选择在回退路径使用 **Numba 的**语义，而非 Rextio 的 CPython 等价原生契约。不要与 `@rextio.native` 组合。安装 Numba 后，wheel/zipapp 与 source-hybrid 路径可工作；Nuitka 可执行文件和 Nuitka hybrid dispatcher 会提前拒绝加速函数，因为编译函数不暴露 bytecode 且 accelerator 未被打包。任何 accelerator 下，小函数都可能因边界开销变慢。

## 示例与项目信息

```bash
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math
```

在 [`examples/`](examples/) 中可查看直接数学运算、回退与边界行为、wheel、zipapp、Nuitka、Numba、Rust 可执行文件/crate 和嵌入 helper。Embedding 为 Experimental，默认关闭，仅 AOT、仅标量，并会改变原生调用者看到 monkeypatch 的方式；它不是运行时 JIT。

- [安全模型](SECURITY.md)
- [贡献指南](CONTRIBUTING.md)
- [版本策略](docs/versioning.md)
- [更新日志](CHANGELOG.md)
- [许可证](LICENSE) — MIT

作者：Steve Si-young Song · [@RextioDev](https://x.com/RextioDev)
