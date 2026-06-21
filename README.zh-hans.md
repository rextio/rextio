# Rextio

[English](README.md) | [한국어](README.ko.md) | [繁體中文](README.zh-hant.md) | [日本語](README.ja.md)

Rextio 会把符合条件、带类型标注的 Python 函数编译为 Rust 原生模块，并把其余代码
打包为安全的 Python fallback。

Public 1 的范围刻意保持很窄。它是一个面向使用 typed Python 热路径项目的本地 CLI
和构建工具 MVP。Rextio 默认自动发现符合条件的 typed 函数；项目也可以选择退出自动
发现，并要求使用 `@rextio.native` 标记。Rextio 不声称提供完整 Python 兼容性、
完整 NumPy 支持、框架迁移、JIT 行为，或完整的运行时边界成本优化器。

Public 1 包含保守的静态边界检查。它会拒绝调用 fallback-only 代码的 native 函数，
当 Python 循环反复调用 native 函数时发出警告，并且在重复的 Python/Rust 边界
crossing 超过简单运行时阈值后，让生成的 wrapper 将该 native 函数切换到 fallback。

## 当前命令

```text
rextio init
rextio check
rextio generate
rextio build
rextio bench
rextio clean
```

初始实现重点覆盖项目初始化、native 候选发现、subset 诊断、静态边界诊断、运行时
禁用标志，以及确定性的 check report。

典型本地流程：

```text
python -m pip install -e .
rextio init --project-root path/to/project
rextio check path/to/project
rextio generate path/to/project --fallback=cpython
rextio build path/to/project --fallback=cpython
rextio bench myapp.scoring.compute_score --project-root path/to/project
rextio clean path/to/project
```

## Public 1 范围

Public 1 支持一个面向模块级函数的小型 typed Python subset。符合条件的 typed 函数
默认会成为 native 候选。不受支持的语法、动态特性、不安全的 native-to-fallback
调用，以及无法解析的外部调用，都会从 native 编译中被拒绝，并在可能时保留为 Python
fallback。

有关支持的 subset、边界限制、诊断和非目标，请参阅
[Public 1 不支持的功能](docs/unsupported-features.md)。

## 构建前提

Native 构建需要 Rust 和 Cargo。配置 `[rust] build_tool = "maturin"` 时，Rextio 也可以
使用 `maturin`；如果 maturin 不可用，Rextio 会在可能时 fallback 到 Cargo。

Nuitka fallback 打包是实验性的。如果在未安装 Nuitka 的情况下请求
`--fallback=nuitka`，Rextio 会报告明确的 `RXT060` 错误并建议使用
`--fallback=cpython`。安装 Nuitka 后，Rextio 会对生成的 Python fallback 模块运行
Nuitka，同时仍在构建产物中保留 CPython fallback 文件。

省略 `--fallback` 时，`rextio build` 会使用 `rextio.toml` 中的
`[build] fallback_backend`。传入 `--fallback=cpython` 或 `--fallback=nuitka` 会覆盖
本次运行的项目设置。

## 生成产物

Rextio 会把生成文件写入 `.rextio/` 下，不会原地修改用户源文件。

```text
.rextio/
  build/
    python/
      rextio/
        runtime/
  generated/
    rust/
    python/
  reports/
    check.json
    build.json
    bench.json
dist/
  <project>-0.1.0-<tag>.whl
```

`rextio check` 会写入 `.rextio/reports/check.json`。`rextio build` 会同时写入 check 和
build report。`rextio bench` 会写入 `.rextio/reports/bench.json`，其中包含结构化的
fallback/native 计时比较。

`rextio generate` 会运行分析，并在 `.rextio/generated/` 下写入生成的 Rust/PyO3 和
Python wrapper/fallback 源码；它不会调用 Cargo、maturin 或 Nuitka，也不会创建
`.rextio/build/` 或 `dist/`。

`rextio build` 成功后，还会在 `dist/` 下写入生成的 hybrid artifact wheel。纯
fallback wheel 使用 `py3-none-any`；包含生成 native extension 的 wheel 使用本地
CPython/platform tag。测试套件会把该 wheel 安装到全新环境中，并用
`REXTIO_DISABLE_NATIVE=1` 验证打包后的 fallback import 仍能工作。

## 策略配置

Public 1 会保守地验证 `rextio.toml`，并拒绝未知 section、未知 key、不支持的 backend，
以及超出 Public 1 范围的策略值。

边界警告默认启用。希望只保留严格安全错误、不要 Python-loop 边界警告的项目可以设置：

```toml
[policy]
boundary_warnings = false
```

自动 native discovery 默认启用：

```toml
[policy]
native_marker = "auto"
```

只希望使用显式 native 候选的项目可以禁用 auto discovery：

```toml
[policy]
native_marker = "decorator"
```

在 decorator-only 模式下，只有用 `@rextio.native` 标记的函数才会成为 native 候选。

即使启用了自动 native discovery，也可以使用 `@rextio.exempt` 让某个函数保留在
Python fallback。exempt 函数永远不会被 emit 到生成的 Rust；调用它们的 native 候选
会按正常的 native-to-fallback 边界规则被拒绝。

## Fallback 安全性

生成的 wrapper 会在可用且安全时使用 native 函数。当 native import 失败，或 native
执行被禁用时，它们会 fallback 到 Python。

```text
REXTIO_DISABLE_NATIVE=1
```

当项目需要明确的运行时行为时，可以设置 `REXTIO_NATIVE_MODE`：

```text
REXTIO_NATIVE_MODE=auto      # 默认：可用时使用 native，否则 fallback
REXTIO_NATIVE_MODE=fallback  # 强制 Python fallback
REXTIO_NATIVE_MODE=native    # 要求生成的 native 函数可用
```

重复的 Python-to-native wrapper 调用一开始是允许的。如果某个函数的 wrapper crossing
次数超过 `REXTIO_BOUNDARY_FALLBACK_THRESHOLD`，后续调用会使用该函数生成的 Python
fallback。默认阈值为 `1000`。`rextio generate --fallback-threshold=N` 和
`rextio build --fallback-threshold=N` 会为该 artifact embed 一个生成代码默认值。
运行时环境变量会覆盖这个 embed 的默认值。将阈值设为 `0`，或设置
`REXTIO_DISABLE_BOUNDARY_FALLBACK=1`，可以禁用此自动 fallback。
`REXTIO_NATIVE_MODE=native` 会绕过该阈值。

使用 `.rextioignore` 可以让 Rextio 分析忽略生成文件或无关的 Python 文件。

## 边界诊断

Public 1 的边界检查是静态且保守的：

- `RXT070`：native 函数调用了 fallback-only Python 代码。
- `RXT072`：native 函数依赖被拒绝的 native 函数。
- `RXT073`：fallback Python 在循环中调用 native 函数。

`RXT070` 和 `RXT072` 会拒绝 native 候选。`RXT073` 是警告；该函数仍然符合条件，并且
一开始可以使用 native，但当重复的运行时 crossing 超过配置阈值后，生成的 wrapper 会
fallback 到 CPython/Nuitka fallback 路径。

## 示例

Public 1 包含聚焦的本地示例：

- `examples/pure_math`：编译为 native hot path 的简单 typed 数学函数。
- `examples/fastapi_scoring`：FastAPI 保持 Python，`compute_score` 变为 Rust native。
- `examples/fallback_demo`：当 native 缺失或设置 `REXTIO_DISABLE_NATIVE=1` 时，生成的 wrapper 使用 Python fallback。
- `examples/boundary_demo`：通过 `@rextio.exempt` 展示保守边界拒绝，以及 Python-loop 边界警告。

试一试：

```text
rextio check examples/pure_math
rextio generate examples/pure_math --fallback=cpython
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math
rextio check examples/boundary_demo
```
