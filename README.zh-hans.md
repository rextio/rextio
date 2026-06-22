# Rextio

[English](README.md) | [한국어](README.ko.md) | [繁體中文](README.zh-hant.md) | [日本語](README.ja.md)

Rextio 0.1.0 是 alpha 阶段的混合构建工具。它会把符合条件、可静态解析类型的 Python
函数编译为 Rust 原生模块，并把其余代码打包为安全的 Python fallback。

0.1.0 alpha 的范围刻意保持很窄。它是一个面向可静态解析类型的 Python 热路径项目的本地 CLI
和构建工具 MVP。Rextio 默认自动发现类型来自 annotation、同名 `.pyi` stub 或保守本地
上下文推断的符合条件函数；项目也可以选择退出自动发现，并要求使用 `@rextio.native`
标记。Rextio 不声称提供完整 Python 兼容性、内置第三方包覆盖、框架迁移、JIT 行为，
或完整的运行时边界成本优化器。

0.1.0 alpha 包含保守的静态边界检查。它会拒绝调用 fallback-only 代码的 native 函数，
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
rextio build path/to/project --fallback=cpython --entrypoint=myapp.cli:main
rextio bench myapp.scoring.compute_score --project-root path/to/project
rextio clean path/to/project
```

## 0.1.0 alpha 范围

0.1.0 alpha 支持一个面向模块级函数的小型静态类型 subset。当 Rextio 能从 source
annotation、同名 `.pyi` stub 或保守本地上下文推断解析所有参数和返回类型时，符合条件的
函数默认会成为 native 候选。不受支持的语法、未解析的类型、动态特性、不安全的
native-to-fallback 调用，以及无法解析的外部调用，都会从 native 编译中被拒绝，并在可能时
保留为 Python fallback。

有关支持的 subset、边界限制、诊断和非目标，请参阅
[0.1.0 alpha 不支持的功能](docs/unsupported-features.md)。

当前 native 候选支持 scalar、`list[...]` 与 `list[list[T]]`、fixed `tuple[...]`、有限的
固定 `dict[K, V]`、有限的 `set[int|float|bool|str]`，以及 `Optional[T]` / `T | None` 类型。支持的语法包括算术、
比较、`if`、`while`、`for x in xs`、`range(...)` 循环、
`for i, x in enumerate(xs)`、`for x, y in zip(xs, ys)`、`break`、`continue`、
augmented assignment、带类型的局部 annotation、简单索引、list literal、fixed tuple
literal、有限的 dict read/write、有限的 list/dict/set comprehension、comprehension 内的
assignment expression，以及支持的 list item 类型上的 `list.append(...)`。
Builtin 支持有意限制为 `len`、`abs`、两个参数的 `min`/`max`，以及
`sum(list[int|float])`。支持的 `math` subset 是 `math.sqrt`、`math.sin`、`math.cos`
和 `math.floor`。

这些扩展形式仍保持保守：空 list literal 需要受支持的 `list[...]` 局部 annotation，
并且 `range(start, stop, step)` 目前要求 `step` 是正的 int literal。`enumerate` 和
`zip` 仅支持作为 list 变量上的 batch loop 或 comprehension iterable。Native subset
现在支持有限的 list/dict/set comprehension、comprehension 内的 assignment expression、
`list[list[T]]`、固定 `dict[K, V]`，以及 `set[int|float|bool|str]` comprehension。
dataclass 仍不在 direct Rust lowering 范围内。

对于无法安全 lowering 为 direct Rust 的 Python semantics，Rextio 可以生成 Python runtime
semantics native shim。该 shim 是调用生成的 Python fallback 实现的 Rust/PyO3 函数，因此可以
保留 class/object 行为、标记为 `@rextio.native` 的普通 instance method、exception handling、
context manager、`async`/`await`、generator/`yield`，以及 `getattr` 或 `obj.attr` 等 dynamic
attribute access。该路径会报告 `RXT080`，它是 compatibility 路径，不是 Rust speedup 路径。

类型推断刻意保持窄范围。Rextio 可以从常量、算术、比较、`if` test、loop、indexing、
comprehension 和受支持 builtin 推断简单 scalar 与 collection signature。缺少 source
annotation 时，会优先参考同名 `.pyi` 文件的 signature。类型仍然模糊时，该函数保留在
Python fallback。

模块顶层逻辑默认保留在 Python fallback。设置 `[policy] native_top_level = true` 或
`--native-top-level` 后，Rextio 会尝试生成受限的 native initializer。支持范围包括
assignment、annotated assignment、augmented assignment、受支持 expression，以及只更新已
提前赋值模块变量的 `if`/`while` block。导出的模块变量必须共享一个受支持 value 类型；
native 被禁用或不可用时会使用原始 fallback 模块。

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

## 配置来源

构建和分析设置按以下优先级解析：

```text
CLI parameter > environment variable > rextio.toml > built-in default
```

`project_root`、bench target、`init --force`、`check --json` 等决定命令执行方式或输出
形式的参数仍然只属于 command line。项目行为设置可以从以下任一来源配置：

| `rextio.toml` key | CLI parameter | Environment variable |
| --- | --- | --- |
| `[build] native_backend` | `--native-backend` / `--target-language` | `REXTIO_TARGET_LANGUAGE` / `REXTIO_NATIVE_BACKEND` |
| `[build] fallback_backend` | `--fallback` | `REXTIO_FALLBACK_BACKEND` |
| `[build] fallback_threshold` | `--fallback-threshold` | `REXTIO_BOUNDARY_FALLBACK_THRESHOLD` |
| `[rust] binding` | `--rust-binding` | `REXTIO_RUST_BINDING` |
| `[rust] build_tool` | `--rust-build-tool` | `REXTIO_RUST_BUILD_TOOL` |
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

0.1.0 alpha 仍会保守地验证取值。当前已实现的 native target 只有 Rust。
`native_backend = "mojo"` 和 `native_backend = "julia"` 会作为未来的 target-language
选择被接受，因此可以配置 versioned mapper 和 build-option metadata；但在对应 backend
实现前，source generation 会明确失败。

Mapper plugin 可从 local metadata folder 或 public Git repository 加载。Local folder
通过 `[mappers] paths` 和可选的 `[mappers] enabled` 配置；每个 folder 必须包含
`rextio-mapper.toml` 或 `mapper.toml`。`[mappers] repository`、`--mapper-repository`
或 `REXTIO_MAPPER_REPOSITORY` 可设置为 public Git URL；Rextio 会将其 clone 到
`.rextio/mappers/repositories/` 并递归发现 mapper manifest。

## 生成产物

Rextio 会把生成文件写入 `.rextio/` 下，不会原地修改用户源文件。

```text
.rextio/
  build/
    python/
      rextio/
        runtime/
  generated/
    <target-language>/
    python/
  reports/
    check.json
    build.json
    bench.json
dist/
  <project>-0.1.0-<tag>.whl
  <executable-name>.pyz
  <executable-name>
  <executable-name>.dist/
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

`rextio build --entrypoint=module:function` 还会在 `dist/` 下生成 zipapp 可执行
artifact。可以使用 `--executable-name=name` 控制输出文件名；否则 Rextio 会从
entrypoint 模块派生名称。结果是 Python zipapp（`.pyz`），因此目标机器仍需要兼容的
Python 解释器。Native extension 模块不能直接从 zipapp 内部 import，所以生成的
wrapper 会保留 fallback 安全性，并在 native 模块不可用时使用 Python fallback。

安装 Nuitka 后，也可以生成 Nuitka executable artifact：

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

standalone 模式会在 `dist/` 下写入 Nuitka `.dist` 应用目录。onefile 模式会在 `dist/`
下写入单个 Nuitka 可执行文件。Nuitka executable 打包仍依赖本地 toolchain。如果
Nuitka 不可用，Rextio 会报告明确的 `RXT060` 错误并建议使用 zipapp backend。

## 策略配置

0.1.0 alpha 会保守地验证 `rextio.toml`，并拒绝未知 section、未知 key、不支持的 backend，
以及超出 0.1.0 alpha 范围的策略值。

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

显式 marker 也可以固定目标 native 语言。例如
`@rextio.native(target="rust")` 只会在 active `--target-language` /
`[build] native_backend` 为 Rust 时生效。`target="mojo"` 和 `target="julia"` 会作为
未来 backend 的 planning 值保留，但 0.1.0 alpha 只实现 Rust source generation。

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
`rextio build --fallback-threshold=N`、`REXTIO_BOUNDARY_FALLBACK_THRESHOLD`、
`[build] fallback_threshold = N` 都可以为该 artifact 设置生成代码默认值。运行时
`REXTIO_BOUNDARY_FALLBACK_THRESHOLD` 会覆盖这个 embed 的默认值。将阈值设为 `0`，或设置
`REXTIO_DISABLE_BOUNDARY_FALLBACK=1`，可以禁用此自动 fallback。`REXTIO_NATIVE_MODE=native`
会绕过该阈值。

使用 `.rextioignore` 可以让 Rextio 分析忽略生成文件或无关的 Python 文件。

## 边界诊断

0.1.0 alpha 的边界检查是静态且保守的：

- `RXT070`：native 函数调用了 fallback-only Python 代码。
- `RXT072`：native 函数依赖被拒绝的 native 函数。
- `RXT073`：fallback Python 在循环中调用 native 函数。
- `RXT080`：native 函数使用 Python runtime semantics shim。

`RXT070` 和 `RXT072` 会拒绝 native 候选。`RXT073` 是警告；该函数仍然符合条件，并且
一开始可以使用 native，但当重复的运行时 crossing 超过配置阈值后，生成的 wrapper 会
fallback 到 CPython/Nuitka fallback 路径。`RXT080` 是 warning；生成的 Rust 函数会调用
Python fallback 函数以保留 Python semantics。

## 示例

0.1.0 alpha 包含聚焦的本地示例：

- `examples/pure_math`：编译为 native hot path 的简单 typed 数学函数。
- `examples/fallback_demo`：当 native 缺失或设置 `REXTIO_DISABLE_NATIVE=1` 时，生成的 wrapper 使用 Python fallback。
- `examples/boundary_demo`：通过 `@rextio.exempt` 展示保守边界拒绝，以及 Python-loop 边界警告。

试一试：

```text
rextio check examples/pure_math
rextio generate examples/pure_math --fallback=cpython
rextio build examples/pure_math --fallback=cpython
rextio build examples/fallback_demo --entrypoint=fallback_demo.run_demo:main
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math
rextio check examples/boundary_demo
```
