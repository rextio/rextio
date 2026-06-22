# Rextio

[English](README.md) | [한국어](README.ko.md) | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md)

Rextio 0.1.0 は alpha 段階のハイブリッドビルドツールです。条件を満たし型を静的に
解決できる Python 関数を Rust ネイティブモジュールへコンパイルし、それ以外を安全な
Python fallback としてパッケージします。

0.1.0 alpha は意図的に狭い範囲に絞っています。型を静的に解決できる Python の hot path を使う
プロジェクト向けのローカル CLI およびビルドツール MVP です。Rextio は annotation、
同名の `.pyi` stub、または保守的なローカル文脈推論から型を解決できる条件を満たす関数を
デフォルトで自動検出します。プロジェクト側では自動検出を無効にし、`@rextio.native`
マーカーを必須にすることもできます。Rextio は Python の完全互換、組み込みの
サードパーティパッケージ対応、フレームワーク移行、JIT 動作、または完全なランタイム
境界コスト最適化器を提供すると主張しません。

0.1.0 alpha には保守的な静的境界チェックが含まれます。fallback-only コードを呼び出す
native 関数は拒否され、Python ループが native 関数を繰り返し呼び出す場合は警告し、
繰り返しの Python/Rust 境界 crossing が単純なランタイムしきい値を超えると、生成された
wrapper がその native 関数を fallback に切り替えます。

## 現在のコマンド

```text
rextio init
rextio check
rextio generate
rextio build
rextio bench
rextio clean
```

初期実装は、プロジェクト初期化、native 候補の検出、subset 診断、静的境界診断、
ランタイム無効化フラグ、決定的な check report に重点を置いています。

典型的なローカルフロー:

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

## 0.1.0 alpha の範囲

0.1.0 alpha は、モジュールレベル関数向けの小さな静的型 subset をサポートします。
Rextio が source annotation、同名 `.pyi` stub、または保守的なローカル文脈推論から
すべての引数と戻り値の型を解決できる場合、条件を満たす関数はデフォルトで native 候補に
なります。未対応の構文、未解決の型、動的機能、安全でない native-to-fallback 呼び出し、
解決できない外部呼び出しは native コンパイルから拒否され、可能な場合は Python fallback
として維持されます。

対応 subset、境界の制限、診断、非目標については
[0.1.0 alpha で未対応の機能](docs/unsupported-features.md)を参照してください。

現在の native 候補は、`bytes` を含む scalar、`list[...]` と `list[list[T]]`、fixed `tuple[...]`、限定的な
固定 `dict[K, V]`、限定的な `set[int|float|bool|str]`、`Optional[T]` / `T | None` 型をサポートします。対応構文は
算術、比較、`if`、`while`、`for x in xs`、`range(...)` ループ、
`for i, x in enumerate(xs)`、`for x, y in zip(xs, ys)`、`break`、`continue`、
augmented assignment、型付きローカル annotation、単純な indexing、list literal、
fixed tuple literal、限定的な dict read/write、限定的な list/dict/set comprehension、
comprehension 内の assignment expression、対応 list item 型への
`list.append(...)` です。Builtin の対応は意図的に `len`、`abs`、2 引数の
`min`/`max`、`sum(list[int|float])`、`all`/`any`、限定的な `sorted`/`reversed`
に限定されています。
対応する `math` subset は三角関数、対数、rounding、finite/NaN チェック、
`math.pi`/`math.e` を含みます。よく使われる side-effect と標準ライブラリの
lowering は `print(...)`、`logging.debug/info/warning/error(...)`、
`logging.getLogger(...)` から代入された logger 変数、`datetime`/`time`、
`statistics`、選択された `str`/`bytes`/`list` method、限定的な `hashlib.sha256`、
`base64`、`json` pattern を含みます。

これらの拡張形式も保守的に扱われます。空の list literal には対応する `list[...]`
ローカル annotation が必要で、`range(start, stop, step)` は現時点では `step` が
正の int literal である必要があります。`enumerate` と `zip` は list 変数に対する
batch loop または comprehension iterable としてのみサポートされます。Native subset
は限定的な list/dict/set comprehension、comprehension 内の assignment expression、
`list[list[T]]`、固定 `dict[K, V]`、`set[int|float|bool|str]` comprehension に対応します。
dataclass はまだ direct Rust lowering の範囲外です。

Rextio は Python/Rust の ownership 差を保守的に扱います。`str`、`bytes`、`list`、
`dict`、`set` のような Rust の owned value を read-only で再利用する場合は、必要な位置に
明示的な clone を生成します。一方、`ys = xs` のように mutable collection alias を作成し、
いずれかの alias を mutate する Python pattern は、Rust ownership と Python reference
aliasing の意味が同じではないため Python fallback に残します。

Direct Rust に安全に lowering できない Python semantics については、Rextio は Python runtime
semantics native shim を生成できます。この shim は生成された Python fallback 実装を呼び出す
Rust/PyO3 関数なので、class/object の動作、`@rextio.native` が付いた通常の instance method、
exception handling、context manager、`async`/`await`、generator/`yield`、`getattr` や
`obj.attr` のような dynamic attribute access を保持できます。この経路では `RXT080` が報告され、
Rust speedup ではなく compatibility 経路として扱います。
この経路の automatic discovery は保守的であり、広い object-runtime コードは明示的に
`@rextio.native` を付けることを推奨します。

型推論は意図的に狭い範囲です。Rextio は定数、算術、比較、`if` test、loop、indexing、
comprehension、対応 builtin から単純な scalar と collection signature を推論できます。
source annotation がない場合は同名 `.pyi` ファイルの signature を優先して参照します。
型が曖昧なままなら、その関数は Python fallback に残ります。

モジュール top-level ロジックはデフォルトで Python fallback に残ります。
`[policy] native_top_level = true` または `--native-top-level` を設定すると、限定的な
native initializer の生成を試みます。対応範囲は assignment、annotated assignment、
augmented assignment、対応 expression、そして事前に代入済みのモジュール変数だけを更新する
`if`/`while` block です。export されるモジュール変数は 1 つの対応 value 型を共有する
必要があります。native が無効または利用不可の場合は元の fallback モジュールを使います。

## ビルド前提条件

Native ビルドには Rust と Cargo が必要です。`[rust] build_tool = "maturin"` が設定
されている場合、Rextio は `maturin` も使用できます。maturin が利用できない場合は、
可能であれば Cargo に fallback します。

Nuitka fallback パッケージングは実験的です。Nuitka がインストールされていない状態で
`--fallback=nuitka` が指定された場合、Rextio は明確な `RXT060` エラーを報告し、
`--fallback=cpython` を提案します。Nuitka がインストールされている場合、Rextio は
生成された Python fallback モジュールに対して Nuitka を実行しつつ、CPython fallback
ファイルをビルド成果物に残します。

`--fallback` が省略された場合、`rextio build` は `rextio.toml` の
`[build] fallback_backend` を使用します。`--fallback=cpython` または
`--fallback=nuitka` を渡すと、その実行ではプロジェクト設定を上書きします。

## 設定ソース

ビルドと解析の設定は、次の優先順位で解決されます。

```text
CLI parameter > environment variable > rextio.toml > built-in default
```

`project_root`、bench target、`init --force`、`check --json` のように、コマンド実行や
出力形式を決める引数は command-line 専用です。プロジェクト動作の設定は、次のどの
経路からでも指定できます。

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

0.1.0 alpha は引き続き値を保守的に検証します。現在実装されている native target は Rust
のみです。`native_backend = "mojo"` と `native_backend = "julia"` は将来の
target-language 選択肢として受け付けられ、versioned mapper や build-option metadata
を設定できますが、backend が実装されるまでは source generation は明確に失敗します。

Mapper plugin は local metadata folder または public Git repository から読み込めます。
Local folder は `[mappers] paths` と任意の `[mappers] enabled` で設定し、各 folder には
`rextio-mapper.toml` または `mapper.toml` が必要です。`[mappers] repository`、
`--mapper-repository`、または `REXTIO_MAPPER_REPOSITORY` には public Git URL を設定でき、
Rextio はそれを `.rextio/mappers/repositories/` へ clone して mapper manifest を
再帰的に検出します。

## 生成される成果物

Rextio は生成ファイルを `.rextio/` 以下に書き込み、ユーザーのソースファイルを
その場で変更しません。

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

`rextio check` は `.rextio/reports/check.json` を書き込みます。`rextio build` は check
と build の両方の report を書き込みます。`rextio bench` は構造化された fallback/native
タイミング比較を含む `.rextio/reports/bench.json` を書き込みます。

`rextio generate` は解析を実行し、Cargo、maturin、Nuitka を呼び出さず、
`.rextio/build/` や `dist/` を作成せずに、生成された Rust/PyO3 と Python
wrapper/fallback ソースを `.rextio/generated/` 以下に書き込みます。`--rust-importable`
を指定した場合は `.rextio/generated/rust_crate/` に Rust library crate のソースも
書き込みますが、その crate はコンパイルしません。

`rextio build` が成功すると、生成された hybrid artifact wheel も `dist/` 以下に
書き込みます。純粋な fallback wheel は `py3-none-any` を使用し、生成された native
extension を含む wheel はローカルの CPython/platform tag を使用します。テストスイートは
この wheel を新しい環境にインストールし、`REXTIO_DISABLE_NATIVE=1` でパッケージ済み
fallback import が引き続き動作することを検証します。

`rextio build --rust-importable --rust-crate-name=my_native` は、Rust から直接利用できる
library crate も生成し、Cargo でコンパイルします。Source artifact は
`dist/my_native-rust-crate/` にコピーされ、Rust プロジェクトから path dependency として
利用できます。

```toml
[dependencies]
my_native = { path = "../dist/my_native-rust-crate" }
```

生成された crate 関数は Rextio の deterministic native 名を使い、
`Result<T, RextioError>` を返します。

```rust
fn main() -> Result<(), my_native::RextioError> {
    let value = my_native::myapp__math_ops__sum_squares(vec![1, 2, 3])?;
    assert_eq!(value, 14);
    Ok(())
}
```

Rust-importable crate には typed Rust に直接 lowering された関数だけが含まれます。
Python runtime semantics shim と fallback-only 関数は Python-facing compatibility 経路に
残り、この crate には export されません。

`rextio build --entrypoint=module:function` は、`dist/` 以下に zipapp 実行 artifact も
生成します。出力ファイル名は `--executable-name=name` で指定できます。省略した場合、
Rextio は entrypoint モジュールから名前を導出します。結果は Python zipapp（`.pyz`）
なので、対象マシンには互換性のある Python インタープリタが必要です。Native extension
モジュールは zipapp 内部から直接 import できないため、生成された wrapper は fallback
安全性を維持し、native モジュールを利用できない場合は Python fallback を使用します。

Nuitka がインストールされている場合は、Nuitka executable artifact も利用できます。

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

standalone モードは `dist/` 以下に Nuitka の `.dist` アプリケーションディレクトリを
書き込みます。onefile モードは `dist/` 以下に単一の Nuitka 実行ファイルを書き込みます。
Nuitka executable パッケージングは、引き続きローカル toolchain に依存します。Nuitka が
利用できない場合、Rextio は明確な `RXT060` エラーを報告し、zipapp backend を提案します。

## ポリシー設定

0.1.0 alpha は `rextio.toml` を保守的に検証し、不明な section、不明な key、未対応の
backend、0.1.0 alpha の範囲外のポリシー値を拒否します。

境界警告はデフォルトで有効です。Python-loop 境界警告なしで厳格な安全エラーだけを
必要とするプロジェクトは、次のように設定できます。

```toml
[policy]
boundary_warnings = false
```

自動 native discovery はデフォルトで有効です。

```toml
[policy]
native_marker = "auto"
```

明示的な native 候補だけを使いたいプロジェクトは、auto discovery を無効化できます。

```toml
[policy]
native_marker = "decorator"
```

decorator-only モードでは、`@rextio.native` が付いた関数だけが native 候補になります。

明示的な marker では対象 native 言語も固定できます。たとえば
`@rextio.native(target="rust")` は、active な `--target-language` /
`[build] native_backend` が Rust の場合だけ適用されます。`target="mojo"` と
`target="julia"` は将来の backend 向け planning 値として保持されますが、0.1.0 alpha で
実装済みの source generation は Rust のみです。

自動 native discovery が有効な場合でも、Python fallback に残す必要がある関数には
`@rextio.exempt` を使ってください。exempt 関数は生成された Rust に emit されません。
それを呼び出す native 候補は、通常の native-to-fallback 境界ルールによって拒否されます。

## Fallback の安全性

生成された wrapper は、利用可能で安全な場合に native 関数を使います。native import が
失敗した場合、または native 実行が無効化されている場合は Python に fallback します。

```text
REXTIO_DISABLE_NATIVE=1
```

プロジェクトが明示的なランタイム動作を必要とする場合は、`REXTIO_NATIVE_MODE` を設定できます。

```text
REXTIO_NATIVE_MODE=auto      # デフォルト: 利用可能なら native、そうでなければ fallback
REXTIO_NATIVE_MODE=fallback  # Python fallback を強制
REXTIO_NATIVE_MODE=native    # 生成された native 関数が利用可能であることを要求
```

繰り返しの Python-to-native wrapper 呼び出しは最初は許可されます。ある関数の wrapper
crossing 回数が `REXTIO_BOUNDARY_FALLBACK_THRESHOLD` を超えると、それ以降の呼び出しは
その関数の生成済み Python fallback を使用します。デフォルトのしきい値は `1000` です。
`rextio generate --fallback-threshold=N`、`rextio build --fallback-threshold=N`、
`REXTIO_BOUNDARY_FALLBACK_THRESHOLD`、`[build] fallback_threshold = N` で、その artifact
の生成コード上のデフォルト値を設定できます。ランタイムでは
`REXTIO_BOUNDARY_FALLBACK_THRESHOLD` が embed されたデフォルト値より優先されます。
しきい値を `0` にするか `REXTIO_DISABLE_BOUNDARY_FALLBACK=1` を設定すると、この自動
fallback は無効になります。`REXTIO_NATIVE_MODE=native` はこのしきい値を迂回します。

生成ファイルや無関係な Python ファイルを Rextio の解析対象外にするには、
`.rextioignore` を使用してください。

## 境界診断

0.1.0 alpha の境界チェックは静的で保守的です。

- `RXT070`: native 関数が fallback-only Python コードを呼び出しています。
- `RXT072`: native 関数が拒否された native 関数に依存しています。
- `RXT073`: fallback Python がループ内で native 関数を呼び出しています。
- `RXT080`: native 関数が Python runtime semantics shim を使用しています。

`RXT070` と `RXT072` は native 候補を拒否します。`RXT073` は警告です。その関数は
引き続き条件を満たし、最初は native を使用できますが、繰り返しのランタイム crossing が
設定されたしきい値を超えると、生成された wrapper は CPython/Nuitka fallback パスへ
fallback します。`RXT080` は warning であり、生成された Rust 関数が Python fallback 関数を
呼び出して Python semantics を保持します。

## 例

0.1.0 alpha には焦点を絞ったローカル例が含まれています。

- `examples/pure_math`: native hot path としてコンパイルされる単純な型付き数学関数。
- `examples/fallback_demo`: native がない場合、または `REXTIO_DISABLE_NATIVE=1` の場合に、生成された wrapper が Python fallback を使用します。
- `examples/boundary_demo`: `@rextio.exempt` による保守的な境界拒否と Python-loop 境界警告。

試すには:

```text
rextio check examples/pure_math
rextio generate examples/pure_math --fallback=cpython
rextio build examples/pure_math --fallback=cpython
rextio build examples/fallback_demo --entrypoint=fallback_demo.run_demo:main
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math
rextio check examples/boundary_demo
```
