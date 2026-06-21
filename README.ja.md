# Rextio

[English](README.md) | [한국어](README.ko.md) | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md)

Rextio は、条件を満たす型付き Python 関数を Rust ネイティブモジュールへコンパイルし、
それ以外を安全な Python fallback としてパッケージします。

Public 1 は意図的に狭い範囲に絞っています。型付き Python の hot path を使う
プロジェクト向けのローカル CLI およびビルドツール MVP です。Rextio は条件を満たす
型付き関数をデフォルトで自動検出します。プロジェクト側では自動検出を無効にし、
`@rextio.native` マーカーを必須にすることもできます。Rextio は Python の完全互換、
NumPy の完全対応、フレームワーク移行、JIT 動作、または完全なランタイム境界コスト
最適化器を提供すると主張しません。

Public 1 には保守的な静的境界チェックが含まれます。fallback-only コードを呼び出す
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
rextio build path/to/project --fallback=cpython --entrypoint=myapp.cli:main
rextio bench myapp.scoring.compute_score --project-root path/to/project
rextio clean path/to/project
```

## Public 1 の範囲

Public 1 は、モジュールレベル関数向けの小さな型付き Python subset をサポートします。
条件を満たす型付き関数はデフォルトで native 候補になります。未対応の構文、動的機能、
安全でない native-to-fallback 呼び出し、解決できない外部呼び出しは native コンパイル
から拒否され、可能な場合は Python fallback として維持されます。

対応 subset、境界の制限、診断、非目標については
[Public 1 で未対応の機能](docs/unsupported-features.md)を参照してください。

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

Public 1 は引き続き値を保守的に検証します。現在実装されている native target は Rust
のみです。`native_backend = "mojo"` と `native_backend = "julia"` は将来の
target-language 選択肢として受け付けられ、versioned mapper や build-option metadata
を設定できますが、backend が実装されるまでは source generation は明確に失敗します。

Mapper plugin は現時点では local metadata folder です。`[mappers] paths` と任意の
`[mappers] enabled` で設定し、各 folder には `rextio-mapper.toml` または
`mapper.toml` が必要です。`[mappers] repository` は将来の download 機能のための設定枠
であり、Public 1 では実装されていません。

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

`rextio check` は `.rextio/reports/check.json` を書き込みます。`rextio build` は check
と build の両方の report を書き込みます。`rextio bench` は構造化された fallback/native
タイミング比較を含む `.rextio/reports/bench.json` を書き込みます。

`rextio generate` は解析を実行し、Cargo、maturin、Nuitka を呼び出さず、
`.rextio/build/` や `dist/` を作成せずに、生成された Rust/PyO3 と Python
wrapper/fallback ソースを `.rextio/generated/` 以下に書き込みます。

`rextio build` が成功すると、生成された hybrid artifact wheel も `dist/` 以下に
書き込みます。純粋な fallback wheel は `py3-none-any` を使用し、生成された native
extension を含む wheel はローカルの CPython/platform tag を使用します。テストスイートは
この wheel を新しい環境にインストールし、`REXTIO_DISABLE_NATIVE=1` でパッケージ済み
fallback import が引き続き動作することを検証します。

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

Public 1 は `rextio.toml` を保守的に検証し、不明な section、不明な key、未対応の
backend、Public 1 の範囲外のポリシー値を拒否します。

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

Public 1 の境界チェックは静的で保守的です。

- `RXT070`: native 関数が fallback-only Python コードを呼び出しています。
- `RXT072`: native 関数が拒否された native 関数に依存しています。
- `RXT073`: fallback Python がループ内で native 関数を呼び出しています。

`RXT070` と `RXT072` は native 候補を拒否します。`RXT073` は警告です。その関数は
引き続き条件を満たし、最初は native を使用できますが、繰り返しのランタイム crossing が
設定されたしきい値を超えると、生成された wrapper は CPython/Nuitka fallback パスへ
fallback します。

## 例

Public 1 には焦点を絞ったローカル例が含まれています。

- `examples/pure_math`: native hot path としてコンパイルされる単純な型付き数学関数。
- `examples/fastapi_scoring`: FastAPI は Python のままで、`compute_score` が Rust native になります。
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
