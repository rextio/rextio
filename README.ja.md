# Rextio

[English](README.md) | [한국어](README.ko.md) | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md)

Rextio 0.1.0 は alpha 段階のローカル Python ビルドツールです。

安全に Rust へ lowering できる Python 関数を見つけて ahead-of-time でコンパイルし、
それ以外のコードは Python fallback としてそのまま実行できるようにします。

```text
typed Python project
  -> native 候補を解析
  -> 未対応または安全でない関数を拒否
  -> accepted 関数の Rust + PyO3 を生成
  -> その他のコードの Python fallback wrapper を生成
  -> import 可能な hybrid artifact をビルド
```

Rextio は Python の代替でも、whole-project Rust migration ツールでもありません。
Native コンパイルは最適化であり、Python fallback の動作が正しさの基準です。

## 提供するもの

| 生成物 | 用途 |
| --- | --- |
| `.rextio/generated/rust/` | accepted native 関数の Rust/PyO3 ソース |
| `.rextio/generated/python/` | Python wrapper と fallback module |
| `.rextio/build/python/` | import 可能な hybrid package tree |
| `dist/*.whl` | fallback コードと native extension を含む wheel |
| `dist/<name>.pyz` | Python entrypoint 用の zipapp executable artifact |
| `dist/<name>.dist/` または `dist/<name>` | Nuitka standalone/onefile executable artifact |
| `dist/<crate>-rust-crate/` | Rust プロジェクトが path dependency として使える crate |

生成された Python wrapper は native を優先して試します。native が無効、読み込み不可、
解析で拒否、または boundary threshold 超過の場合は Python fallback を使います。

```text
REXTIO_DISABLE_NATIVE=1
```

## クイック例

```python
# src/myapp/math_ops.py
def sum_squares(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += x * x
    return total

def format_result(value: int) -> str:
    return f"score={value}"  # direct Rust subset ではない
```

```text
python -m pip install -e .
rextio check .
rextio build . --fallback=cpython
```

Rextio は `sum_squares` を Rust にコンパイルし、`format_result` は Python fallback に
残せます。Python の import path は変わりません。

```python
from myapp.math_ops import sum_squares, format_result

assert sum_squares([1, 2, 3]) == 14
assert format_result(14) == "score=14"
```

## よく使う流れ

```text
rextio init --project-root path/to/project
rextio check path/to/project
rextio generate path/to/project --fallback=cpython
rextio build path/to/project --fallback=cpython
rextio bench myapp.math_ops.sum_squares --project-root path/to/project
rextio clean path/to/project
```

`rextio generate` は生成ソースだけを書き出し、Cargo、maturin、Nuitka、wheel build、
executable packaging は実行しません。`rextio build` は生成、コンパイル、パッケージングを
実行します。

## コマンド

| コマンド | 役割 |
| --- | --- |
| `rextio init` | `rextio.toml`、`REXTIO.md`、`.rextioignore` を作成 |
| `rextio check` | native 候補を解析し diagnostics を出力 |
| `rextio generate` | コンパイルせず Rust/Python ソースだけを生成 |
| `rextio build` | 生成、コンパイル、パッケージングを行い build report を出力 |
| `rextio bench` | 1 つの関数について Python fallback と Rust native の時間を比較 |
| `rextio clean` | `.rextio/build`、`.rextio/generated`、`.rextio/reports` を削除 |

よく使う build 形式:

```text
rextio build . --fallback=cpython
rextio build . --fallback=nuitka
rextio build . --fallback-threshold=1000
rextio build . --jit
rextio build . --entrypoint=myapp.cli:main
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
rextio build . --rust-importable --rust-crate-name=my_native
```

## Native 選択

デフォルトでは automatic native discovery が有効です。

```toml
[policy]
native_marker = "auto"
```

関数の型を解決でき、direct Rust subset に合う module-level 関数は native 候補になります。
明示 marker だけを使うモードにもできます。

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

将来の multi-target 構成に備えて target も指定できます。

```python
@rextio.native(target="rust")
def score(x: float) -> float:
    return x * 2.0
```

必ず Python fallback に残す関数には `@rextio.exempt` を使います。

```python
@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1
```

exempt 関数は Rust に生成されません。native 候補が exempt または fallback-only 関数を
呼び出す場合、その候補も fallback に回されます。

## 安全モデル

- direct Rust native 関数は accepted native 関数、対応 builtin、対応 standard-library 関数だけを呼び出せます。
- fallback-only コードを呼び出す native 関数は拒否されます。
- Python fallback コードは native 関数を呼び出せます。
- Python loop が native 関数を繰り返し呼ぶ場合、boundary warning を出します。
- wrapper crossing が threshold を超えると、生成 wrapper はその関数を fallback に切り替えられます。
- Python/Rust ownership 差は明示的に扱います。read-only reuse は必要に応じて clone し、mutable collection alias mutation は Python fallback に残します。

関連する runtime 設定:

```text
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
REXTIO_NATIVE_MODE=auto|fallback|native
```

## direct Rust subset

0.1.0 alpha は小さな subset だけを direct Rust に lowering します。ここが実際の Rust
speedup を期待できる経路です。

対応型は `int`、`float`、`bool`、`str`、`bytes`、`None`、`list[T]`、
`list[list[T]]`、fixed `tuple[...]`、fixed `dict[K, V]`、限定的な `set[...]`、
`Optional[T]`、`T | None` です。

対応構文は local assignment、typed local annotation、算術、比較、`if`、`while`、
`for x in xs`、対応形式の `range`/`enumerate`/`zip`、`break`、`continue`、`return`、
限定的な list/dict/set comprehension、限定的な `list.append`、dict read/write、
indexing、accepted native helper call です。

lowering できる builtin/standard-library の範囲には `len`、`abs`、`min`、`max`、
`sum`、`all`、`any`、`sorted`、`reversed`、一部 `math`、一部 `str`/`bytes`/`list`
method、`print`、`logging`、`datetime`、`time`、`hashlib.sha256`、
`base64.b64encode` が含まれます。（`statistics.mean`/`fmean`、
`json.dumps`/`json.loads`、`base64.b64decode` は CPython と正確に一致する
native 実装がないため、Python fallback または runtime shim に残ります。）

未対応または意味が曖昧なコードは fallback に残るか、対応している場合は Python runtime
semantics shim で挙動を保ちます。詳しい境界は
[0.1.0 alpha で未対応の機能](docs/unsupported-features.md)を参照してください。

## Python runtime semantics shim

一部の Python 機能は typed Rust statement に安全に変換できません。明示的に native 指定された
コードに対して、Rextio は Python fallback 実装を呼び出す PyO3 shim を生成できます。

この compatibility path は class/object、instance method、exception、context manager、
`async`/`await`、generator、dynamic attribute access などの挙動を保持し、`RXT080` を
報告します。これは挙動維持の経路であり、Rust speedup の経路ではありません。

## Rust-importable crate

direct Rust 関数を Rust application からも使いたい場合、Cargo library crate を追加生成できます。

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

この crate は typed Rust に直接 lowering された関数だけを export します。fallback-only 関数と
runtime semantics shim は Python-facing path のままです。

## Experimental scalar helper 埋め込み（embedding）

Rextio はごく狭い scalar helper（型が確定した単一算術 return 式の unmarked 関数）を
native 関数内に AOT で埋め込めます。デフォルトでは無効です。

```toml
[jit]
enabled = true
```

同じ設定は `rextio build . --jit` または `REXTIO_JIT=true` でも指定できます。
（`[jit]` というキー名に反して、この機能は JIT では
ありません — すべてのコンパイルはビルド時（AOT）に完了し、ビルド成果物の中で
動作する JIT コンパイラは存在しません。）
埋め込まれた helper は通常の checked 経路でコンパイルされ、overflow は
OverflowError を、ゼロ除算は ZeroDivisionError を正しく raise し、PyO3 関数として
export されません。ランタイムコンパイルはありません。

## Numba 外部アクセラレータ（experimental）

0.1.0 alpha における Numba サポートは実験的（experimental）機能です:
認識・レポート・Nuitka 共存の挙動は最初の non-alpha リリース前に変わる
可能性があります。

`numba.jit`/`njit`/`vectorize`/`guvectorize`/`cuda.jit` デコレータ付きの関数は
意図的に Python fallback に残り（診断ノイズなし）、レポートに
`external_accelerator: numba` と表示されます。これらの関数は Numba のセマンティクス
（例: nopython モードの int overflow は wrap）で実行され、Rextio の CPython 正確性
契約の外にあります — `@rextio.exempt` と同じ opt-in 哲学です。`--fallback=nuitka`
は自動的に共存します: アクセラレータを使うモジュールはコンパイルから除外され
plain `.py` のまま残り、wheel は Nuitka でコンパイルされたモジュールの `.py`
ソースを除外してプラットフォームタグを付けます。Nuitka *実行ファイル* と
`--hybrid-runtime=nuitka` はアクセラレータ使用モジュールがあると案内付きで早期に
失敗します（`--hybrid-runtime=source` を使用）。ビルド時スキャンはレポートの
ラベルより範囲が広く、`rextio check` のラベルは直線的な import のみを扱うため、
ラベルのない関数のモジュールもビルドでは正しく plain のまま保持されることがあります。

## executable artifact

```text
rextio build . --entrypoint=myapp.cli:main --executable-name=myapp
```

これは `dist/myapp.pyz` を生成します。ターゲットマシンには互換性のある Python interpreter が
必要です。Native extension は zipapp 内から直接 import されないため、`_rextio_native` が
利用できない場合も wrapper は fallback behavior を保ちます。

Nuitka executable packaging は実験的で、Nuitka のインストールが必要です。

```text
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=standalone
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
```

## 設定

```text
CLI parameter > environment variable > rextio.toml > built-in default
```

主な設定:

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

現在実装されている native target は Rust だけです。`mojo` と `julia` は将来 backend のための
planning value です。Rextio plugin は `pip` や `uv` でインストールする通常の Python
package で、`rextio.plugins` entry point group から metadata を公開します。プロジェクトは
`[plugins] enabled` または `--enable-plugin` で使う plugin id を指定します。0.1.0 alpha は
具体的な third-party plugin 変換を内蔵しません。plugin がない外部 Python package は
default で fallback です。明示的に許可する pure-Python dependency は
`[imports.packages]` または `--package-import-policy` で `try-native` を指定できますが、
安全な direct lowering がなければ Rextio は fallback を使います。

## 例

```text
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math

rextio check examples/boundary_demo
rextio build examples/fallback_demo --entrypoint=fallback_demo.run_demo:main
```

- `examples/pure_math`: typed math hot path の direct Rust lowering
- `examples/fallback_demo`: native disabled/missing 時の fallback behavior
- `examples/boundary_demo`: native-to-fallback boundary rejection と warning
- `examples/app_shell`: application shell は Python のまま、scoring hot path は native 化可能
