# Rextio

[English](README.md) | [한국어](README.ko.md) | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md)

**適格な typed Python 関数を Rust にコンパイルし、それ以外はすべて
Python fallback のまま動かします。**

Rextio 0.1.2 は Python プロジェクト向けの alpha 段階ローカルビルドツール
です（このブランチのリリース候補 — **まだ PyPI には公開されていません**;
最新の公開パッケージは **0.1.1**）。型付きの Python 関数のうち安全に
Rust へ下ろせるものを見つけて PyO3 で事前（ahead-of-time）コンパイルし、
それ以外はすべて生成された Python fallback コードで動かし続けます —
import パスも動作もそのままです。

```text
型付き Python プロジェクト
  -> サポートされる native 候補を分析
  -> 安全でない・未サポートの関数は拒否
  -> 受理された関数は Rust + PyO3 を生成
  -> 残りは Python fallback wrapper を生成
  -> import 互換 artifact をビルド
```

契約は厳格です: 関数は CPython と等価なセマンティクスで native コンパイル
されるか、診断とともに拒否されて Python fallback に残ります。Rextio は
確信が持てないとき推測せず、fallback を選びます。

Rextio は Python の代替ではなく、プロジェクト全体を Rust へ移行する
ツールでもありません。Native コンパイルは最適化であり、Python fallback の
動作が正しさの基準線です。

## クイックスタート

普通の Python コードから始めます:

```python
# src/myapp/math_ops.py
def sum_squares(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += x * x
    return total

def format_result(value: int) -> str:
    return f"score={value}"  # direct Rust subset の外
```

ビルドします（インストール済みユーザー向け。ソースチェックアウトでは
`python -m pip install -e .` を代わりに使用）:

```text
python -m pip install rextio
rextio check .
rextio build . --fallback=cpython
```

Rextio は `sum_squares` を Rust にコンパイルし、`format_result` を Python
fallback に残せます。import パスは Python のままです:

```python
from myapp.math_ops import sum_squares, format_result

assert sum_squares([1, 2, 3]) == 14
assert format_result(14) == "score=14"
```

主なコマンド:

| コマンド | 動作 |
| --- | --- |
| `rextio init` | `rextio.toml`、`REXTIO.md`、`.rextioignore` を作成します。 |
| `rextio check` | native 候補を分析し、診断を出力します（構造化 JSON は `--format json`）。 |
| `rextio capabilities` | 機械可読な capability manifest を出力します: サポート型、ガイダンス付きの昇格ルール、アクティブなプラグイン（experimental）。 |
| `rextio generate` | コンパイルせずに Rust/Python 生成ソースを書き出します。 |
| `rextio build` | 生成・コンパイル・パッケージングし、ビルドレポートを書きます。 |
| `rextio bench` | 1 つの関数について Python fallback と Rust native の時間を比較します。 |
| `rextio clean` | `.rextio/build`、`.rextio/generated`、`.rextio/reports` を削除します。 |

よく使うビルドの変形:

```text
rextio build . --fallback=cpython
rextio build . --fallback=nuitka
rextio build . --fallback-threshold=1000
rextio build . --embed-helpers
rextio build . --entrypoint=myapp.cli:main
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
rextio build . --rust-importable --rust-crate-name=my_native
```

よくある一連の流れ:

```text
rextio init --project-root path/to/project
rextio check path/to/project
rextio generate path/to/project --fallback=cpython
rextio build path/to/project --fallback=cpython
rextio bench myapp.math_ops.sum_squares --project-root path/to/project
rextio clean path/to/project
```

生成ソースだけが欲しいときは `rextio generate` を使います。Cargo、maturin、
Nuitka、wheel ビルド、実行ファイルのパッケージングは実行しません。

生成ソースに加えコンパイル/パッケージ済み成果物まで欲しいときは
`rextio build` を使います。

## 要件

| コンポーネント | バージョン | 備考 |
| --- | --- | --- |
| CPython | >= 3.11（3.11-3.14 で検証） | アナライザはビルドインタプリタの `ast` を使用し、生成拡張は PyO3 0.29（CPython 3.14 まで対応）を固定します。より新しいインタプリタは動作する可能性がありますが未検証です。wheel はビルドインタプリタの minor バージョンタグを持ちます。 |
| Rust toolchain | MSRV 1.83（最新 stable で検証） | 生成 crate は edition 2021 + PyO3 0.29 を使用します。[rustup](https://rustup.rs) でインストールしてください。 |
| Nuitka（任意） | >= 2.0 | `--fallback=nuitka`/`--executable-backend=nuitka`/`--hybrid-runtime=nuitka` 専用です。前者 2 つはビルド preflight が事前に拒否し、hybrid runtime は委譲された fallback 呼び出しが実際に Nuitka dispatcher を必要とする時点で検査されます。 |
| Numba（任意・experimental） | インタプリタに応じて: 3.11→>=0.57, 3.12→>=0.59, 3.13→>=0.61, 3.14→>=0.63 | Rextio は Numba デコレータを認識するだけで、パッケージ自体は Rextio ではなくユーザープロジェクトのランタイム依存です。下限は [Numba のバージョンサポート表](https://numba.readthedocs.io/en/stable/user/installing.html#version-support-information) に従います。 |

ツールの場所とバージョン pin は設定可能です: `rextio.toml` の `[toolchain]`
（または `REXTIO_*` 環境変数 / CLI フラグ）でビルドが使う cargo・maturin・
Nuitka・CPython を選択し、バージョンを検証できます。
[REXTIO.md](./REXTIO.md#toolchain-selection-and-version-pins) を参照。

## ビルド target

Rextio は同じ Python プロジェクトから複数の成果物を作れます:

| 成果物 | 用途 |
| --- | --- |
| `.rextio/generated/rust/` | 受理された native 関数の Rust/PyO3 生成ソース。 |
| `.rextio/generated/python/` | 生成された Python wrapper と fallback モジュール。 |
| `.rextio/build/python/` | import 互換の hybrid パッケージツリー。 |
| `dist/*.whl` | fallback コードと（ビルドされた場合）native 拡張を含む wheel。 |
| `dist/<name>.pyz` | 設定した Python entrypoint 用の zipapp 実行ファイル（任意）。 |
| `dist/<name>.dist/` または `dist/<name>` | Nuitka standalone/onefile 実行ファイル（任意）。 |
| `dist/<name>` | 独立した native Rust バイナリ（`--executable-backend=rust`）、Python ランタイム不要（任意）。 |
| `dist/<crate>-rust-crate/` | Rust プロジェクトが import できる Rust ライブラリ crate（任意）。 |

生成された Python wrapper はまず native コードを試し、native が無効・
利用不可・分析で拒否・設定した boundary threshold 超過のときに Python へ
fallback します。

```text
REXTIO_NATIVE_MODE=fallback
```

ビルド済み native モジュールのロード失敗時に、警告して fallback する
代わりに完全な traceback を上げるには `REXTIO_DEBUG_NATIVE=1` を設定して
ください — ABI 不一致や wrapper/codegen 名の不一致のデバッグに有用です。

Zipapp:

```text
rextio build . --entrypoint=myapp.cli:main --executable-name=myapp
```

`dist/myapp.pyz` が書き出されます。ターゲットマシンには互換の Python
インタプリタが依然として必要です。native 拡張は zipapp 内から import
されないため、`_rextio_native` がないとき wrapper は fallback 動作を保存
します。

Nuitka:

```text
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=standalone
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
```

Nuitka 実行ファイルのパッケージングは experimental で、Nuitka のインス
トールが必要です。

Native Rust バイナリ:

```text
rextio build . --entrypoint=myapp.cli:main --executable-backend=rust
```

`main` が Rust で動く native バイナリ（`dist/<name>`）をコンパイルします。
entrypoint は受理された direct-native `def main(argv: list[str]) -> int`
でなければなりません: `argv` は `sys.argv` を反映し（index 0 はプログラム
パス）、返した `int` がプロセスの exit code になり、送出されたエラーは
CPython スタイル（`OverflowError: ...`）で stderr に出力され non-zero で
終了します。Cargo が必要です。

entrypoint が Python fallback に残るプロジェクト関数（Rust subset 外の
コード）を呼ぶ場合、Rextio はその呼び出しを外部 CPython サブプロセスへ
委譲します: ビルドは `dist/<name>.runtime/` ディレクトリ（dispatcher +
プロジェクトソース）を同梱し、バイナリが stdio で駆動するため、コンパイル
しづらいロジックは Python のまま残せます。このような hybrid バイナリは
実行時に Python インタプリタを必要とします。呼び出しグラフが完全に
direct-native のバイナリは Python 依存のない独立型です。委譲呼び出しの
引数と結果はどちらも不変スカラー（`int`/`float`/`bool`/`str`/`None`）で
なければなりません。`list`/`dict`/`set` はどちらの方向にも委譲されません
（値として wire を渡り、CPython が保存する aliasing が切れて、変更された
引数や変更された alias 付き戻り値が静かにずれるため）。非有限 float
（`NaN`/`Infinity`）は静かに落とされる代わりに拒否されます。委譲された
関数自身の stdout/stderr はバイナリの stderr に現れます（バイナリの
stdout は wire プロトコル専用）。RXT080 runtime shim 上の関数は委譲され
ません: それに依存する entry はビルドされず拒否されます。

`--executable-python` はバイナリが起動するインタプリタを固定します
（`PATH` 上の名前、絶対パス、またはバンドル用の `<binary>.runtime` 相対
パス）。`REXTIO_RUNTIME_PYTHON` はターゲットマシン上で実行時にこれを上書き
します。`--hybrid-runtime=nuitka` は委譲される Python を runtime ディレク
トリに同梱される自己完結 dispatcher 実行ファイルへコンパイルし、hybrid
バイナリが別途の Python インストールを不要にします（ビルド時に Nuitka が
必要）。

direct Rust 関数を Rust アプリケーションから使いたい場合、追加の Cargo
ライブラリ crate をビルドします:

```text
rextio build . --rust-importable --rust-crate-name=my_native
```

Rust から生成 crate を使う:

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

この crate から export されるのは、直接型付き Rust へ下ろされた関数だけ
です。fallback 専用関数、runtime semantics shim、そしてスカラー boundary
call を使う関数（いずれもインタプリタが必要）は Python 側の経路に残り
ます。

## 設定

ビルド/分析の設定は次の順で解決されます:

```text
CLI パラメータ > 環境変数 > rextio.toml > 組み込みデフォルト
```

主な設定:

| `rextio.toml` キー | CLI パラメータ | 環境変数 |
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
| `[toolchain] *_version` pin | `--cargo-version` など | `REXTIO_CARGO_VERSION` など |
| `[policy] native_marker` | `--native-marker` | `REXTIO_NATIVE_MARKER` |
| `[policy] boundary_warnings` | `--boundary-warnings` / `--no-boundary-warnings` | `REXTIO_BOUNDARY_WARNINGS` |
| `[policy] native_top_level` | `--native-top-level` / `--no-native-top-level` | `REXTIO_NATIVE_TOP_LEVEL` |

0.1.2 で実装済みの native ターゲットは Rust だけです。

Rextio プラグインは `pip` や `uv` などでインストールする普通の Python
パッケージです。プラグインパッケージは、対象とする Python パッケージ名を
含むメタデータを `rextio.plugins` entry point グループで公開します。
プロジェクトは `[plugins] enabled` または `--enable-plugin` で特定の
プラグイン id を有効化します。

アクティブな Rextio プラグインのない外部 Python パッケージはデフォルトで
保守的に扱います: Rextio はサードパーティのパッケージソースを黙って Rust
に翻訳しません。そうしたパッケージの呼び出しは、プラグインを追加するか、
既知の純 Python パッケージについて実験的な依存分析へ明示的に opt-in
しない限り、周囲の native 候補を fallback に残します:

```toml
[imports]
default_external_policy = "fallback"

[imports.packages]
"some_pure_python_pkg" = { policy = "try-native", max_depth = 1 }
"legacy_dynamic_pkg" = "fallback"
"known_pkg" = { policy = "plugin", plugin = "known-rust" }
```

サポートされるパッケージポリシーは `fallback`、`analyze`、`try-native`、
`plugin` です。0.1.1 からはプラグインがカバーする構文を記述し、直接
*lowering* することもできます（plugin API 1.1 —
[plugin lowering 仕様](docs/specs/plugin-lowering.md) を参照）。0.1.2 は
後方互換の plugin API **1.2**（静的リテラル／順序付きキーワードメタデータ、
構造化 `ClaimExpr` 木、leaves モード lowering）を追加します。first-party の
[rextio-numpy](https://github.com/rextio/rextio-numpy) プラグインは別途
インストールします（core は逆依存しません）: **PyPI 0.1.0** が公開済みの
初期認証 float64 1-D サーフェス、**未タグ 0.1.1 RC** は literal-axis／
fusion を広げ **core >= 0.1.2** が必要です。関連パッケージの**厳密な公開
順序**は rextio-lsp 0.1.1 → core 0.1.2 → rextio-numpy 0.1.1（同時公開は
しない; [tooling contract](docs/specs/tooling-contract.md) を参照）。一般的な
依存 lowering はバンドルされません。`try-native` は明示的な計画ポリシーで、
安全な direct lowering がなければやはり fallback します。

## Native 選択

デフォルトは自動 native 探索です:

```toml
[policy]
native_marker = "auto"
```

このモードでは、型を解決でき、サポートされる direct Rust subset に収まる
モジュールレベル関数を native 候補として扱うことがあります。

明示的なマーカーを要求することもできます:

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

将来のマルチターゲット対応のため、マーカーで対象を固定できます:

```python
@rextio.native(target="rust")
def score(x: float) -> float:
    return x * 2.0
```

関数を必ず Python fallback に残す場合は `@rextio.exempt` を使います:

```python
@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1
```

exempt 関数が生成 Rust に含まれることはありません。native 候補が exempt
または fallback 専用の関数を呼ぶ場合、その候補も fallback に落ちます。

## 安全モデル

Rextio は native コンパイルを保守的に保ちます:

- direct Rust native 関数が呼べるのは、受理された native 関数、サポート
  される builtin、サポートされる標準ライブラリ関数だけです。
- fallback 専用コードを呼ぶ native 関数は拒否されます — ただし呼び出し側が
  明示的にマークされ、callee のシグネチャが端から端まで不変スカラー
  （`int`/`float`/`bool`/`str`/`None`）なら、その呼び出しは in-process の
  スカラー boundary call（`RXT075`）になります。callee はインタプリタで
  実行され続けるため、値と例外は CPython-正確で monkeypatch も反映
  されます。スカラーは値で境界を越えるため、引数の identity（`is`）は
  保存されません（`None`/`bool` のシングルトンは保存されます）。コンテナは
  境界を越えず、内包表記本体を含む native ループ内の boundary call は
  呼び出し側を fallback に残します（`RXT076`）。
- Python fallback コードは native 関数を呼べます。
- native 関数を繰り返し呼ぶ Python ループは boundary 警告を出します。
- 生成された wrapper は、境界横断が繰り返されるとその関数を fallback へ
  戻すことがあります — Python→native の wrapper 進入と native スカラー
  boundary call は同じ関数別しきい値に合算されます。
- Python/Rust の所有権の違いは明示的に扱います。所有値の読み取り専用の
  再利用は必要に応じて Rust の clone で下ろし、可変コレクションの alias
  変更は Python fallback に残します。

boundary fallback は次で制御します:

```text
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
REXTIO_NATIVE_MODE=auto|fallback|native
```

## direct Rust subset

Rextio 0.1.2 は意図的に小さな subset をサポートします。この subset が
native Rust として実行されるコードです。

サポートされる型:

- `int`、`float`、`bool`、`str`、`bytes`、`None`
- サポートされる要素型の `list[T]`（`list[list[T]]` を含む）
- 固定 `tuple[...]`
- キーがサポートされるスカラーキー型である固定 `dict[K, V]`
- 限定的な `set[int]`、`set[bool]`、`set[str]`（`set[float]` は Python
  fallback に残ります: NaN-identity の重複排除には忠実な Rust lowering が
  なく、native コードは set を*反復*もしません — ハッシュ順序が CPython と
  異なります）
- `Optional[T]`、`T | None`

サポートされる構文:

- ローカル代入と型注釈付きローカル
- 算術、ブール演算、比較、`if`、`while`
- `for x in xs`
- サポートされるループ/内包形式の `range(...)`、`enumerate(xs)`、`zip(xs, ys)`
- `break`、`continue`、`return`
- 制限付きの実験的 `try`/`except`/`finally` サブセット（組み込み例外
  ハンドラのみ。[安定性ティア](docs/stability.md) を参照）
- サポートされる形式の list/dict/set 内包表記
- 限定的な `list.append`、dict の読み書き、インデックス参照
- 受理された native ヘルパー関数の呼び出し

builtin・標準ライブラリの lowering（限定形式）:

- `len`、`abs`、`min`、`max`、`sum`、`all`、`any`、`sorted`、`reversed`
- 一部の `math` 関数と定数
- 一部の `str`、`bytes`、`list` メソッド
- `print`、`logging.debug/info/warning/error`
- `datetime`、`time`、`hashlib.sha256`、`base64.b64encode`
  （`statistics.mean`/`fmean`、`json.dumps`/`json.loads`、
  `base64.b64decode` には忠実な direct-native 等価物がありません: 明示的に
  マークされた関数は RXT080 runtime shim に乗り、自動探索された関数は
  Python fallback に残ります）

未サポート・曖昧なコードは fallback に残るか、サポートされる場合は Python
runtime semantics shim として公開されます。詳細な境界は
[0.1.0 の未サポート機能](docs/unsupported-features.md) を参照して
ください。

## Rextio に適した Python の書き方

native への昇格と boundary の挙動はコードの形からそのまま決まります。
Rextio を最大限に活かすには:

- ホットな関数は端から端まで annotate する - 引数と戻り値の型を、サポート
  される scalar/list 型で。型が解決できない関数は fallback に残ります。
- ホットパスはサポート subset の中に収め、`rextio check` を早めに実行する。
  すべての拒否には原因となった構文が明示されます。
- ループを native の中へ移す: native 関数を呼ぶ Python ループは反復ごとに
  境界を越えますが（boundary 警告）、内部でループする native 関数は呼び出し
  ごとに 1 回だけ越えます。
- native 呼び出しグラフは native のまま保つ: native-to-native 呼び出しは
  Rust 内に留まります。fallback 専用 helper の呼び出しは呼び出し側を拒否
  させるか、呼び出しごとに発生して降格 threshold に加算される scalar
  boundary call になります。
- boundary call はループや内包表記本体の外に置く（`RXT076`）。外へ
  巻き上げるか、callee が subset に収まるなら `@rextio.native` を付ける。
- 境界は不変スカラーで越える。コンテナは境界を越えません。
- Python に残すべき関数は `@rextio.exempt` を付け、混在した関数は typed な
  ホットコアが独立した関数になるよう分割する。
- `rextio bench` で測定する: 非常に小さな関数は呼び出しオーバーヘッドに
  負けることがあるため、native 呼び出し 1 回に十分な仕事をまとめる。

## Python runtime semantics shim

一部の Python 機能は型付き Rust 文へ安全に翻訳できません。明示的にマーク
された native コードに対し、Rextio は生成された Python fallback 実装を
代わりに呼ぶ PyO3 shim を生成することがあります。

この互換経路は class/オブジェクトの動作、インスタンスメソッド、例外、
コンテキストマネージャ、`async`/`await`、ジェネレータ、動的属性アクセス
などを保存できます。`RXT080` として報告されます。

この経路は動作を保存します。Rust の高速化経路として扱ってはいけません。

## Experimental scalar helper 埋め込み（embedding）

Rextio は、マークされていないごく狭い範囲のスカラーヘルパーを内部 native
関数として任意で埋め込めます — 他のすべてと同じく事前（ahead-of-time）に
コンパイルされます。デフォルトはオフです。

有効化すると、適格な未マークヘルパー（スカラー引数と戻り値、単一の算術
return 式）が生成 native artifact の普通の内部関数としてコンパイルされます
— native コードから呼べ、Python へは export されません。埋め込まれた
ヘルパーは通常の checked 経路で下ろされるため、整数 overflow は
OverflowError を、ゼロ除算は ZeroDivisionError を他の native 関数と同じく
発生させます。Rust 実行ファイル backend では、埋め込まれたヘルパーは呼び
出しごとに CPython dispatcher へ委譲される代わりにバイナリへコンパイル
されます。

```toml
[embedding]
enabled = true
```

同等の CLI / 環境変数:

```text
rextio build . --embed-helpers
REXTIO_EMBED_HELPERS=true rextio build .
```

埋め込みは生成 Cargo プロジェクトに crate 依存を追加しません。埋め込みが
無効でも、適格なヘルパー呼び出しは実行時のスカラー boundary call で動作
します — 埋め込みは呼び出しごとのインタプリタ往復を除去する高速経路です。
boundary call と異なり、埋め込まれたヘルパーはビルド時に native 成果物へ
コンパイルされたコピーなので、ヘルパーの実行時差し替え（monkeypatch）は
native 呼び出し側からは見えません。

## Numba 外部アクセラレータ（experimental）

Numba サポートは 0.1.0 で EXPERIMENTAL です: 認識、レポート、Nuitka
共存の挙動は最初の non-alpha リリース前に変わる可能性があります。Rextio は
Numba デコレータ（`numba.jit`、`numba.njit`、`numba.vectorize`、
`numba.guvectorize`）を Python fallback コード向けの外部アクセラレータ
（experimental）として認識します — Nuitka パッケージング backend と同じ
「外部でサポートされるツール」パターンです。デコレートされた関数は Python
fallback にきれいに残り（自動探索とヘルパー埋め込みから除外）、レポートで
`external_accelerator: numba` とラベル付けされ、`rextio check` がそれらを
一覧します。認識はモジュールの import を通じて解決されます（attribute、
from-import、別名、呼び出し形式; `numba.cuda.jit` を含む）。`rextio check`
のレポートラベルは直線的な import のみを扱い、Nuitka ビルド時スキャンは
より広い（star import、任意依存ガード、関数内の遅延 import）ため、関数に
ラベルがなくてもビルドはモジュールを正しく plain のまま保てます。

契約境界が重要です: `@rextio.native` 関数は Rextio が検証した CPython-正確
セマンティクスを持ちますが、`@numba.*` 関数は **Numba の**セマンティクスで
実行されます（例: nopython モードの整数演算は overflow で例外ではなく
wrap）— そのトレードはユーザーの明示的な opt-in であり、`@rextio.exempt`
と同様に Rextio の native 契約の外です。`@rextio.native` と numba
デコレータの併用は明確に拒否されます。

互換性: wheel と zipapp の配布は numba をプロジェクト依存として
インストールすれば動作します。Rust 実行ファイルの source モード hybrid
runtime も動作します（dispatcher が本物の CPython を実行）。
`--fallback=nuitka` backend は自動で共存します: 認識された外部アクセラ
レータを使うモジュールは plain Python のまま（`.py` が import され続ける）
で、ツリーの残りは Nuitka でコンパイルされ、ビルドレポートに一覧されます。
生成された wheel は Nuitka コンパイル済みモジュールを拡張としてのみ載せ —
覆い隠された `.py` ソースは除外（死重であり、ソース露出でもある）—
プラットフォームタグを持ちます。アクセラレータ対象モジュールは `.py` を
保持します。Nuitka *実行ファイル*（`--executable-backend=nuitka`）と
`--hybrid-runtime=nuitka` dispatcher はアクセラレータ対象関数を提供でき
ません（コンパイル済み関数はバイトコードを公開せず、アクセラレータは
バンドルされない）— 最初の呼び出しで死ぬ代わりに案内付きで早期に失敗
します。型付きスカラーコードには `@rextio.native` を、NumPy/配列カーネル
には Numba を推奨し、ごく小さな関数はどのアクセラレータでも呼び出し境界
コストに負ける点に注意してください。

first-party の [rextio-numpy](https://github.com/rextio/rextio-numpy)
プラグインは、カバーされた NumPy を AOT コンパイルされた native Rust へ
変換します。**公開済み rextio-numpy 0.1.0** は初期認証 float64 1-D
サーフェス（要素ごとの算術、`numpy.dot`、配列全体の `sum`/`mean`）を
カバーします。**未タグ rextio-numpy 0.1.1 RC** は core plugin API 1.2
（**core >= 0.1.2**）を要する literal-axis／fusion lowering を広げます
（公開パッケージではなく 0.1.0 と混同しないこと）。その RC の公開は dual-map
**rextio-lsp 0.1.1** と **core 0.1.2** の後です。これにより NumPy コード
には 2 つの経路（カバーされたサーフェスに対する Rextio plugin の AOT
コンパイル、または Python fallback 内の Numba JIT）があります。両方が
適用できる場合は明示的な `@numba.*` デコレータが優先され、analyzer は
情報提供の RXT091 ノートを出力します。経路選択のより広いガイドは、
プラグインのサーフェスが育つにつれて固まっていく予定です。

## 例

```text
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math

rextio check examples/boundary_demo
rextio build examples/fallback_demo --entrypoint=fallback_demo.run_demo:main
```

サンプルプロジェクト:

- `examples/pure_math`: 型付き数値 hot path の direct Rust lowering。
- `examples/fallback_demo`: native が無効・欠如のときの fallback 動作。
- `examples/boundary_demo`: native→fallback boundary の拒否と警告。
- `examples/app_shell`: アプリの shell は Python のまま、スコアリングの
  hot path だけ native になり得る構成。
- `examples/wheel_package`: 既定の hybrid wheel を新しい環境にインストール
  し、同じ import で使う例。
- `examples/nuitka_fallback`: Nuitka でコンパイルされた fallback を含む
  hybrid wheel。
- `examples/numba_accelerator`: Rextio native と Numba-JIT の NumPy カーネル
  の併用。
- `examples/nuitka_numba`: Rust native + Nuitka fallback + plain Python の
  まま残る Numba モジュールを 1 つのビルドで。
- `examples/zipapp_app`: 単一ファイルの `.pyz` 実行ファイル。
- `examples/nuitka_executable`: onefile の Nuitka 実行ファイル。
- `examples/rust_executable`: 独立した native Rust バイナリ。
- `examples/rust_crate`: Rust 呼び出し側向けの Cargo ライブラリ crate。
- `examples/embedding_helpers`: scalar boundary call と埋め込み helper の
  対比。

## 開発と検証

テストスイートの実行:

```text
python -m pytest
```

実 Cargo、Nuitka、実行ファイルのテストは、対応する toolchain がなければ
スキップされます。

開発環境の詳細と品質ゲートは [CONTRIBUTING.md](CONTRIBUTING.md) を参照して
ください。

## 今後の計画

約束ではなく計画であり、alpha のフィードバックで優先順位は変わり得ます:

1. まず安定化: 表面を広げる前に、実利用に基づいて 0.1.0 の表面を
   固めます。
2. コーディングエージェントに Rextio に適した Python の書き方を教える
   agentic coding 用 skill/plugin。
3. 編集中のコードがサポート対象の native subset に収まるかを画面上で
   示す VS Code 拡張。
4. Rextio plugin - 特定のパッケージを使う Python コードを Rust と
   fallback コードへ変換する規則を定義するプラグインです。NumPy を
   皮切りに、よく使われる数値計算・AI パッケージを対象とした自前の
   プラグインを開発する計画で、plugin の表面が安定すれば誰でも Rextio
   plugin を作って公開できるようになります。
5. 長期的には Rust 以外の native target backend を増やす可能性が
   ありますが、具体的な計画はまだありません。

## プロジェクト情報

- [機能の安定性](docs/stability.md) — 0.1.0 で何が stable で何が experimental か。
- [バージョニングポリシー](docs/versioning.md) — pre-1.0 の注意点付き SemVer。
- [未サポート機能](docs/unsupported-features.md) — 0.1.0 subset の境界。
- [セキュリティモデル](SECURITY.md) — 信頼境界と脆弱性の報告方法。
- [コントリビュート](CONTRIBUTING.md) — セットアップ、ゲート、慣例。
- [変更履歴](CHANGELOG.md)。
- 開発者: 宋始永（ソン・シヨン） <rextio.co@gmail.com> — X (Twitter): [@RextioDev](https://x.com/RextioDev)。
