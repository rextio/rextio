# Rextio

<p align="center"><img src="./assets/readme/rextio-icon.png" width="112" alt="Rextio アイコン"></p>

<p align="center"><strong>対象となる型付き Python 関数を Rust/PyO3 へ事前コンパイル。<br>それ以外は安全な Python フォールバックで動かし続けます。</strong></p>

<p align="center">
  <a href="https://github.com/rextio/rextio/blob/main/README.md">English</a> · <a href="https://github.com/rextio/rextio/blob/main/README.ko.md">한국어</a> ·
  <a href="https://github.com/rextio/rextio/blob/main/README.zh-hans.md">简体中文</a> · <a href="https://github.com/rextio/rextio/blob/main/README.zh-hant.md">繁體中文</a> ·
  <a href="https://github.com/rextio/rextio/blob/main/README.ja.md">日本語</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/rextio/"><img alt="PyPI バージョン" src="https://img.shields.io/pypi/v/rextio"></a>
  <a href="https://pypi.org/project/rextio/"><img alt="対応 Python バージョン" src="https://img.shields.io/pypi/pyversions/rextio"></a>
  <a href="https://github.com/rextio/rextio/blob/main/LICENSE"><img alt="MIT ライセンス" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

Rextio は、アプリケーションを書き直さずに一部の型付きホットパスをネイティブ Rust で実行したい **Python 開発者向けの Alpha ローカルビルドツール**です。保守的なアナライザーは、文書化された意味を保って安全に lower できるコードだけを受け入れます。未対応または曖昧なコードは生成済み Python フォールバック wrapper に残ります。ネイティブ実行を無効化した場合、または既定の `auto` モードでネイティブコードを利用できない場合も、同じ import がこれらの wrapper を通して動作します。

```bash
python -m pip install rextio
rextio check .
```

ビルド前に受理される関数を確認する、最短で有用な最初の一歩です。

Core **0.1.8** は 2026-07-27 に plugin API **1.7**、tooling contract **3.0.0** とともに公開されました。履歴は[変更履歴](CHANGELOG.md)を参照してください。

> **Tooling 移行：**contract 3.0 は milestone 由来の artifact identity を意味ベースの `artifact-*` 名へ置き換えます。正確な 0.1.7 identity は legacy の読み取り/検証入力としてのみ残り、2.x 専用 consumer は major 3 で機能を縮退させる必要があります。

## 証拠：測定済み CPU ワークロード

**Mac16,11 / Apple M4 Pro**、**2026-07-26**、CPython **3.11.9** における 3 回実行の中央値です。

| ワークロード | source/native 中央高速化率 |
| --- | ---: |
| Core hybrid | 57.729× |
| NumPy mixed fusion | 2.523× |
| NetworkX Dijkstra | 3.679× |
| pandas `Series.map` | 66.143× |
| PyTorch CPU deep MLP | 1.017× |
| TensorFlow CPU eager chain | 1.040× |

これは**特定ワークロードでの観測値**であり、ライブラリ全体の性能保証ではありません。1× 付近は同等を意味し、保存された診断ケースには Python より遅いものもあります。CUDA は測定していません。監査可能な [rextio-benchmark](https://github.com/rextio/rextio-benchmark) リポジトリに、正確な revision、source/fallback/native lane、生の証拠、安定性ポリシー、診断、低速・同等ケースがあります。

## 仕組み

```text
typed Python
  → 型を解決して対応サブセットを検査
  → 安全でない native/fallback 呼び出しグラフを拒否
  → 受理した関数を Rust + PyO3 へ lowering
  → import 互換の Python wrapper を生成
  → fallback を維持したままネイティブ成果物をビルド
```

正しさの基準は Python です。Rextio は Python の代替、汎用 Python-to-Rust 変換器、JIT、プロジェクト全体の移行ツールではありません。

## 最初のビルド

既定の自動モードではデコレーターは任意です。通常の型付き Python から始めます。

```python
# src/myapp/math_ops.py
def sum_squares(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += x * x
    return total

def format_result(value: int) -> str:
    return f"score={value}"  # Python fallback に残る
```

```bash
rextio check .
rextio build . --fallback=cpython
```

Rextio は `sum_squares` を lower し、`format_result` をフォールバックに残せます。呼び出し側は通常の Python import を維持します。

```python
from myapp.math_ops import format_result, sum_squares

assert sum_squares([1, 2, 3]) == 14
assert format_result(14) == "score=14"
```

ビルド済みパッケージはいつでもフォールバックに固定できます。

```bash
REXTIO_NATIVE_MODE=fallback python -m myapp
```

主なコマンドは `rextio init`、`rextio capabilities`、`rextio check`、`rextio generate`、`rextio build`、`rextio bench`、`rextio clean` です。

## 要件

| コンポーネント | 対応境界 |
| --- | --- |
| CPython | `>=3.11`。3.11–3.14 で検証済み。生成 extension は CPython 3.14 まで対応する PyO3 0.29 に固定されます。それ以降の interpreter は未検証で、wheel はビルド interpreter の minor version 用に tag されます。 |
| Rust | MSRV 1.83。最近の stable をテスト。生成 crate は Rust 2021 を使用します。[rustup](https://rustup.rs) でインストールしてください。 |
| Nuitka | 任意、`>=2.0`。選択した Nuitka fallback、実行ファイル、dispatcher 経路でのみ必要です。これらは Experimental です。 |
| Numba | 任意かつ Experimental。interpreter ごとの下限は 0.57（3.11）、0.59（3.12）、0.61（3.13）、0.63（3.14）。Numba は利用者プロジェクト側の依存関係です。 |

ツールの場所とバージョンは `[toolchain]`、環境変数、CLI オプションで固定できます。[REXTIO.md](./REXTIO.md#toolchain-selection-and-version-pins) を参照してください。

## 選択とフォールバック安全性

既定は自動検出です。

```toml
[policy]
native_marker = "auto"
```

`@rextio.native` を必須にするには `native_marker = "decorator"`、Python に固定するには `@rextio.exempt` を使います。実装済みのネイティブ対象は Rust のみです。

```python
import rextio

@rextio.native
def score(x: float) -> float:
    return x * 2.0

@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1
```

アプリケーション設計に影響する安全規則：

- 直接ネイティブ関数は、受理されたネイティブ関数と対応 builtin/標準ライブラリ操作だけを呼び出せます。
- 明示的に mark した呼び出し元が immutable scalar 境界経路を満たす場合を除き、fallback-only コードの呼び出しはネイティブ呼び出し元を拒否します。コンテナは境界を越えず、ループや comprehension 内の境界呼び出しはフォールバックに残ります。
- Python ループからネイティブ関数を呼ぶと、静的な境界診断 `RXT073` が発生します。条件を満たす直接ネイティブ関数だけが wrapper 入口と scalar 境界入口を関数ごとの実行時フォールバック閾値へ加算し、plugin 経路の関数は対象外です。
- `auto` モードでは、ネイティブ import が利用できない場合や閾値による降格時に Python fallback を使い、アナライザーで拒否された関数も fallback に残ります。`fallback` モードはネイティブ実行を明示的に無効化します。`native` モードは昇格済みネイティブコードを必須とし、その import が利用できなければ例外を送出します。`REXTIO_DEBUG_NATIVE=1` はネイティブ読み込み警告を診断用 traceback に変えます。
- `native-shim`/`RXT080` は動的 Python 意味論を守るため PyO3 経由で Python fallback を呼びます。互換経路であり、**Rust 高速化経路ではありません**。
- Rust ownership が挙動を変える可変 collection alias は Python に残します。「変換できそう」という理由だけでネイティブ候補を生成しません。

実行時制御：

```text
REXTIO_NATIVE_MODE=auto|fallback|native
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
REXTIO_DEBUG_NATIVE=1
```

## 対応する直接 Rust コード形状

意図的に狭い直接経路は、次の対応済み組み合わせを扱います。

- scalar `int`、`float`、`bool`、`str`、`bytes`、`None`
- list（入れ子を含む）、固定 tuple、scalar key の固定 dict、限定的な `set[int|bool|str]`、`Optional[T]` / `T | None`
- 型付きローカル、算術、比較、`if`、`while`、対応する `for`/`range`/`enumerate`/`zip`、comprehension、受理済みネイティブ helper
- 限定的な builtin、`math`、文字列/bytes/list method、ログ/出力、`datetime`、`time`、`hashlib.sha256`、`base64.b64encode`

重要な除外も明示されています。`set[float]` と set iteration は CPython の NaN identity/hash 順序を保持できません。`statistics.mean/fmean`、`json.dumps/loads`、`base64.b64decode` に直接ネイティブ経路はありません。ファイル/ネットワーク/データベース/ORM 操作や動的オブジェクト挙動は、フォールバックまたは明示的に mark した互換 shim に残ります。完全なバージョン別境界は[未対応機能](docs/unsupported-features.md)と[機能安定性](docs/stability.md)を参照してください。

## ビルド出力

| 指定 | 結果と境界 |
| --- | --- |
| 既定ビルド | import 互換パッケージ tree、および任意のネイティブコード＋Python fallback wheel。 |
| `--entrypoint=…` | Zipapp。対象には互換 Python が必要で、zipapp 内部からネイティブ extension は import しません。 |
| `--executable-backend=nuitka` | Experimental standalone/onefile 実行ファイル。Nuitka が必要です。任意のサードパーティ依存関係を跨いだクロスプラットフォーム packaging は主張しません。 |
| `--executable-backend=rust` | ネイティブ Rust entrypoint。閉じた call graph は standalone にできます。`python-subprocess` は限定された immutable scalar 呼び出しのみ委譲し CPython が必要、`nuitka-sidecar` は Nuitka が必要です。runtime shim とコンテナ越境は拒否されます。移植可能な process status には exit code `0..255` を推奨します。 |
| `--rust-importable` | 直接 Rust 関数だけを含む Experimental Cargo path dependency crate。fallback、shim、scalar 境界関数は Python-facing のままです。 |

`rextio build` と `generate` は毎回再解析・再生成します。0.1.x に incremental build cache はありません。subprocess hybrid runtime はソースを `<binary>.runtime/` にコピーするため、委譲コードの `__file__` はコピー先を指します。元ファイルからの相対パスでデータを探すコードには別の方法が必要です。

## Plugin、デバイス、外部ソース

Plugin はプロジェクト設定で明示的に有効化する別の Python distribution です。active plugin がないパッケージは既定で保守的に扱います。`try-native` は Experimental な計画ポリシーであり、一般的な依存関係変換の約束ではありません。

Device Provider API 1 の選択も明示的かつ Experimental です。設定だけで CPU-only Torch/TensorFlow 経路が CUDA 対応になることはありません。混在・競合する device domain、provider 不在、未対応 GPU ordinal、誤った capability は fail closed です。Provider preflight は `support_claim: false` を報告し、Core は認証済み CUDA 実行を主張しません。

外部 pure-Python ソース inventory は、正確に 1 つの固定・検証済み depth-1 `py3-none-any` distribution に対する非ビルド preview です。package の import、語彙候補とプロジェクト call の接続、lowering、copy、redistribution、build authorization は行いません。SourceLock 証拠が欠落・無効なら block され、検証済み lock だけでも build/distribution 権限は得られません。

別個の `strict-evidence` **Alpha/Experimental** profile は、macOS arm64 または Linux x86_64 上の CPython 3.11 host-extension build、SourceLock 承認依存関係 1 つ、scalar leaf call、owner-pinned offline input、2 回の隔離 build、外部 Ed25519 signature に固定されています。plugin、実行ファイル、Rust crate、embedding、native top-level 初期化、Windows、広範な package lowering、一般 redistribution は対象外です。sandbox/support lock は owner 管理プロセス内の証拠完全性を守るだけで、secure boot、悪意ある同一 UID プロセスや侵害 OS への防御、一般 hermeticity、registry 認証、cross-platform certification ではありません。

> **法的境界：**依存ソースの変換・再配布には、特に GNU/copyleft 条項のライセンスや派生著作物義務が生じる可能性があります。Rextio の inventory と SourceLock 検査は法的助言や法的承認ではありません。

高度な機能に依存する前に、[host source-AOT とネイティブ実行ファイル](docs/source-aot-and-executables.md)、[Device Provider API 1](docs/specs/device-provider.md)、[tooling contract](docs/specs/tooling-contract.md) を読んでください。

## Numba と Nuitka

認識された `@numba.*` デコレーターは、フォールバック上で **Numba の**意味論を使う明示的な選択であり、Rextio の CPython 等価ネイティブ契約ではありません。`@rextio.native` と併用しないでください。Numba が導入済みなら wheel/zipapp と source-hybrid 経路は動作可能ですが、Nuitka 実行ファイルと Nuitka hybrid dispatcher は、コンパイル済み関数が bytecode を公開せず accelerator も同梱されないため、accelerated function を早期拒否します。どの accelerator でも小さな関数は境界オーバーヘッドで遅くなる可能性があります。

## 例とプロジェクト情報

```bash
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math
```

[`examples/`](examples/) には直接計算、fallback と境界挙動、wheel、zipapp、Nuitka、Numba、Rust 実行ファイル/crate、embedded helper があります。Embedding は Experimental、既定で無効、AOT-only・scalar-only で、ネイティブ呼び出し元から見える monkeypatch 挙動を変えます。実行時 JIT ではありません。

- [セキュリティモデル](SECURITY.md)
- [コントリビューション](CONTRIBUTING.md)
- [バージョニング](docs/versioning.md)
- [変更履歴](CHANGELOG.md)
- [ライセンス](LICENSE) — MIT

作者: Steve Si-young Song · [@RextioDev](https://x.com/RextioDev)
