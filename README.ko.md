# Rextio

[English](README.md) | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md) | [日本語](README.ja.md)

**적합한 typed Python 함수는 Rust로 컴파일하고, 나머지는 전부 Python
fallback으로 유지합니다.**

Rextio **0.1.6**은 plugin API **1.6**, tooling contract **2.27.0**, readiness
policy **11**로 2026-07-26 PyPI에 게시된 alpha 단계 로컬 빌드 도구이며
0.1.5를 대체합니다.
타입이 지정된 Python
함수 중 안전하게 Rust로 낮출 수 있는 것을 찾아 PyO3로 미리(ahead-of-time)
컴파일하고, 나머지는 전부 생성된 Python fallback 코드로 계속 실행합니다 —
import 경로도, 동작도 그대로입니다.

<!-- rextio-benchmark:start -->
## 검증된 CPU 벤치마크 스냅샷

동일한 Python 소스와 결정론적 입력; **Mac16,11 / Apple M4 Pro**, **2026-07-26**, CPython **3.11.9**. Mac CPU에서 세 차례 실행했으며, 상단 표의 여섯 workload는 모두 **10% 안정성 veto**를 통과했습니다. 표는 시간순으로 첫 번째 적격 실행을 의도적으로 선택합니다.
버전: 아직 릴리스되지 않은 정확한 Git 후보 rextio 0.1.7@b8b8ed11f6b7, rextio-numpy 0.1.3@cf461e677578, rextio-torch 0.1.3@1e92b24b154c, rextio-tensorflow 0.1.3@1fdb2e1cd91d; 릴리스된 rextio-networkx 0.1.1 및 rextio-pandas 0.1.2.

| 영역 | Python 소스 | Rextio native | 속도비 (소스 ÷ native) |
| --- | ---: | ---: | ---: |
| Core hybrid | 7.988211 ms | 0.138802 ms | 57.729× |
| NumPy mixed fusion | 0.051241 ms | 0.019296 ms | 2.425× |
| NetworkX Dijkstra | 50.836724 ms | 13.651031 ms | 3.719× |
| pandas Series.map | 179.817448 ms | 2.700109 ms | 66.143× |
| PyTorch CPU deep MLP | 0.391130 ms | 0.385014 ms | 1.018× |
| TensorFlow CPU eager chain | 0.648913 ms | 0.622690 ms | 1.040× |

각 수치는 해당 workload의 결과이며 라이브러리 전체 성능이나 BLAS, libtorch, TensorFlow kernel 고유 가속을 뜻하지 않고 CUDA를 주장하지도 않습니다. 빌드, import, 첫 호출, worker 프로세스 시작 시간은 이 steady-state 행에서 제외됩니다. Core 실행 파일은 프로세스 시작을 포함하므로 별도 보고됩니다. 세 번 실행한 중앙값 속도비는 Core 57.729×, NumPy 2.523×, NetworkX 3.679×, pandas 66.143×, Torch 1.017×, TensorFlow 1.040×입니다. NumPy `dot`은 BLAS negative control이며 수동 벡터화한 pandas/NumPy 재작성은 더 빠를 수 있습니다. 1× 미만은 Rextio가 더 느렸다는 뜻이며, 1× 부근의 값은 실질적인 속도 향상이 아니라 성능이 대체로 동등하다는 뜻입니다.

[정식 보고서](https://github.com/rextio/rextio-benchmark/blob/0fed54c64283aaa08dfef0c9973e1d522d52bf1b/results/canonical/cohort-15e2f2527664ea2ed5c36e0c03b054ea6da69d1e476c07934727c252b947ccec/report.md) · [측정 커밋](https://github.com/rextio/rextio-benchmark/commit/92ef027cea25f9d6bf1d730de4c226d40016ba6e) · [증거 커밋](https://github.com/rextio/rextio-benchmark/commit/0fed54c64283aaa08dfef0c9973e1d522d52bf1b)
<!-- rextio-benchmark:end -->

```text
타입이 지정된 Python 프로젝트
  -> 지원되는 native 후보 분석
  -> 안전하지 않거나 미지원인 함수는 거부
  -> 수락된 함수는 Rust + PyO3 생성
  -> 나머지는 Python fallback wrapper 생성
  -> import 호환 artifact 빌드
```

계약은 엄격합니다: 함수는 CPython과 동등한 의미론으로 native 컴파일되거나,
진단과 함께 거부되어 Python fallback에 남습니다. Rextio는 확신이 없으면
추측하지 않고 fallback을 택합니다.

Rextio는 Python을 대체하지 않으며 프로젝트 전체를 Rust로 옮기는 도구도
아닙니다. Native 컴파일은 최적화이고, Python fallback 동작이 정확성의
기준선입니다.

## 빠른 시작

일반 Python 코드에서 시작합니다:

```python
# src/myapp/math_ops.py
def sum_squares(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += x * x
    return total

def format_result(value: int) -> str:
    return f"score={value}"  # direct Rust subset 밖
```

빌드합니다(설치된 사용자 기준; 소스 체크아웃에서는
`python -m pip install -e .`를 대신 사용):

```text
python -m pip install rextio
rextio check .
rextio build . --fallback=cpython
```

Rextio는 `sum_squares`를 Rust로 컴파일하고 `format_result`는 Python
fallback에 남길 수 있습니다. import 경로는 Python 그대로입니다:

```python
from myapp.math_ops import sum_squares, format_result

assert sum_squares([1, 2, 3]) == 14
assert format_result(14) == "score=14"
```

주요 명령어:

| 명령 | 하는 일 |
| --- | --- |
| `rextio init` | `rextio.toml`, `REXTIO.md`, `.rextioignore`를 생성합니다. |
| `rextio check` | native 후보를 분석하고 진단을 출력합니다(구조화된 JSON은 `--format json`). |
| `rextio capabilities` | 기계가 읽을 수 있는 capability manifest를 출력합니다: 지원 타입, 가이드가 딸린 승격 규칙, 활성 플러그인 (experimental). |
| `rextio generate` | 컴파일 없이 Rust/Python 생성 소스를 작성합니다. |
| `rextio build` | 생성, 컴파일, 패키징 후 빌드 리포트를 작성합니다. |
| `rextio bench` | 한 함수의 Python fallback과 Rust native 시간을 비교합니다. |
| `rextio clean` | `.rextio/build`, `.rextio/generated`, `.rextio/reports`를 제거합니다. |

자주 쓰는 빌드 변형:

```text
rextio build . --fallback=cpython
rextio build . --fallback=nuitka
rextio build . --fallback-threshold=1000
rextio build . --embed-helpers
rextio build . --entrypoint=myapp.cli:main
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
rextio build . --rust-importable --rust-crate-name=my_native
```

일반적인 전체 흐름:

```text
rextio init --project-root path/to/project
rextio check path/to/project
rextio generate path/to/project --fallback=cpython
rextio build path/to/project --fallback=cpython
rextio bench myapp.math_ops.sum_squares --project-root path/to/project
rextio clean path/to/project
```

생성 소스만 원하면 `rextio generate`를 사용하세요. Cargo, maturin, Nuitka,
wheel 빌드, 실행파일 패키징은 실행하지 않습니다.

생성 소스에 더해 컴파일/패키징된 산출물까지 원하면 `rextio build`를
사용하세요.

## 요구 사항

| 구성요소 | 버전 | 비고 |
| --- | --- | --- |
| CPython | >= 3.11 (3.11-3.14에서 검증) | 분석기는 빌드 인터프리터의 `ast`를 사용하고, 생성 확장은 PyO3 0.29(CPython 3.14까지 지원)를 고정합니다. 더 새로운 인터프리터는 동작할 수 있으나 검증되지 않았습니다. wheel은 빌드 인터프리터의 minor 버전 태그를 답니다. |
| Rust toolchain | MSRV 1.83 (최신 stable에서 검증) | 생성 crate는 edition 2021 + PyO3 0.29를 사용합니다. [rustup](https://rustup.rs)으로 설치하세요. |
| Nuitka (선택) | >= 2.0 | `--fallback=nuitka`/`--executable-backend=nuitka`/`--hybrid-runtime=nuitka` 전용입니다. 앞의 두 경로는 빌드 preflight가 선제 거부하고, hybrid runtime은 위임된 fallback 호출이 실제로 Nuitka dispatcher를 필요로 할 때 검사합니다. |
| Numba (선택, experimental) | 인터프리터에 맞춰: 3.11→>=0.57, 3.12→>=0.59, 3.13→>=0.61, 3.14→>=0.63 | Rextio는 Numba 데코레이터를 인식만 하며, 패키지 자체는 Rextio가 아닌 사용자 프로젝트의 런타임 의존성입니다. 하한은 [Numba 버전 지원 표](https://numba.readthedocs.io/en/stable/user/installing.html#version-support-information)를 따릅니다. |

도구 위치와 버전 pin을 설정할 수 있습니다: `rextio.toml`의 `[toolchain]`
(또는 `REXTIO_*` 환경변수 / CLI 플래그)으로 빌드가 사용할
cargo·maturin·Nuitka·CPython을 선택하고 버전을 검증할 수 있습니다.
[REXTIO.md](./REXTIO.md#toolchain-selection-and-version-pins) 참고.

## 빌드 target

Rextio는 같은 Python 프로젝트에서 여러 산출물을 만들 수 있습니다:

| 산출물 | 용도 |
| --- | --- |
| `.rextio/generated/rust/` | 수락된 native 함수의 Rust/PyO3 생성 소스. |
| `.rextio/generated/python/` | 생성된 Python wrapper와 fallback 모듈. |
| `.rextio/build/python/` | import 호환 hybrid 패키지 트리. |
| `dist/*.whl` | fallback 코드와 (빌드된 경우) native 확장을 담은 wheel. |
| `dist/<name>.pyz` | 설정된 Python entrypoint용 zipapp 실행파일(선택). |
| `dist/<name>.dist/` 또는 `dist/<name>` | Nuitka standalone/onefile 실행파일(선택). |
| `dist/<name>` | 독립 native Rust 바이너리(`--executable-backend=rust`), Python 런타임 불필요(선택). |
| `dist/<crate>-rust-crate/` | Rust 프로젝트가 import할 수 있는 Rust 라이브러리 crate(선택). |

생성된 Python wrapper는 native 코드를 먼저 시도하고, native가 비활성화되어
있거나, 사용할 수 없거나, 분석에서 거부됐거나, 설정된 boundary threshold를
넘으면 Python으로 fallback합니다.

```text
REXTIO_NATIVE_MODE=fallback
```

빌드된 native 모듈이 로드에 실패할 때 경고 후 fallback하는 대신 전체
traceback을 올리려면 `REXTIO_DEBUG_NATIVE=1`을 설정하세요 — ABI 불일치나
wrapper/codegen 이름 불일치를 디버깅할 때 유용합니다.

Zipapp:

```text
rextio build . --entrypoint=myapp.cli:main --executable-name=myapp
```

`dist/myapp.pyz`가 작성됩니다. 대상 머신에는 여전히 호환되는 Python
인터프리터가 필요합니다. native 확장은 zipapp 내부에서 import되지 않으므로
`_rextio_native`가 없을 때 wrapper는 fallback 동작을 보존합니다.

Nuitka:

```text
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=standalone
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
```

Nuitka 실행파일 패키징은 experimental이며 Nuitka 설치가 필요합니다.

Native Rust 바이너리:

```text
rextio build . --entrypoint=myapp.cli:main --executable-backend=rust
```

`main`이 Rust에서 실행되는 native 바이너리(`dist/<name>`)를 컴파일합니다.
entrypoint는 수락된 direct-native `def main(argv: list[str]) -> int`여야
합니다: `argv`는 `sys.argv`를 반영하고(index 0은 프로그램 경로), 반환된
`int`가 프로세스 exit code이며, 발생한 오류는 CPython 스타일
(`OverflowError: ...`)로 stderr에 출력되고 non-zero로 종료합니다. Cargo가
필요합니다.

entrypoint가 Python fallback에 남는 프로젝트 함수(Rust subset 밖 코드)를
호출하면 Rextio는 그 호출을 외부 CPython 서브프로세스에 위임합니다: 빌드가
`dist/<name>.runtime/` 디렉토리(dispatcher + 프로젝트 소스)를 함께 싣고
바이너리가 stdio로 구동하므로, 컴파일하기 어려운 로직은 Python으로 남길 수
있습니다. 이런 hybrid 바이너리는 런타임에 Python 인터프리터가 필요합니다.
호출 그래프가 전부 direct-native인 바이너리는 Python 의존성이 없는
독립형입니다. 위임 호출의 인자와 결과는 모두 불변 스칼라
(`int`/`float`/`bool`/`str`/`None`)여야 합니다. `list`/`dict`/`set`은 어느
방향으로도 위임되지 않습니다(값으로 wire를 건너며 CPython이 보존하는
aliasing이 끊겨, 변경된 인자나 변경된 aliased 반환이 조용히 어긋나게 됨).
비유한 float(`NaN`/`Infinity`)는 조용히 소실되는 대신 거부됩니다. 위임된
함수 자신의 stdout/stderr는 바이너리의 stderr에 나타납니다(바이너리의
stdout은 wire 프로토콜 전용). RXT080 runtime shim 위의 함수는 위임되지
않습니다: 그것에 의존하는 entry는 빌드되지 않고 거부됩니다.

`--executable-python`은 바이너리가 실행할 인터프리터를 고정합니다(`PATH`의
이름, 절대 경로, 또는 번들을 위한 `<binary>.runtime` 상대 경로).
`REXTIO_RUNTIME_PYTHON`은 대상 머신에서 실행 시점에 이를 재정의합니다.
`--hybrid-runtime=nuitka`는 위임되는 Python을 runtime 디렉토리에 실리는
자체 완결 dispatcher 실행파일로 컴파일해, hybrid 바이너리가 별도 Python
설치를 필요로 하지 않게 합니다(빌드 시 Nuitka 필요).

direct Rust 함수를 Rust 애플리케이션에서 쓰고 싶으면 추가 Cargo 라이브러리
crate를 빌드하세요:

```text
rextio build . --rust-importable --rust-crate-name=my_native
```

Rust에서 생성 crate 사용:

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

이 crate로는 직접 타입 Rust로 낮춰진 함수만 export됩니다. fallback 전용
함수, runtime semantics shim, 그리고 스칼라 boundary call을 쓰는 함수
(둘 다 인터프리터가 필요)는 Python 쪽 경로로 남습니다.

## 설정

빌드/분석 설정은 다음 순서로 해석됩니다:

```text
CLI 파라미터 > 환경변수 > rextio.toml > 내장 기본값
```

주요 설정:

| `rextio.toml` 키 | CLI 파라미터 | 환경변수 |
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
| `[toolchain] *_version` pin | `--cargo-version` 등 | `REXTIO_CARGO_VERSION` 등 |
| `[policy] native_marker` | `--native-marker` | `REXTIO_NATIVE_MARKER` |
| `[policy] boundary_warnings` | `--boundary-warnings` / `--no-boundary-warnings` | `REXTIO_BOUNDARY_WARNINGS` |
| `[policy] native_top_level` | `--native-top-level` / `--no-native-top-level` | `REXTIO_NATIVE_TOP_LEVEL` |

0.1.6에서 구현된 native target은 Rust뿐입니다.

Rextio 플러그인은 `pip`이나 `uv` 같은 도구로 설치하는 평범한 Python
패키지입니다. 플러그인 패키지는 자신이 다루는 Python 패키지 이름을 포함한
메타데이터를 `rextio.plugins` entry point 그룹으로 노출합니다. 프로젝트는
`[plugins] enabled` 또는 `--enable-plugin`으로 특정 플러그인 id를
활성화합니다.

활성 Rextio 플러그인이 없는 외부 Python 패키지는 기본적으로 보수적으로
다룹니다: Rextio는 서드파티 패키지 소스를 조용히 Rust로 번역하지 않습니다.
그런 패키지 호출은 플러그인을 추가하거나, 알려진 순수 Python 패키지에 대해
실험적 의존성 분석을 명시적으로 opt-in하지 않는 한 주변 native 후보를
fallback에 남깁니다:

```toml
[imports]
default_external_policy = "fallback"

[imports.packages]
"some_pure_python_pkg" = { policy = "try-native", max_depth = 1 }
"legacy_dynamic_pkg" = "fallback"
"known_pkg" = { policy = "plugin", plugin = "known-rust" }
```

지원되는 패키지 정책은 `fallback`, `analyze`, `try-native`, `plugin`입니다.
0.1.1부터 플러그인은 자신이 커버하는 구문을 기술하고 직접 *lowering*할
수도 있습니다(plugin API 1.1 —
[plugin lowering 스펙](docs/specs/plugin-lowering.md) 참고). 0.1.2는
하위 호환 plugin API **1.2**(정적 리터럴/순서 있는 키워드 메타데이터,
구조화 `ClaimExpr` 트리, leaves 모드 lowering)를 추가합니다. first-party
[rextio-numpy](https://github.com/rextio/rextio-numpy) 플러그인은 별도로
설치합니다(core는 역의존하지 않음): **PyPI 0.1.1**이 게시된
literal-axis/fusion 확장 버전이며 **core >= 0.1.2**가 필요합니다(초기 인증
float64 1-D 표면은 0.1.0). 관련 패키지는 **엄격한 게시 순서**
rextio-lsp 0.1.1 → core 0.1.2 → rextio-numpy 0.1.1로 게시되었습니다([tooling
contract](docs/specs/tooling-contract.md) 참고). Core **0.1.3**은 plugin API
1.3과 tooling contract **2.1.0**(core 0.1.2가 내보낸 **2.0.0** 형태 위의
additive; dual-map `2.x` 소비자는 호환)으로 2026-07-17에 게시되었습니다.
Core **0.1.4**는 rextio-lsp 0.1.2가 먼저 게시된 후 2026-07-18에 게시되어
엄격한 consumer-first 순서로 Release Train B를 완료했습니다. plugin API
1.3을 유지하고 tooling contract **2.2.0**을 내보내며, legacy
route/status/rejection 의미는 바꾸지 않으면서 분리된 승격 판정, 신뢰된
marker 의도, 함수/이름 range를 추가합니다.
Core **0.1.5**는 plugin API **1.4**, tooling contract **2.24.0**, readiness
policy **11**로 2026-07-23 게시되었습니다. Train C의 host source-AOT,
실행 파일, 제한된 Full-C6/C5.2 표면은 계속 Experimental/Alpha입니다.
Core **0.1.6**은 plugin API **1.6**, tooling contract **2.27.0**으로
2026-07-26 게시되었습니다. 제한된 plugin 비교식, Device Provider API 1
선택·preflight·빌드 연결, 정적 device-domain lowering 승인을 추가하지만
Core 자체가 CUDA framework 지원이나 가속기 실행 인증을 주장하지는 않습니다.
일반 의존성 lowering은 번들되지 않습니다. `try-native`는 명시적 계획
정책이며, 안전한 direct lowering이 없으면 여전히 fallback합니다.

## Native 선택 방식

기본값은 자동 native 탐색입니다:

```toml
[policy]
native_marker = "auto"
```

이 모드에서 Rextio는 타입을 해석할 수 있고 지원되는 direct Rust subset에
맞는 모듈 레벨 함수를 native 후보로 취급할 수 있습니다.

명시적 마커를 요구할 수도 있습니다:

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

미래의 multi-target 지원을 위해 마커에 대상(target)을 고정할 수 있습니다:

```python
@rextio.native(target="rust")
def score(x: float) -> float:
    return x * 2.0
```

함수를 반드시 Python fallback에 남겨야 하면 `@rextio.exempt`를 사용하세요:

```python
@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1
```

exempt 함수는 생성 Rust에 결코 포함되지 않습니다. native 후보가 exempt
또는 fallback 전용 함수를 호출하면 그 후보도 fallback으로 내려갑니다.

## 안전 모델

Rextio는 native 컴파일을 보수적으로 유지합니다:

- direct Rust native 함수는 수락된 native 함수, 지원되는 builtin, 지원되는
  표준 라이브러리 함수만 호출할 수 있습니다.
- fallback 전용 코드를 호출하는 native 함수는 거부됩니다 — 단, 호출자가
  명시적으로 마킹돼 있고 callee의 시그니처가 처음부터 끝까지 불변 스칼라
  (`int`/`float`/`bool`/`str`/`None`)라면 그 호출은 in-process 스칼라
  boundary call(`RXT075`)이 됩니다. callee는 인터프리터에서 계속 실행되므로
  값과 예외가 CPython-정확하고 monkeypatch도 반영됩니다. 스칼라는 값으로
  건너가므로 인자의 identity(`is`)는 보존되지 않습니다(`None`/`bool`
  싱글턴은 보존됩니다). 컨테이너는 경계를 넘지 않으며, comprehension 본문을
  포함한 native 루프 안의 boundary call은 호출자를 fallback에
  남깁니다(`RXT076`).
- Python fallback 코드는 native 함수를 호출할 수 있습니다.
- native 함수를 반복 호출하는 Python 루프는 boundary 경고를 냅니다.
- 생성된 wrapper는 경계 교차가 반복되면 그 함수를 다시 fallback으로
  전환할 수 있습니다 — Python→native wrapper 진입과 native 스칼라 boundary
  call이 같은 함수별 threshold에 함께 계상됩니다.
- Python/Rust의 소유권 차이는 명시적으로 다룹니다. 소유 값의 읽기 전용
  재사용은 필요 시 Rust clone으로 낮추고, 가변 컬렉션의 alias mutation은
  Python fallback에 남습니다.

boundary fallback은 다음으로 제어합니다:

```text
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
REXTIO_NATIVE_MODE=auto|fallback|native
```

## 지원하는 direct Rust subset

Rextio 0.1.6은 의도적으로 작은 subset을 지원합니다. 이 subset이
native Rust로 실행되는 코드입니다.

지원 타입:

- `int`, `float`, `bool`, `str`, `bytes`, `None`
- 지원되는 item 타입의 `list[T]` (`list[list[T]]` 포함)
- 고정 `tuple[...]`
- key가 지원되는 스칼라 key 타입인 고정 `dict[K, V]`
- 제한적 `set[int]`, `set[bool]`, `set[str]` (`set[float]`는 Python
  fallback에 남습니다: NaN-identity 중복 제거에는 충실한 Rust lowering이
  없고, native 코드는 set을 *순회*하지도 않습니다 — 해시 순서가 CPython과
  다릅니다)
- `Optional[T]`, `T | None`

지원 구문:

- 지역 대입과 타입 주석이 있는 지역 변수
- 산술, 불리언 연산, 비교, `if`, `while`
- `for x in xs`
- 지원되는 루프/컴프리헨션 형태의 `range(...)`, `enumerate(xs)`, `zip(xs, ys)`
- `break`, `continue`, `return`
- 제한된 실험적 `try`/`except`/`finally` 부분집합(내장 예외 핸들러만;
  [안정성 계층](docs/stability.md) 참조)
- 지원되는 형태의 list/dict/set 컴프리헨션
- 제한적 `list.append`, dict 읽기/쓰기, 인덱싱
- 수락된 native helper 함수 호출

builtin·표준 라이브러리 lowering(제한적 형태):

- `len`, `abs`, `min`, `max`, `sum`, `all`, `any`, `sorted`, `reversed`
- 일부 `math` 함수와 상수
- 일부 `str`, `bytes`, `list` 메서드
- `print`, `logging.debug/info/warning/error`
- `datetime`, `time`, `hashlib.sha256`, `base64.b64encode`
  (`statistics.mean`/`fmean`, `json.dumps`/`json.loads`,
  `base64.b64decode`는 충실한 direct-native 등가물이 없습니다: 명시적으로
  마킹된 함수는 RXT080 runtime shim을 타고, 자동 탐색된 함수는 Python
  fallback에 남습니다)

미지원이거나 모호한 코드는 fallback에 남거나, 지원되는 경우 Python runtime
semantics shim으로 노출됩니다. 자세한 경계는
[0.1.0의 미지원 기능](docs/unsupported-features.md)을 보세요.

## Rextio 친화적인 Python 작성법

native 승격과 boundary 동작은 코드의 모양에서 그대로 결정됩니다. Rextio를
최대한 활용하려면:

- 핫 함수는 끝까지 annotate하세요 - 매개변수와 반환 타입을 지원되는
  scalar/list 타입으로. 타입이 해석되지 않는 함수는 fallback에 남습니다.
- 핫 경로는 지원 subset 안에 두고 `rextio check`를 일찍 돌리세요. 모든
  거부에는 원인이 된 구문이 명시됩니다.
- 루프를 native 안으로 옮기세요: native 함수를 호출하는 Python 루프는
  반복마다 경계를 넘지만(boundary 경고), 내부에서 루프를 도는 native
  함수는 호출당 한 번만 넘습니다.
- native 호출 그래프는 native로 유지하세요: native-to-native 호출은 Rust
  안에 머뭅니다. fallback 전용 helper 호출은 호출자를 거부시키거나,
  호출마다 발생하며 강등 threshold에 누적되는 scalar boundary call이
  됩니다.
- boundary call은 루프와 comprehension 본문 밖에 두세요(`RXT076`).
  밖으로 끌어올리거나, callee가 subset에 맞으면 `@rextio.native`로
  마킹하세요.
- 경계는 불변 스칼라로 건너세요. 컨테이너는 경계를 넘지 않습니다.
- Python에 남아야 하는 함수는 `@rextio.exempt`로 표시하고, 혼합 함수는
  typed 핫 코어가 별도 함수가 되도록 분리하세요.
- `rextio bench`로 측정하세요: 아주 작은 함수는 호출 오버헤드에 질 수
  있으므로 native 호출 한 번에 충분한 작업을 몰아넣으세요.

## Python runtime semantics shim

일부 Python 기능은 타입이 있는 Rust 문장으로 안전하게 번역할 수 없습니다.
명시적으로 마킹된 native 코드에 대해 Rextio는 생성된 Python fallback 구현을
대신 호출하는 PyO3 shim을 생성할 수 있습니다.

이 호환 경로는 class/객체 동작, 인스턴스 메서드, 예외, 컨텍스트 매니저,
`async`/`await`, 제너레이터, 동적 속성 접근 같은 기능을 보존할 수 있습니다.
`RXT080`으로 보고됩니다.

이 경로는 동작을 보존합니다. Rust 속도 향상 경로로 취급하면 안 됩니다.

## 실험적 scalar helper 내장(embedding)

Rextio는 마킹되지 않은 아주 좁은 범위의 스칼라 helper를 내부 native 함수로
선택적으로 내장할 수 있습니다 — 다른 모든 것과 마찬가지로 미리(ahead-of-
time) 컴파일됩니다. 기본값은 꺼짐입니다.

활성화하면 적격인 비마킹 helper(스칼라 인자와 반환 타입, 단일 산술 반환
식)가 생성 native artifact의 평범한 내부 함수로 컴파일됩니다 — native
코드에서 호출 가능하고 Python으로 export되지 않습니다. 내장된 helper는
일반 checked 경로로 낮춰지므로 정수 overflow는 OverflowError를, 0 나눗셈은
ZeroDivisionError를 다른 native 함수와 똑같이 발생시킵니다. Rust 실행파일
backend에서 내장 helper는 호출마다 CPython dispatcher로 위임되는 대신
바이너리 안으로 컴파일됩니다.

```toml
[embedding]
enabled = true
```

동등한 CLI/환경변수 제어:

```text
rextio build . --embed-helpers
REXTIO_EMBED_HELPERS=true rextio build .
```

내장(embedding)은 생성 Cargo 프로젝트에 crate 의존성을 추가하지 않습니다.
내장이 꺼져 있어도 적격 helper 호출은 런타임 스칼라 boundary call로 여전히
동작합니다 — 내장은 호출마다의 인터프리터 왕복을 제거하는 빠른 경로입니다.
boundary call과 달리 내장된 helper는 빌드 시점에 native 산출물로 컴파일된
사본이므로, helper의 런타임 교체(monkeypatch)는 native 호출자에게 보이지
않습니다.

## Numba 외부 가속기 (experimental)

Numba 지원은 0.1.0에서 EXPERIMENTAL입니다: 인식, 리포트, Nuitka 공존
동작은 첫 non-alpha 릴리스 전에 바뀔 수 있습니다. Rextio는 Numba 데코레이터
(`numba.jit`, `numba.njit`, `numba.vectorize`, `numba.guvectorize`)를 Python
fallback 코드용 외부 가속기(experimental)로 인식합니다 — Nuitka 패키징
backend와 같은 "외부에서 지원되는 도구" 패턴입니다. 데코레이트된 함수는
Python fallback에 깔끔하게 남고(자동 탐색과 helper 내장에서 제외), 리포트에
`external_accelerator: numba`로 표시되며 `rextio check`가 그런 함수를
나열합니다. 인식은 모듈의 import를 통해 해석됩니다(attribute, from-import,
별칭, 호출 형태; `numba.cuda.jit` 포함). `rextio check`의 리포트 라벨은
직선적 import만 다루고, Nuitka 빌드 시 스캔은 더 넓습니다(star import,
선택적 의존성 가드, 함수 안의 지연 import) — 따라서 함수에 라벨이 없어도
빌드는 모듈을 올바르게 plain으로 유지할 수 있습니다.

계약 경계가 중요합니다: `@rextio.native` 함수는 Rextio가 검증한
CPython-정확 의미론을 갖지만, `@numba.*` 함수는 **Numba의** 의미론으로
실행됩니다(예: nopython 모드 정수 산술은 overflow 시 예외 대신 wrap) — 그
트레이드는 사용자의 명시적 opt-in이며 `@rextio.exempt`처럼 Rextio native
계약 밖입니다. `@rextio.native`와 numba 데코레이터의 조합은 요란하게
거부됩니다.

호환성: wheel과 zipapp 배포는 numba를 프로젝트 의존성으로 설치하면
동작합니다. Rust 실행파일의 source 모드 hybrid runtime도 동작합니다
(dispatcher가 진짜 CPython을 실행). `--fallback=nuitka` backend는 자동으로
공존합니다: 인식된 외부 가속기를 쓰는 모듈은 plain Python으로 유지되고
(`.py`가 계속 import됨) 트리의 나머지는 Nuitka로 컴파일되며, 빌드 리포트가
그 목록을 담습니다. 생성된 wheel은 Nuitka 컴파일 모듈을 확장으로만 싣고 —
가려진 `.py` 소스는 제외(죽은 무게이자 소스 노출) — 플랫폼 태그를 답니다.
가속 모듈은 `.py`를 유지합니다. Nuitka *실행파일*
(`--executable-backend=nuitka`)과 `--hybrid-runtime=nuitka` dispatcher는
가속 함수를 서비스할 수 없어(컴파일된 함수는 바이트코드를 노출하지 않고
가속기는 번들되지 않음) 첫 호출에서 죽는 대신 안내와 함께 일찍 실패합니다.
타입이 있는 스칼라 코드에는 `@rextio.native`를, NumPy/배열 커널에는 Numba를
권하며, 아주 작은 함수는 어떤 가속기에서도 호출 경계 비용에 지는 점을
유의하세요.

first-party [rextio-numpy](https://github.com/rextio/rextio-numpy)
플러그인은 커버된 NumPy를 AOT 컴파일된 native Rust로 변환합니다. **게시된
rextio-numpy 0.1.1**은 초기 0.1.0의 인증 float64 1-D 표면을 F64/F32/I64
rank-1/rank-2 broadcasting, literal-axis reduction, 2–8-op 원소별 fusion으로
확장합니다. core plugin API 1.2(**core >= 0.1.2**)를 사용하며 rank-2
`dot`/matmul은 계속 fallback입니다. dual-map **rextio-lsp 0.1.1** →
**core 0.1.2** → **rextio-numpy 0.1.1**의 필수 게시 순서는 2026-07-14에
완료됐습니다. 따라서 NumPy 코드에는 두 가지 경로(커버된
표면에 대한 Rextio plugin AOT 컴파일, 또는 Python fallback 안의 Numba
JIT)가 있습니다. 둘 다 적용될 수 있으면 명시적 `@numba.*` 데코레이터가
우선하며 analyzer가 정보성 RXT091 노트를 내보냅니다. 경로 선택에 대한 더
넓은 가이드는 플러그인 표면이 커지면서 구체화될 예정입니다.

## 예제

```text
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math

rextio check examples/boundary_demo
rextio build examples/fallback_demo --entrypoint=fallback_demo.run_demo:main
```

예제 프로젝트:

- `examples/pure_math`: 타입이 있는 수학 hot path의 direct Rust lowering.
- `examples/fallback_demo`: native가 꺼져 있거나 없을 때의 fallback 동작.
- `examples/boundary_demo`: native→fallback boundary 거부와 경고.
- `examples/app_shell`: 애플리케이션 shell은 Python으로 두고 스코어링 hot
  path만 native가 될 수 있는 구성.
- `examples/wheel_package`: 기본 hybrid wheel을 신선한 환경에 설치해
  동일한 import로 사용하는 예.
- `examples/nuitka_fallback`: Nuitka로 컴파일된 fallback을 담은 hybrid wheel.
- `examples/numba_accelerator`: Rextio native와 Numba-JIT NumPy 커널의 병행.
- `examples/nuitka_numba`: Rust native + Nuitka fallback + plain Python으로
  유지되는 Numba 모듈을 한 빌드에.
- `examples/zipapp_app`: 단일 파일 `.pyz` 실행파일.
- `examples/nuitka_executable`: onefile Nuitka 실행파일.
- `examples/rust_executable`: 독립 native Rust 바이너리.
- `examples/rust_crate`: Rust 호출자를 위한 Cargo 라이브러리 crate.
- `examples/embedding_helpers`: scalar boundary call과 내장 helper의 대비.

## 개발 및 검증

테스트 스위트 실행:

```text
python -m pytest
```

실제 Cargo, Nuitka, 실행파일 테스트는 해당 toolchain이 없으면 건너뜁니다.

전체 개발 환경과 품질 게이트는 [CONTRIBUTING.md](CONTRIBUTING.md)를 보세요.

## 향후 계획

약속이 아닌 계획이며, alpha 피드백에 따라 우선순위가 바뀔 수 있습니다:

1. 안정화 우선: 표면을 키우기 전에 실제 사용을 바탕으로 0.1.0
   표면을 다집니다.
2. 코딩 에이전트에게 Rextio 친화적인 Python 작성법을 알려 주는 agentic
   coding용 skill/plugin.
3. 편집 중인 코드가 지원 native subset에 맞는지 화면에서 바로 보여 주는
   VS Code 확장.
4. Rextio plugin - 특정 패키지를 사용하는 Python 코드를 Rust와 fallback
   코드로 변환하는 규칙을 정의하는 플러그인입니다. NumPy를 시작으로 자주
   쓰이는 수치 계산·AI 패키지를 대상으로 자체 플러그인을 직접 개발할
   계획이며, plugin 표면이 안정화되면 누구나 Rextio plugin을 만들어
   배포할 수 있게 됩니다.
5. 장기적으로 Rust 외의 native target backend를 늘릴 가능성이 있으나,
   아직 구체적인 계획은 없습니다.

## 프로젝트 정보

- [기능 안정성](docs/stability.md) — 0.1.0에서 무엇이 stable이고 무엇이 experimental인지.
- [버전 정책](docs/versioning.md) — pre-1.0 유의점이 있는 SemVer.
- [미지원 기능](docs/unsupported-features.md) — 0.1.0 subset의 경계.
- [보안 모델](SECURITY.md) — 신뢰 경계와 취약점 신고 방법.
- [기여 안내](CONTRIBUTING.md) — 환경 설정, 게이트, 관례.
- [변경 이력](CHANGELOG.md).
- 개발자: 송시영 <rextio.co@gmail.com> — X (Twitter): [@RextioDev](https://x.com/RextioDev).
