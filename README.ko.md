# Rextio

[English](README.md) | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md) | [日本語](README.ja.md)

**증명 가능하게 안전한 곳에는 Rust의 속도를. 나머지는 전부 Python으로.
조용히 틀리는 일은 없습니다.**

Rextio 0.1.0은 Python 프로젝트를 위한 alpha 단계 로컬 빌드 도구입니다.
타입이 지정된 Python 함수 중 안전하게 Rust로 낮출 수 있는 것을 찾아
PyO3로 미리(ahead-of-time) 컴파일하고, 나머지는 전부 생성된 Python
fallback 코드로 계속 실행합니다 — import 경로도, 동작도 그대로입니다.

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

## 무엇을 제공하나

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
REXTIO_DISABLE_NATIVE=1
```

빌드된 native 모듈이 로드에 실패할 때 경고 후 fallback하는 대신 전체
traceback을 올리려면 `REXTIO_DEBUG_NATIVE=1`을 설정하세요 — ABI 불일치나
wrapper/codegen 이름 불일치를 디버깅할 때 유용합니다.

## 요구 사항

| 구성요소 | 버전 | 비고 |
| --- | --- | --- |
| CPython | >= 3.11 (3.11-3.14에서 검증) | 분석기는 빌드 인터프리터의 `ast`를 사용하고, 생성 확장은 PyO3 0.29(CPython 3.14까지 지원)를 고정합니다. 더 새로운 인터프리터는 동작할 수 있으나 검증되지 않았습니다. wheel은 빌드 인터프리터의 minor 버전 태그를 답니다. |
| Rust toolchain | MSRV 1.83 (최신 stable에서 검증) | 생성 crate는 edition 2021 + PyO3 0.29를 사용합니다. [rustup](https://rustup.rs)으로 설치하세요. |
| Nuitka (선택) | >= 2.0 | `--fallback=nuitka`/`--executable-backend=nuitka`/`--hybrid-runtime=nuitka` 전용입니다. 앞의 두 경로는 빌드 preflight가 선제 거부하고, hybrid runtime은 위임된 fallback 호출이 실제로 Nuitka dispatcher를 필요로 할 때 검사합니다. |
| Numba (선택, experimental) | 인터프리터에 맞춰: 3.11→>=0.57, 3.12→>=0.59, 3.13→>=0.61, 3.14→>=0.63 | Rextio는 Numba 데코레이터를 인식만 하며, 패키지 자체는 Rextio가 아닌 사용자 프로젝트의 런타임 의존성입니다. 하한은 [Numba 버전 지원 표](https://numba.readthedocs.io/en/stable/user/installing.html#version-support-information)를 따릅니다. |

도구 위치와 버전 pin을 설정할 수 있습니다: `rextio.toml`의 `[toolchain]`
(또는 `REXTIO_*` 환경변수 / CLI 플래그)으로 빌드가 사용할 cargo·maturin·
Nuitka·CPython을 선택하고 버전을 검증할 수 있습니다.
[REXTIO.md](./REXTIO.md#toolchain-selection-and-version-pins) 참고.

## 빠른 예시

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

빌드합니다:

```text
python -m pip install -e .
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

## 일반적인 흐름

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

## 명령어

| 명령 | 하는 일 |
| --- | --- |
| `rextio init` | `rextio.toml`, `REXTIO.md`, `.rextioignore`를 생성합니다. |
| `rextio check` | native 후보를 분석하고 진단을 출력합니다. |
| `rextio generate` | 컴파일 없이 Rust/Python 생성 소스를 작성합니다. |
| `rextio build` | 생성, 컴파일, 패키징 후 빌드 리포트를 작성합니다. |
| `rextio bench` | 한 함수의 Python fallback과 Rust native 시간을 비교합니다. |
| `rextio clean` | `.rextio/build`, `.rextio/generated`, `.rextio/reports`를 제거합니다. |

자주 쓰는 빌드 변형:

```text
rextio build . --fallback=cpython
rextio build . --fallback=nuitka
rextio build . --fallback-threshold=1000
rextio build . --jit
rextio build . --entrypoint=myapp.cli:main
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
rextio build . --rust-importable --rust-crate-name=my_native
```

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
- fallback 전용 코드를 호출하는 native 함수는 native 컴파일에서 거부됩니다.
- Python fallback 코드는 native 함수를 호출할 수 있습니다.
- native 함수를 반복 호출하는 Python 루프는 boundary 경고를 냅니다.
- 생성된 wrapper는 Python→native wrapper 교차가 반복되면 그 함수를 다시
  fallback으로 전환할 수 있습니다.
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

Rextio 0.1.0 alpha는 의도적으로 작은 subset을 지원합니다. 이것이 실제 Rust
속도 향상을 제공할 수 있는 경로입니다.

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
[0.1.0 alpha의 미지원 기능](docs/unsupported-features.md)을 보세요.

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
선택적으로 내장할 수 있습니다. 기본값은 꺼짐입니다. 설정 키 이름이
`[jit]`이지만 이것은 JIT가 아닙니다: 모든 것은 미리 컴파일되고, 빌드된
artifact 안에 JIT 컴파일러는 존재하지도 실행되지도 않습니다.

활성화하면 적격인 비마킹 helper(스칼라 인자와 반환 타입, 단일 산술 반환
식)가 생성 native artifact의 평범한 내부 함수로 컴파일됩니다 — native
코드에서 호출 가능하고 Python으로 export되지 않습니다. 내장된 helper는
일반 checked 경로로 낮춰지므로 정수 overflow는 OverflowError를, 0 나눗셈은
ZeroDivisionError를 다른 native 함수와 똑같이 발생시킵니다. Rust 실행파일
backend에서 내장 helper는 호출마다 CPython dispatcher로 위임되는 대신
바이너리 안으로 컴파일됩니다.

```toml
[jit]
enabled = true
```

동등한 CLI/환경변수 제어:

```text
rextio build . --jit
REXTIO_JIT=true rextio build .
```

## Numba 외부 가속기 (experimental)

Numba 지원은 0.1.0 alpha에서 EXPERIMENTAL입니다: 인식, 리포트, Nuitka 공존
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

내장(embedding)은 생성 Cargo 프로젝트에 crate 의존성을 추가하지 않습니다.
내장이 꺼져 있으면 후보였을 함수는 일반 fallback 경로에 남습니다(그리고
그 native 호출자는 평범한 boundary 규칙의 지배를 받습니다).

## Rust에서 import 가능한 crate

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
함수와 runtime semantics shim은 Python 쪽 경로로 남습니다.

## 실행 artifact

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

0.1.0 alpha에서 구현된 native target은 Rust뿐입니다. `mojo`와 `julia`는
미래 backend를 위한 계획 값으로 받아들여지지만, 해당 backend가 존재할
때까지 코드 생성은 명확하게 실패합니다.

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
구체적인 서드파티 플러그인 변환과 일반 의존성 lowering은 0.1.0 alpha에
번들되지 않습니다. `try-native`는 명시적 계획 정책이며, 안전한 direct
lowering이 없으면 여전히 fallback합니다.

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

## 개발 및 검증

테스트 스위트 실행:

```text
python -m pytest
```

실제 Cargo, Nuitka, 실행파일 테스트는 해당 toolchain이 없으면 건너뜁니다.

전체 개발 환경과 품질 게이트는 [CONTRIBUTING.md](CONTRIBUTING.md)를 보세요.

## 프로젝트 정보

- [기능 안정성](docs/stability.md) — 0.1.0 alpha에서 무엇이 stable이고 무엇이 experimental인지.
- [버전 정책](docs/versioning.md) — pre-1.0 유의점이 있는 SemVer.
- [미지원 기능](docs/unsupported-features.md) — 0.1.0 alpha subset의 경계.
- [보안 모델](SECURITY.md) — 신뢰 경계와 취약점 신고 방법.
- [기여 안내](CONTRIBUTING.md) — 환경 설정, 게이트, 관례.
- [변경 이력](CHANGELOG.md).
