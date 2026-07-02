# Rextio

[English](README.md) | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md) | [日本語](README.ja.md)

Rextio 0.1.0은 alpha 단계의 로컬 Python 빌드 도구입니다.

Rextio는 Rust로 안전하게 낮출 수 있는 Python 함수를 찾아 ahead-of-time으로 컴파일하고,
나머지 코드는 Python fallback으로 계속 실행되게 만듭니다.

```text
typed Python project
  -> native 후보 분석
  -> 지원하지 않거나 안전하지 않은 함수 거부
  -> accepted 함수는 Rust + PyO3 생성
  -> 나머지는 Python fallback wrapper 생성
  -> import 가능한 hybrid artifact 빌드
```

Rextio는 Python 대체 언어도 아니고, 전체 프로젝트를 Rust로 이주하는 도구도 아닙니다.
Native 컴파일은 최적화이며, Python fallback 동작이 correctness baseline입니다.

## 무엇을 제공하나

Rextio는 같은 Python 프로젝트에서 여러 산출물을 만들 수 있습니다.

| 산출물 | 용도 |
| --- | --- |
| `.rextio/generated/rust/` | accepted native 함수용 Rust/PyO3 소스 |
| `.rextio/generated/python/` | Python wrapper와 fallback module |
| `.rextio/build/python/` | import 가능한 hybrid package tree |
| `dist/*.whl` | fallback 코드와 native extension을 담은 wheel |
| `dist/<name>.pyz` | Python entrypoint용 zipapp 실행 artifact |
| `dist/<name>.dist/` 또는 `dist/<name>` | Nuitka standalone/onefile 실행 artifact |
| `dist/<crate>-rust-crate/` | Rust 프로젝트에서 path dependency로 쓸 수 있는 crate |

생성된 Python wrapper는 native가 가능하면 native를 먼저 사용하고, native가 비활성화되었거나,
로드되지 않았거나, 분석에서 거부되었거나, boundary threshold를 넘으면 Python fallback을
사용합니다.

```text
REXTIO_DISABLE_NATIVE=1
```

## 빠른 예시

일반 Python 코드에서 시작합니다.

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

빌드합니다.

```text
python -m pip install -e .
rextio check .
rextio build . --fallback=cpython
```

Rextio는 `sum_squares`를 Rust로 컴파일할 수 있고, `format_result`는 Python fallback으로
유지합니다. import 경로는 Python 기준으로 유지됩니다.

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

`rextio generate`는 생성 소스만 필요할 때 사용합니다. Cargo, maturin, Nuitka, wheel 빌드,
실행 artifact 패키징을 실행하지 않습니다.

`rextio build`는 생성 소스와 컴파일/패키징 가능한 artifact가 필요할 때 사용합니다.

## 명령어

| 명령 | 역할 |
| --- | --- |
| `rextio init` | `rextio.toml`, `REXTIO.md`, `.rextioignore` 생성 |
| `rextio check` | native 후보 분석 및 diagnostic 출력 |
| `rextio generate` | 컴파일 없이 Rust/Python 생성 소스 작성 |
| `rextio build` | 생성, 컴파일, 패키징, build report 작성 |
| `rextio bench` | 특정 함수의 Python fallback/Rust native 실행 시간 비교 |
| `rextio clean` | `.rextio/build`, `.rextio/generated`, `.rextio/reports` 삭제 |

자주 쓰는 build 형태:

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

기본값은 자동 native discovery입니다.

```toml
[policy]
native_marker = "auto"
```

이 모드에서는 타입이 해결되고 direct Rust subset에 맞는 module-level 함수를 Rextio가 native
후보로 볼 수 있습니다.

명시적 marker만 사용하게 만들 수도 있습니다.

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

향후 다중 target을 고려해 target을 지정할 수도 있습니다.

```python
@rextio.native(target="rust")
def score(x: float) -> float:
    return x * 2.0
```

반대로 반드시 Python fallback에 남겨야 하는 함수에는 `@rextio.exempt`를 사용합니다.

```python
@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1
```

exempt 함수는 생성 Rust에 절대 포함되지 않습니다. native 후보가 exempt 함수나 fallback-only
함수를 호출하면 그 native 후보도 fallback됩니다.

## 안전 모델

Rextio는 native 컴파일을 보수적으로 적용합니다.

- direct Rust native 함수는 accepted native 함수, 지원 builtin, 지원 표준 라이브러리 함수만
  호출할 수 있습니다.
- fallback-only 코드를 호출하는 native 함수는 native 컴파일에서 거부됩니다.
- Python fallback 코드는 native 함수를 호출할 수 있습니다.
- Python loop가 native 함수를 반복 호출하면 boundary warning을 냅니다.
- 생성 wrapper는 Python-to-native wrapper crossing이 임계값을 넘으면 해당 함수를 fallback으로
  전환할 수 있습니다.
- Python/Rust ownership 차이는 명시적으로 다룹니다. read-only owned value 재사용은 필요한
  경우 Rust clone으로 낮추고, mutable collection alias mutation은 Python fallback에 남깁니다.

Boundary fallback 관련 런타임 설정:

```text
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
REXTIO_NATIVE_MODE=auto|fallback|native
```

## 지원하는 direct Rust subset

Rextio 0.1.0 alpha는 의도적으로 작은 subset만 지원합니다. 실제 Rust speedup을 기대할 수 있는
경로는 이 direct Rust lowering 경로입니다.

지원 타입:

- `int`, `float`, `bool`, `str`, `bytes`, `None`
- 지원 item 타입의 `list[T]`, `list[list[T]]`
- fixed `tuple[...]`
- key/value가 지원 타입인 fixed `dict[K, V]`
- 제한적 `set[int]`, `set[bool]`, `set[str]` (`set[float]`은 NaN identity 때문에
  native lowering이 없어 Python fallback/shim에 남으며, set을 *순회*하는 코드는
  해시 순서가 CPython과 달라 거부됩니다)
- `Optional[T]`, `T | None`

지원 문법:

- local assignment와 typed local annotation
- 산술, boolean operation, 비교, `if`, `while`
- `for x in xs`
- 지원 loop/comprehension 형태의 `range(...)`, `enumerate(xs)`, `zip(xs, ys)`
- `break`, `continue`, `return`
- 지원 형태의 list/dict/set comprehension
- 제한적 `list.append`, dict read/write, indexing
- accepted native helper 호출

제한적으로 낮추는 builtin/표준 라이브러리:

- `len`, `abs`, `min`, `max`, `sum`, `all`, `any`, `sorted`, `reversed`
- 일부 `math` 함수와 상수
- 일부 `str`, `bytes`, `list` method
- `print`, `logging.debug/info/warning/error`
- `datetime`, `time`, `statistics`, `hashlib.sha256`, `base64`, `json`

지원하지 않거나 모호한 코드는 fallback에 남거나, 지원되는 경우 Python runtime semantics shim을
통해 보존됩니다. 자세한 경계는
[0.1.0 alpha에서 지원하지 않는 기능](docs/unsupported-features.md)을 참고하세요.

## Python runtime semantics shim

일부 Python 기능은 typed Rust statement로 안전하게 변환하기 어렵습니다. 명시적으로 native
표시된 코드에 대해 Rextio는 생성된 Python fallback 구현을 호출하는 PyO3 shim을 만들 수
있습니다.

이 compatibility 경로는 class/object 동작, instance method, exception, context manager,
`async`/`await`, generator, dynamic attribute access 같은 기능의 동작 보존에 사용됩니다.
이 경우 `RXT080`이 보고됩니다.

이 경로는 동작 보존용입니다. Rust speedup 경로로 보면 안 됩니다.

## 실험적 scalar helper 내장(embedding)

Rextio는 아주 좁은 scalar helper(타입이 확정된 단일 산술 return 식의 unmarked 함수)를
native 함수 내부에 AOT로 내장할 수 있습니다. 기본값은 꺼짐입니다.

```toml
[jit]
enabled = true
```

동일한 설정은 `rextio build . --jit` 또는 `REXTIO_JIT=true`로도 지정할 수 있습니다.
내장된 helper는 일반 checked 경로로 컴파일되어 overflow는 OverflowError를,
0으로 나누기는 ZeroDivisionError를 정상적으로 raise하며, PyO3 함수로 export되지
않습니다. 런타임 컴파일은 없습니다. (과거의 Cranelift 런타임 JIT와 `backend`/
`hot_threshold` 설정은 벤치마크 결과 AOT 경로보다 항상 느려 제거되었고, 제거된
환경변수는 마이그레이션 안내와 함께 즉시 오류를 냅니다.)

## Numba 외부 가속기

`numba.jit`/`njit`/`vectorize`/`guvectorize`/`cuda.jit` 데코레이터가 붙은 함수는
의도적으로 Python fallback에 남고(진단 소음 없음) 리포트에
`external_accelerator: numba`로 표시됩니다. 이런 함수는 Numba의 시맨틱(예: nopython
모드 int overflow는 wrap)으로 실행되며 Rextio의 CPython-정확 계약 밖입니다 —
`@rextio.exempt`와 같은 opt-in 철학입니다. `--fallback=nuitka`는 자동으로
공존합니다: 가속기를 쓰는 모듈은 컴파일에서 제외되어 plain `.py`로 남고, wheel은
Nuitka로 컴파일된 모듈의 `.py` 원본을 제외한 채 플랫폼 태그를 답니다. Nuitka
*실행 파일*과 `--hybrid-runtime=nuitka`는 가속 모듈이 있으면 안내 메시지와 함께
조기 실패합니다(`--hybrid-runtime=source` 사용). 빌드 타임 스캔은 리포트
라벨보다 범위가 넓습니다: `rextio check` 라벨은 직선적 import만 다루므로,
라벨이 없는 함수의 모듈도 빌드에서는 정확히 plain으로 유지될 수 있습니다.

## Rust에서 import 가능한 crate

direct Rust 함수가 Rust 애플리케이션에서도 필요하면 Cargo library crate를 추가로 만들 수
있습니다.

```text
rextio build . --rust-importable --rust-crate-name=my_native
```

Rust 프로젝트에서 path dependency로 사용합니다.

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

이 crate에는 typed Rust로 직접 lowering된 함수만 export됩니다. fallback-only 함수와 runtime
semantics shim은 Python-facing 경로로 남습니다.

## 실행 artifact

Zipapp:

```text
rextio build . --entrypoint=myapp.cli:main --executable-name=myapp
```

`dist/myapp.pyz`를 생성합니다. 대상 머신에는 호환되는 Python interpreter가 필요합니다.
Native extension은 zipapp 내부에서 직접 import되지 않으므로, `_rextio_native`를 사용할 수
없으면 wrapper가 fallback 동작을 유지합니다.

Nuitka:

```text
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=standalone
rextio build . --entrypoint=myapp.cli:main --executable-backend=nuitka --nuitka-mode=onefile
```

Nuitka 실행 artifact 패키징은 실험적이며 Nuitka 설치가 필요합니다.

## 설정

빌드 및 분석 설정은 다음 우선순위로 해석됩니다.

```text
CLI parameter > environment variable > rextio.toml > built-in default
```

주요 설정:

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

0.1.0 alpha에서 구현된 native target은 Rust뿐입니다. `mojo`와 `julia`는 향후 backend를 위한
planning 값으로 받을 수 있지만, 해당 codegen backend가 생기기 전까지는 명확히 실패합니다.

Rextio plugin은 `pip`나 `uv`로 설치하는 일반 Python package이며, `rextio.plugins`
entry point group으로 metadata를 노출합니다. 프로젝트는 `[plugins] enabled` 또는
`--enable-plugin`으로 사용할 plugin id를 명시합니다. plugin이 없는 외부 Python package는
기본적으로 fallback입니다. 특정 pure-Python dependency를 명시적으로 허용하려면
`[imports.packages]` 또는 `--package-import-policy`로 `try-native`를 지정할 수 있지만,
안전한 direct lowering이 없으면 Rextio는 계속 fallback으로 둡니다. 구체적인 외부 패키지
plugin 변환은 0.1.0 alpha에 번들되어 있지 않습니다.

## 예제

```text
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math

rextio check examples/boundary_demo
rextio build examples/fallback_demo --entrypoint=fallback_demo.run_demo:main
```

예제 프로젝트:

- `examples/pure_math`: typed math hot path의 direct Rust lowering
- `examples/fallback_demo`: native 비활성화 또는 누락 시 fallback 동작
- `examples/boundary_demo`: native-to-fallback boundary rejection과 warning
- `examples/app_shell`: application shell은 Python에 두고 scoring hot path만 native 가능

## 개발 및 검증

테스트 실행:

```text
python -m pytest
```

Cargo, Nuitka, executable 관련 테스트는 해당 toolchain을 사용할 수 없으면 skip됩니다.
