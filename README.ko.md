# Rextio

[English](README.md) | [简体中文](README.zh-hans.md) | [繁體中文](README.zh-hant.md) | [日本語](README.ja.md)

Rextio는 적격한 타입 힌트가 있는 Python 함수를 Rust 네이티브 모듈로 컴파일하고,
나머지는 안전한 Python fallback으로 패키징합니다.

Public 1은 의도적으로 범위가 좁습니다. 타입 힌트가 있는 Python hot path를 사용하는
프로젝트를 위한 로컬 CLI 및 빌드 도구 MVP입니다. Rextio는 기본적으로 적격한 타입
함수를 자동으로 발견하며, 프로젝트는 자동 발견을 끄고 `@rextio.native` 표시를
요구하도록 설정할 수 있습니다. Rextio는 Python 전체 호환성, 전체 NumPy 지원,
프레임워크 마이그레이션, JIT 동작, 또는 완전한 런타임 경계 비용 최적화기를
제공한다고 주장하지 않습니다.

Public 1은 보수적인 정적 경계 검사를 포함합니다. fallback-only 코드를 호출하는
native 함수는 거부하고, Python loop가 native 함수를 반복 호출하면 경고하며, 반복된
Python/Rust 경계 crossing이 단순 런타임 임계값을 넘으면 생성된 wrapper가 해당
native 함수를 fallback으로 전환합니다.

## 현재 명령

```text
rextio init
rextio check
rextio generate
rextio build
rextio bench
rextio clean
```

초기 구현은 프로젝트 초기화, native 후보 발견, subset 진단, 정적 경계 진단,
런타임 비활성화 플래그, 결정적인 check report에 집중합니다.

일반적인 로컬 흐름:

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

## Public 1 범위

Public 1은 모듈 레벨 함수를 위한 작은 타입 지정 Python subset을 지원합니다.
적격한 타입 함수는 기본적으로 native 후보가 됩니다. 지원되지 않는 문법, 동적 기능,
안전하지 않은 native-to-fallback 호출, 해석되지 않는 외부 호출은 native 컴파일에서
거부되고 가능한 경우 Python fallback으로 유지됩니다.

지원 subset, 경계 제한, 진단, 비목표는
[Public 1에서 지원하지 않는 기능](docs/unsupported-features.md)을 참고하세요.

## 빌드 전제 조건

Native 빌드에는 Rust와 Cargo가 필요합니다. `[rust] build_tool = "maturin"`으로
설정하면 Rextio는 `maturin`도 사용할 수 있으며, maturin을 사용할 수 없으면 가능한
경우 Cargo로 fallback합니다.

Nuitka fallback 패키징은 실험적입니다. Nuitka가 설치되지 않은 상태에서
`--fallback=nuitka`가 요청되면 Rextio는 명확한 `RXT060` 오류를 보고하고
`--fallback=cpython`을 제안합니다. Nuitka가 설치되어 있으면 Rextio는 생성된 Python
fallback 모듈에 Nuitka를 실행하면서도 CPython fallback 파일을 빌드 산출물에 계속
포함합니다.

`--fallback`이 생략되면 `rextio build`는 `rextio.toml`의 `[build] fallback_backend`를
사용합니다. `--fallback=cpython` 또는 `--fallback=nuitka`를 전달하면 해당 실행에서
프로젝트 설정을 덮어씁니다.

## 생성 산출물

Rextio는 생성 파일을 `.rextio/` 아래에 쓰며, 사용자 소스 파일을 제자리에서 수정하지
않습니다.

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
  <executable-name>.pyz
```

`rextio check`는 `.rextio/reports/check.json`을 씁니다. `rextio build`는 check 및
build report를 모두 씁니다. `rextio bench`는 구조화된 fallback/native 타이밍 비교를
담은 `.rextio/reports/bench.json`을 씁니다.

`rextio generate`는 분석을 실행하고 Cargo, maturin, Nuitka를 호출하지 않으며
`.rextio/build/` 또는 `dist/`를 만들지 않고 `.rextio/generated/` 아래에 생성된
Rust/PyO3 및 Python wrapper/fallback 소스를 씁니다.

`rextio build`가 성공하면 `dist/` 아래에 생성된 hybrid artifact wheel도 씁니다. 순수
fallback wheel은 `py3-none-any`를 사용하고, 생성된 native extension이 포함된 wheel은
로컬 CPython/platform tag를 사용합니다. 테스트 스위트는 이 wheel을 새 환경에
설치하고 `REXTIO_DISABLE_NATIVE=1`로 패키징된 fallback import가 계속 동작하는지
검증합니다.

`rextio build --entrypoint=module:function`은 `dist/` 아래에 zipapp 실행 artifact도
생성합니다. 출력 파일 이름은 `--executable-name=name`으로 지정할 수 있으며, 생략하면
Rextio가 entrypoint 모듈에서 이름을 파생합니다. 결과물은 Python zipapp(`.pyz`)이므로
대상 머신에는 호환되는 Python 인터프리터가 필요합니다. Native extension 모듈은 zipapp
내부에서 직접 import할 수 없으므로, generated wrapper는 fallback 안전성을 유지하고
native 모듈을 사용할 수 없을 때 Python fallback을 사용합니다.

## 정책 설정

Public 1은 `rextio.toml`을 보수적으로 검증하며 알 수 없는 섹션, 알 수 없는 키,
지원되지 않는 backend, Public 1 범위를 벗어난 정책 값을 거부합니다.

경계 경고는 기본적으로 활성화되어 있습니다. Python-loop 경계 경고 없이 엄격한 안전
오류만 원하는 프로젝트는 다음을 설정할 수 있습니다.

```toml
[policy]
boundary_warnings = false
```

자동 native discovery는 기본적으로 활성화되어 있습니다.

```toml
[policy]
native_marker = "auto"
```

명시적인 native 후보만 원하는 프로젝트는 auto discovery를 비활성화할 수 있습니다.

```toml
[policy]
native_marker = "decorator"
```

decorator-only 모드에서는 `@rextio.native`로 표시된 함수만 native 후보가 됩니다.

자동 native discovery가 켜져 있어도 Python fallback에 남겨야 하는 함수에는
`@rextio.exempt`를 사용하세요. exempt 함수는 생성된 Rust에 절대 emit되지 않으며,
이를 호출하는 native 후보는 일반 native-to-fallback 경계 규칙에 따라 거부됩니다.

## Fallback 안전성

생성된 wrapper는 가능하고 안전할 때 native 함수를 사용합니다. native import가
실패하거나 native 실행이 비활성화되면 Python으로 fallback합니다.

```text
REXTIO_DISABLE_NATIVE=1
```

프로젝트가 명시적인 런타임 동작을 필요로 하면 `REXTIO_NATIVE_MODE`를 설정할 수
있습니다.

```text
REXTIO_NATIVE_MODE=auto      # 기본값: 가능하면 native를 사용하고, 아니면 fallback
REXTIO_NATIVE_MODE=fallback  # Python fallback 강제
REXTIO_NATIVE_MODE=native    # 생성된 native 함수가 사용 가능해야 함
```

반복되는 Python-to-native wrapper 호출은 처음에는 허용됩니다. 함수의 wrapper crossing
횟수가 `REXTIO_BOUNDARY_FALLBACK_THRESHOLD`를 초과하면 이후 호출은 해당 함수의 생성된
Python fallback을 사용합니다. 기본 임계값은 `1000`입니다.
`rextio generate --fallback-threshold=N`과 `rextio build --fallback-threshold=N`은 해당
artifact의 생성 코드 기본값을 embed합니다. 런타임 환경변수는 embed된 기본값보다
우선합니다. 임계값을 `0`으로 설정하거나 `REXTIO_DISABLE_BOUNDARY_FALLBACK=1`을
설정하면 이 자동 fallback이 비활성화됩니다. `REXTIO_NATIVE_MODE=native`는 이
임계값을 우회합니다.

Rextio 분석에서 생성 파일 또는 관련 없는 Python 파일을 제외하려면 `.rextioignore`를
사용하세요.

## 경계 진단

Public 1 경계 검사는 정적이고 보수적입니다.

- `RXT070`: native 함수가 fallback-only Python 코드를 호출합니다.
- `RXT072`: native 함수가 거부된 native 함수에 의존합니다.
- `RXT073`: fallback Python이 loop 안에서 native 함수를 호출합니다.

`RXT070`과 `RXT072`는 native 후보를 거부합니다. `RXT073`은 경고입니다. 해당 함수는
여전히 적격하며 처음에는 native를 사용할 수 있지만, 반복된 런타임 crossing이 설정된
임계값을 넘으면 생성된 wrapper가 CPython/Nuitka fallback 경로로 fallback합니다.

## 예제

Public 1에는 집중된 로컬 예제가 포함됩니다.

- `examples/pure_math`: native hot path로 컴파일되는 단순 타입 수학 함수.
- `examples/fastapi_scoring`: FastAPI는 Python에 남고 `compute_score`는 Rust native가 됩니다.
- `examples/fallback_demo`: native가 없거나 `REXTIO_DISABLE_NATIVE=1`일 때 생성된 wrapper가 Python fallback을 사용합니다.
- `examples/boundary_demo`: `@rextio.exempt`를 통한 보수적인 경계 거부와 Python-loop 경계 경고.

시도해 보기:

```text
rextio check examples/pure_math
rextio generate examples/pure_math --fallback=cpython
rextio build examples/pure_math --fallback=cpython
rextio build examples/fallback_demo --entrypoint=fallback_demo.run_demo:main
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math
rextio check examples/boundary_demo
```
