# Rextio

<p align="center">
  <img src="https://raw.githubusercontent.com/rextio/rextio/main/assets/readme/rextio-icon.png" width="112" alt="Rextio 아이콘">
</p>

<p align="center">
  <strong>조건을 충족하는 타입 명시 Python 함수를 미리 Rust/PyO3로 컴파일합니다.<br>나머지는 모두 안전한 Python 폴백으로 유지합니다.</strong>
</p>

<p align="center">
  <a href="https://github.com/rextio/rextio/blob/main/README.md">English</a> ·
  <a href="https://github.com/rextio/rextio/blob/main/README.ko.md">한국어</a> ·
  <a href="https://github.com/rextio/rextio/blob/main/README.zh-hans.md">简体中文</a> ·
  <a href="https://github.com/rextio/rextio/blob/main/README.zh-hant.md">繁體中文</a> ·
  <a href="https://github.com/rextio/rextio/blob/main/README.ja.md">日本語</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/rextio/"><img alt="PyPI 버전" src="https://img.shields.io/pypi/v/rextio"></a>
  <a href="https://pypi.org/project/rextio/"><img alt="지원 Python 버전" src="https://img.shields.io/pypi/pyversions/rextio"></a>
  <a href="https://github.com/rextio/rextio/blob/main/LICENSE"><img alt="MIT 라이선스" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

Rextio는 애플리케이션을 다시 작성하지 않고도 일부 타입 명시 핫 패스를 네이티브 Rust로 실행하려는 **Python 개발자용 Alpha 로컬 빌드 도구**입니다. 보수적인 분석기는 문서화된 의미를 지키며 내릴 수 있는 코드만 받아들입니다. 지원되지 않거나 모호한 코드는 생성된 Python 폴백 래퍼에 남습니다. 네이티브 실행을 비활성화했거나 기본 `auto` 모드에서 네이티브 코드를 사용할 수 없는 경우에도 같은 import가 이 래퍼를 통해 계속 동작합니다.

```bash
python -m pip install rextio
rextio check .
```

빌드하기 전에 어떤 함수가 승인되는지 확인하는 것이 가장 짧고 유용한 첫 단계입니다.

Core **0.1.8**은 2026-07-27에 plugin API **1.7**, tooling contract **3.0.0**과 함께 배포되었습니다. 릴리스 이력은 [변경 기록](CHANGELOG.md)을 참고하세요.

> **Tooling 마이그레이션:** contract 3.0은 milestone 기반 artifact identity를 의미 기반 `artifact-*` 이름으로 대체합니다. 정확한 0.1.7 identity는 legacy 읽기/검증 입력으로만 유지되며, 2.x 전용 consumer는 major 3에서 기능을 축소해야 합니다.

## 증거: 측정된 CPU 워크로드

**Mac16,11 / Apple M4 Pro**, **2026-07-26**, CPython **3.11.9**에서 세 번 실행한 중앙값입니다.

| 워크로드 | source/native 중앙 속도비 |
| --- | ---: |
| Core hybrid | 57.729× |
| NumPy mixed fusion | 2.523× |
| NetworkX Dijkstra | 3.679× |
| pandas `Series.map` | 66.143× |
| PyTorch CPU deep MLP | 1.017× |
| TensorFlow CPU eager chain | 1.040× |

이는 **특정 워크로드에서의 관측값**이지 라이브러리 전체의 성능 약속이 아닙니다. 1×에 가까운 값은 비슷한 성능을 뜻하며, 보존된 일부 진단 결과는 Python보다 느립니다. CUDA는 측정하지 않았습니다. 감사 가능한 [rextio-benchmark](https://github.com/rextio/rextio-benchmark) 저장소에 정확한 리비전, source/fallback/native 레인, 원시 증거, 안정성 정책, 진단, 느림/동급 사례가 있습니다.

## 작동 방식

```text
typed Python
  → 타입 해석과 지원 하위 집합 검사
  → 안전하지 않은 native/fallback 호출 그래프 거부
  → 승인된 함수를 Rust + PyO3로 lowering
  → import 호환 Python 래퍼 생성
  → fallback을 보존하며 네이티브 산출물 빌드
```

정확성의 기준은 Python입니다. Rextio는 Python 대체재, 범용 Python-to-Rust 변환기, JIT, 프로젝트 전체 마이그레이션 도구가 아닙니다.

## 첫 빌드

기본 자동 모드에서는 데코레이터가 선택 사항이므로 일반적인 타입 명시 Python으로 시작하면 됩니다.

```python
# src/myapp/math_ops.py
def sum_squares(xs: list[int]) -> int:
    total = 0
    for x in xs:
        total += x * x
    return total

def format_result(value: int) -> str:
    return f"score={value}"  # Python fallback에 남음
```

```bash
rextio check .
rextio build . --fallback=cpython
```

Rextio는 `sum_squares`를 lowering하고 `format_result`는 폴백에 둘 수 있습니다. 호출자는 일반 Python import를 그대로 사용합니다.

```python
from myapp.math_ops import format_result, sum_squares

assert sum_squares([1, 2, 3]) == 14
assert format_result(14) == "score=14"
```

빌드된 패키지를 언제든 폴백으로 강제할 수 있습니다.

```bash
REXTIO_NATIVE_MODE=fallback python -m myapp
```

주요 명령은 `rextio init`, `rextio capabilities`, `rextio check`, `rextio generate`, `rextio build`, `rextio bench`, `rextio clean`입니다.

## 요구 사항

| 구성 요소 | 지원 경계 |
| --- | --- |
| CPython | `>=3.11`, 3.11–3.14에서 검증됨. 생성 확장은 CPython 3.14까지 지원하는 PyO3 0.29를 고정합니다. 더 최신 인터프리터는 검증하지 않았고 wheel은 빌드 인터프리터의 minor 버전에 태깅됩니다. |
| Rust | MSRV 1.83, 최근 stable을 테스트함. 생성 crate는 Rust 2021을 사용합니다. [rustup](https://rustup.rs)으로 설치하세요. |
| Nuitka | 선택 사항, `>=2.0`. 선택한 Nuitka 폴백, 실행 파일, dispatcher 경로에서만 필요하며 해당 경로는 Experimental입니다. |
| Numba | 선택 사항이며 Experimental. 인터프리터별 하한은 0.57(3.11), 0.59(3.12), 0.61(3.13), 0.63(3.14)입니다. Numba는 계속 사용자 프로젝트의 의존성입니다. |

도구 위치와 버전은 `[toolchain]`, 환경 변수, CLI 옵션으로 고정할 수 있습니다. [REXTIO.md](./REXTIO.md#toolchain-selection-and-version-pins)를 참고하세요.

## 선택과 폴백 안전성

기본값은 자동 탐색입니다.

```toml
[policy]
native_marker = "auto"
```

`@rextio.native`를 의무화하려면 `native_marker = "decorator"`를, 함수를 Python에 유지하려면 `@rextio.exempt`를 사용하세요. 구현된 네이티브 대상은 Rust뿐입니다.

```python
import rextio

@rextio.native
def score(x: float) -> float:
    return x * 2.0

@rextio.exempt
def keep_python(x: int) -> int:
    return x + 1
```

애플리케이션 설계에 영향을 주는 안전 규칙은 다음과 같습니다.

- 직접 네이티브 함수는 승인된 네이티브 함수와 지원되는 builtin/표준 라이브러리 연산만 호출할 수 있습니다.
- 명시적으로 표시한 호출자가 immutable scalar 경계 경로의 조건을 만족하지 않는 한, 폴백 전용 코드 호출은 네이티브 호출자를 거부합니다. 컨테이너는 이 경계를 넘지 않으며 루프나 comprehension 안의 경계 호출은 폴백에 남습니다.
- Python 루프에서 네이티브 함수를 호출하면 정적 경계 진단 `RXT073`이 발생합니다. 조건을 충족하는 직접 네이티브 함수만 wrapper 진입과 scalar 경계 진입을 함수별 런타임 폴백 임계값에 누적하며, plugin 경로 함수는 제외됩니다.
- `auto` 모드에서는 네이티브 import를 사용할 수 없거나 임계값으로 강등되면 Python 폴백을 사용하고, 분석기에서 거부된 함수는 폴백에 남습니다. `fallback` 모드는 네이티브 실행을 명시적으로 끕니다. `native` 모드는 승격된 네이티브 코드를 필수로 요구하며 네이티브 import를 사용할 수 없으면 예외를 발생시킵니다. `REXTIO_DEBUG_NATIVE=1`은 네이티브 로드 경고를 진단용 traceback으로 바꿉니다.
- `native-shim`/`RXT080`은 동적 Python 의미를 보존하기 위해 PyO3를 통해 Python 폴백을 호출합니다. 이는 호환성 경로이며 **Rust 속도 향상 경로가 아닙니다**.
- Rust ownership이 동작을 바꿀 수 있는 mutable collection aliasing은 Python에 남습니다. 번역이 가능해 보인다는 이유만으로 네이티브 후보를 내보내지 않습니다.

런타임 제어:

```text
REXTIO_NATIVE_MODE=auto|fallback|native
REXTIO_BOUNDARY_FALLBACK_THRESHOLD=1000
REXTIO_DISABLE_BOUNDARY_FALLBACK=1
REXTIO_DEBUG_NATIVE=1
```

## 지원되는 직접 Rust 코드 형태

의도적으로 좁은 직접 경로는 다음의 지원 조합을 포함합니다.

- scalar `int`, `float`, `bool`, `str`, `bytes`, `None`
- list(중첩 포함), 고정 tuple, scalar key의 고정 dict, 제한된 `set[int|bool|str]`, `Optional[T]` / `T | None`
- 타입 명시 지역 변수, 산술, 비교, `if`, `while`, 지원되는 `for`/`range`/`enumerate`/`zip`, comprehension, 승인된 네이티브 helper
- 제한된 builtin, `math`, 문자열/bytes/list 메서드, 로깅/출력, `datetime`, `time`, `hashlib.sha256`, `base64.b64encode`

중요한 제외도 명시합니다. `set[float]`와 set 순회는 CPython의 NaN identity/hash 순서를 보존할 수 없습니다. `statistics.mean/fmean`, `json.dumps/loads`, `base64.b64decode`에는 직접 네이티브 경로가 없습니다. 파일/네트워크/데이터베이스/ORM 작업과 동적 객체 동작은 폴백 또는 명시적으로 표시한 호환성 shim에 남습니다. 전체 버전별 경계는 [지원하지 않는 기능](docs/unsupported-features.md)과 [기능 안정성](docs/stability.md)을 참고하세요.

## 빌드 출력

| 요청 | 결과와 경계 |
| --- | --- |
| 기본 빌드 | 네이티브 코드와 Python 폴백이 포함된 import 호환 패키지 트리 및 선택적 wheel. |
| `--entrypoint=…` | Zipapp. 대상에 호환 Python이 필요하며 zipapp 내부에서 네이티브 확장을 import하지 않습니다. |
| `--executable-backend=nuitka` | Experimental standalone/onefile 실행 파일. Nuitka가 필요하며 임의의 타사 의존성에 대한 크로스 플랫폼 패키징을 주장하지 않습니다. |
| `--executable-backend=rust` | 네이티브 Rust entrypoint. 닫힌 그래프는 standalone일 수 있습니다. `python-subprocess`는 제한된 immutable scalar 호출만 위임하며 CPython이 필요하고, `nuitka-sidecar`는 Nuitka가 필요합니다. runtime shim과 컨테이너 경계 통과는 거부됩니다. 이식 가능한 프로세스 상태에는 `0..255` 종료 코드를 권장합니다. |
| `--rust-importable` | 직접 Rust 함수만 포함하는 Experimental Cargo path-dependency crate. 폴백, shim, scalar 경계 함수는 Python-facing 경로로 남습니다. |

`rextio build`와 `generate`는 매번 깨끗하게 재분석하고 다시 생성합니다. 0.1.x에는 증분 빌드 캐시가 없습니다. subprocess hybrid runtime은 소스를 `<binary>.runtime/` 아래로 복사하므로 위임된 코드는 복사본의 `__file__`을 봅니다. 원래 파일 상대 경로로 데이터를 찾는 코드는 다른 경로가 필요합니다.

## 플러그인, 디바이스, 외부 소스

플러그인은 프로젝트 설정에서 명시적으로 활성화하는 별도 Python 배포물입니다. 활성 플러그인이 없는 패키지는 기본적으로 보수적으로 처리됩니다. `try-native`는 Experimental 계획 정책이며 일반 의존성 변환 약속이 아닙니다.

Device Provider API 1 선택 역시 Experimental이며 명시적입니다. 설정만으로 CPU 전용 Torch/TensorFlow 경로가 CUDA 기능을 얻지 않습니다. 혼합/충돌 디바이스 도메인, 누락된 provider, 지원하지 않는 GPU ordinal, 잘못된 capability는 fail closed로 처리됩니다. Provider preflight는 `support_claim: false`를 보고하며 Core는 인증된 CUDA 실행을 주장하지 않습니다.

외부 pure-Python 소스 인벤토리는 정확히 하나의 고정되고 검증된 depth-1 `py3-none-any` 배포물에 대한 비빌드 미리보기입니다. 패키지를 import하거나, 어휘 후보를 프로젝트 호출에 연결하거나, lowering·복사·재배포·빌드 승인을 하지 않습니다. SourceLock 증거가 없거나 유효하지 않으면 차단되며, 검증된 lock만으로도 빌드/배포 권한은 생기지 않습니다.

별도의 `strict-evidence` **Alpha/Experimental** 프로필은 macOS arm64 또는 Linux x86_64의 CPython 3.11 host-extension 빌드, SourceLock 승인 의존성 하나, scalar leaf 호출, 소유자가 고정한 offline 입력, 두 번의 격리 빌드, 외부 Ed25519 서명으로 범위가 고정됩니다. 플러그인, 실행 파일, Rust crate, embedding, 네이티브 top-level 초기화, Windows, 광범위한 패키지 lowering, 일반 재배포는 제외됩니다. sandbox/support lock은 소유자가 통제하는 프로세스 안에서 증거 무결성을 보호할 뿐, secure boot, 악의적인 동일 UID 프로세스나 손상된 OS 방어, 일반 hermeticity, registry 인증, 크로스 플랫폼 인증을 의미하지 않습니다.

> **법적 경계:** 의존성 소스의 번역 또는 재배포에는 특히 GNU/copyleft 조건의 라이선스 및 파생 저작물 의무가 생길 수 있습니다. Rextio의 인벤토리와 SourceLock 검사는 법률 자문이나 법적 승인이 아닙니다.

이 고급 기능에 의존하기 전에 [host source-AOT 및 네이티브 실행 파일](docs/source-aot-and-executables.md), [Device Provider API 1](docs/specs/device-provider.md), [tooling contract](docs/specs/tooling-contract.md)를 읽으세요.

## Numba와 Nuitka

인식된 `@numba.*` 데코레이터는 폴백에서 **Numba의** 의미를 쓰겠다는 명시적 선택이며 Rextio의 CPython 동등 네이티브 계약이 아닙니다. `@rextio.native`와 함께 사용하지 마세요. Numba가 설치되어 있으면 wheel/zipapp 및 source-hybrid 경로는 작동할 수 있지만, Nuitka 실행 파일과 Nuitka hybrid dispatcher는 컴파일된 함수에 bytecode가 없고 accelerator가 번들되지 않으므로 가속 함수를 일찍 거부합니다. 어떤 accelerator든 작은 함수는 경계 오버헤드 때문에 느려질 수 있습니다.

## 예제와 프로젝트 정보

```bash
rextio check examples/pure_math
rextio build examples/pure_math --fallback=cpython
rextio bench pure_math.math_ops.sum_squares --project-root examples/pure_math
```

직접 수학 연산, 폴백과 경계 동작, wheel, zipapp, Nuitka, Numba, Rust 실행 파일/crate, embedded helper는 [`examples/`](examples/)에서 확인할 수 있습니다. Embedding은 Experimental이고 기본 비활성화이며 AOT-only/scalar-only입니다. 네이티브 호출자에서 monkeypatch가 보이는 방식이 바뀌며 런타임 JIT가 아닙니다.

- [보안 모델](SECURITY.md)
- [기여](CONTRIBUTING.md)
- [버전 정책](docs/versioning.md)
- [변경 기록](CHANGELOG.md)
- [라이선스](LICENSE) — MIT

저자: Steve Si-young Song · [@RextioDev](https://x.com/RextioDev)
