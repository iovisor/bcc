# PR #5517 코드 리뷰

**제목**: [tools/bashreadline: auto-detect libreadline.so for dynamically linked bash](https://github.com/iovisor/bcc/pull/5517)  
**저자**: @xuchunmei000  
**리뷰 날짜**: 2026-06-12

---

## 변경 개요

`/bin/bash`가 `libreadline`을 동적 링크하는 시스템(대부분의 최신 배포판)에서 `readline`
심볼이 bash ELF 내에 `SHN_UNDEF`(미정의 임포트)로만 존재해 `attach_uretprobe`가 실패하는
문제를 자동 탐지로 해결한다.

**추가된 로직 (39 lines, `tools/bashreadline.py`)**
1. `import subprocess` 추가
2. `is_sym_defined(filename, symname)` — `.dynsym` 섹션에서 심볼이 실제로 정의되어
   있는지(SHN_UNDEF 여부) 확인
3. `find_readline_so()` — `ldd /bin/bash`로 libreadline.so 실제 경로 탐색
4. `sym = get_sym(name)` 이후에 자동 탐지 로직 삽입 — 조건을 만족하면 `name`, `sym`
   을 libreadline.so 기준으로 재설정

---

## Findings

### 🔴 Critical

#### 1. `get_sym()` — `.dynsym` 없을 때 크래시

PR이 추가하는 새 코드 경로(`get_sym(lib)` — libreadline.so에 대해 호출)에서,
대상 파일에 `.dynsym` 섹션이 없으면 `symbol_table` 이 `None`이 되어
`NoneType.iter_symbols()` 호출로 `AttributeError`가 발생한다.

원본 코드(bash 대상)에서도 잠재적 버그였으나, libreadline.so 경로가 추가되면서
재현 가능성이 높아졌다.

**수정**: `symbol_table is None` 가드를 추가해 `"readline"`을 반환하도록 처리.

```python
# 수정 전
def get_sym(filename):
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        symbol_table = elf.get_section_by_name(".dynsym")
        for symbol in symbol_table.iter_symbols():   # ← None이면 크래시
            ...

# 수정 후
def get_sym(filename):
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        symbol_table = elf.get_section_by_name(".dynsym")
        if symbol_table is None:          # ← 가드 추가
            return "readline"
        for symbol in symbol_table.iter_symbols():
            ...
```

---

### 🟡 Warning

#### 2. `find_readline_so()` — `/bin/bash` 하드코딩

PR 원본은 함수 내부에 `/bin/bash`를 하드코딩한다. `name` 변수가 항상 `/bin/bash`인
상황에서는 문제없지만, 함수의 재사용성과 명확성을 위해 `binary` 매개변수로 받는 것이
적절하다.

```python
# 수정 전
def find_readline_so():
    out = subprocess.check_output(["ldd", "/bin/bash"], ...)

# 수정 후
def find_readline_so(binary):
    out = subprocess.check_output(["ldd", binary], ...)
```

#### 3. 광범위한 `except Exception: pass`

`is_sym_defined`, `find_readline_so` 모두 최상위 `except Exception: pass`로 예외를
조용히 삼킨다. pyelftools 미설치, 권한 문제, ldd 부재 등 실행 환경 이슈가 숨겨질 수
있다. 이 도구 특성상 graceful degradation(원래 동작으로 폴백)을 우선하므로 허용 가능하나,
verbose 모드가 있다면 예외 메시지를 출력하는 것이 좋다.

#### 4. `import subprocess` 위치

원본 PR은 `import argparse` 뒤에 `import subprocess`를 추가한다. PEP 8 기준
표준 라이브러리 import는 서드파티 import보다 앞에 위치해야 한다.

```python
# 수정 후 (stdlib 먼저)
from __future__ import print_function
import argparse
import subprocess

from elftools.elf.elffile import ELFFile
from bcc import BPF
from time import strftime
```

#### 5. 스모크 테스트 미추가

PR 동기가 "자동화 스모크 테스트 실패"임에도 불구하고
`tests/python/test_tools_smoke.py`에 변경이 없다. 동적 링크 bash 환경에서의
자동 탐지 성공 여부를 검증하는 테스트가 추가되어야 한다.

#### 6. 커밋 메시지 본문 불충분

PR 설명의 "Why this approach" / "Description" 섹션이 비어있다.
BCC 기여 가이드 커밋 형식 요구사항에 따라 커밋 본문에 문제 원인과 접근 방법 선택
이유를 서술해야 한다.

---

## 하위 호환성 분석

| 시나리오 | 동작 | 결과 |
|---------|------|------|
| bash가 readline 정적 링크 | `.dynsym`에 심볼 없음 → ldd에도 libreadline 없음 → `name` 유지 | ✅ 올바름 |
| bash가 readline 동적 링크 | `.dynsym`에 `SHN_UNDEF` → ldd로 .so 경로 탐색 → 리다이렉트 | ✅ 올바름 |
| 사용자가 `-s` 명시 | `args.shared` truthy → 자동 탐지 전체 건너뜀 | ✅ 올바름 |
| ldd 미설치 / 실패 | `find_readline_so` → `None` → `name` 유지 | ✅ 안전한 폴백 |

---

## ldd 파싱 로직 검증

```
# 일반 ldd 출력 예시:
    libreadline.so.8 => /lib/x86_64-linux-gnu/libreadline.so.8 (0x7f...)
    libreadline.so.8 => not found
```

- `split("=>")[1].strip().split()[0]` → `/lib/x86_64-linux-gnu/libreadline.so.8` ✅
- `"not found"` 경우 → `startswith("/")` 필터로 걸러짐 ✅

---

## 적용된 수정 사항 (로컬 파일: `tools/bashreadline.py`)

1. **`get_sym()`** — `symbol_table is None` 가드 추가 (🔴 Critical 수정)
2. **`import` 순서** — stdlib imports를 서드파티 앞으로 재정렬
3. **`find_readline_so(binary)`** — 하드코딩 제거, 매개변수 사용
4. **헤더 주석** — 자동 탐지 동작 설명으로 업데이트

---

## 결론

변경은 실제 문제(현대 배포판에서 bashreadline 동작 실패)를 해결하며 하위 호환성도
유지된다. Critical 이슈(`get_sym` NoneType 크래시)를 수정하고 스타일을 정리하면
merge 적합하다.

- **Approve 조건**: Critical 수정 반영, 스모크 테스트 추가(권장)
- **Blocking 아닌 권장**: 커밋 메시지 본문 보완
