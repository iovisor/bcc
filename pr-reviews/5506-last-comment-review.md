# PR #5506 마지막 컨트리뷰터 코멘트 리뷰

**대상 PR**: https://github.com/iovisor/bcc/pull/5506  
**대상 코멘트**: `discussion_r3377038257` (2026-06-09, by @vdasu)  
**리뷰 날짜**: 2026-06-12

---

## 코멘트 요약

작성자는 다음을 명확히 했습니다.

- 이 이슈는 KASLR를 깨는 형태의 "보안 취약점"은 아님.
- 다만 레코드 간 잔여 바이트가 다음 레코드에 섞여 보일 수 있는
  confidentiality/출력 위생(sanitization) 문제로 볼 수 있음.
- 커스텀 userspace loader, pinned ringbuf, 다중 consumer 상황에서는
  영향 가능성이 커질 수 있음.
- `opensnoop`에서도 variable-length 경로의 stale bytes를 관찰했다고 주장.

---

## 리뷰 의견 (핵심)

### 1) 방향성은 타당함 (동의)

- "security leak"와 "data integrity/sanitization issue"를 구분한 것은 정확합니다.
- maintainers가 우려한 과장 표현(보안 유출 프레이밍)을 완화하면서도,
  수정 필요성 자체는 충분히 방어합니다.

### 2) 근거 제시는 개선 여지 있음 (보완 필요)

현재 코멘트는 논리적으로 설득력 있지만, 마지막 문단(`opensnoop에서도 관찰`)은
정량 근거가 부족합니다. 다음이 있으면 훨씬 강해집니다.

- 최소 재현 절차(커맨드 3~5줄)
- 관찰 지표(예: 이벤트 N건 중 stale byte 포함 비율, 최대/평균 길이)
- consumer 관점 영향(기본 툴 출력에는 안 보이지만 raw reader에서는 보임)

### 3) 용어 정리 권장 (중요)

PR 제목/본문/커밋 메시지에서 "leak" 단어는 오해를 부를 수 있습니다.
다음과 같이 명시하면 리뷰 통과 가능성이 높아집니다.

- `security leak`가 아니라 `cross-record stale data exposure` 또는
  `output sanitization/integrity` 문제로 표현

---

## Maintainer 관점 최종 판단

- **결론**: 해당 코멘트는 기술적으로 합리적이며, 기존 반론에 대한 응답으로 충분히 좋습니다.
- **조건부 권장사항**:
  1. opensnoop 사례에 대한 짧은 재현/수치 추가
  2. PR 텍스트에서 보안 취약점 뉘앙스 완화

위 2가지만 보완하면, 코멘트 품질은 "merge 설득에 충분" 수준입니다.

---

## 추가 검토: 커스텀 loader / pinned ringbuf / 다중 consumer 가능성

컨트리뷰터 코멘트의 "가능성" 자체는 과장이라 보기 어렵습니다. 다만,
`libbpf-tools`의 **기본 사용 모델**과 **확장 가능한 운영 시나리오**는 구분해서 보는 것이 정확합니다.

### 기본 모델(현재 코드 기준)

- 기본 경로는 각 도구 프로세스가 스스로 BPF를 로드/attach하고,
  같은 프로세스에서 이벤트 버퍼를 열어 소비하는 단일 consumer 모델에 가깝습니다.
- `compat.bpf.h`의 `events` map은 일반 ringbuf 선언이며,
  pinning 속성(`LIBBPF_PIN_BY_NAME`)이 명시돼 있지 않습니다.
- userspace에서도 map pin 관련 API를 기본 경로로 호출하지 않습니다.

### 확장 가능성(기술적으로 가능한 영역)

- 별도 커스텀 loader가 같은 BPF object/map FD를 다루도록 구성하면,
  raw 이벤트를 읽는 사용은 가능합니다.
- 운영자가 bpffs pinning을 별도 도입하면, 프로세스 수명과 분리된 map 공유 설계도 가능합니다.

### 다중 consumer 관련 주의

- ringbuf는 fan-out 브로드캐스트 큐가 아니라 소비 위치를 공유하는 모델이므로,
  다중 reader를 "정상 지원 시나리오"로 보기는 어렵습니다.
- 따라서 이 경우는 "일반 기본 사용"이 아니라 "커스텀/고급 운영 구성"으로 분류하는 것이 타당합니다.

### 종합 판단

- 코멘트의 문제의식(기본 CLI 외 소비자에서 잔여 데이터가 관찰될 수 있음)은 타당합니다.
- 다만 표현은 "기본 libbpf-tools 사용에서 즉시 발생하는 보안 문제"가 아니라,
  "확장/커스텀 소비 경로에서 현실화 가능한 위생/무결성 이슈"로 제한하는 것이 가장 정확합니다.

---

## 추가 검토: opensnoop 이벤트 크기와 성능 개선 가능성

### 1. ~8KB는 `path_helper` 때문

`struct event`의 크기는 `struct full_path fname` 필드가 지배합니다.

```
full_path.pathes = NAME_MAX(255) × MAX_PATH_DEPTH(32) = 8,160 bytes
full_path.depth  = 4 bytes
full_path.failed = 4 bytes
                 = 8,168 bytes  ← full_path만
나머지 필드(ts/pid/uid/ret/flags/mode/callers/comm) = 60 bytes
─────────────────────────────────────────────────
sizeof(struct event) ≈ 8,228 bytes
```

이것이 `zero_buf(eventp, sizeof(*eventp))`가 매번 zeroing하는 양입니다.

### 2. `path_helper` 없을 때 zeroing 크기

`path_helper` 이전 opensnoop의 `fname`은 단순 `char fname[NAME_MAX]`(256 B) 수준이었습니다.
`struct full_path`를 제거하면:

```
60(기타 필드) + 256(fname) ≈ 316 bytes
```

**zeroing 비용: 8,228 B → ~316 B, 약 26배 감소**

### 3. `path_helper` 구조 변경으로 성능 개선 접근 가능성

가능하며, 현실적인 방향은 두 가지입니다.

**방향 A — depth 기반 partial zeroing**

실제 채운 슬롯(`depth`)만큼만 zeroing:

```c
zero_buf(eventp, offsetof(struct event, fname));
zero_buf(&eventp->fname,
         sizeof(eventp->fname.depth) +
         sizeof(eventp->fname.failed) +
         NAME_MAX * (eventp->fname.depth + 1));
```

평균 경로 깊이 5 기준 → 255 × 5 = 1,275 B.  
단, `depth`는 BPF 프로그램이 `pathes`를 채운 이후 확정되므로 zeroing 타이밍 설계가 필요합니다.

**방향 B — `full_path`를 옵션 경로로 분리 (더 깔끔)**

```c
struct event {
    __u64 ts; pid_t pid; ...  // ~60 bytes (항상)
    char fname_short[NAME_MAX]; // 255 bytes (기본)
    // full_path=true 옵션 시에만 별도 제출
};
```

- `full_path` 옵션 꺼짐(기본) → ~316 B만 zeroing
- `full_path=true` → 큰 버퍼 활성화
- 방향 A보다 설계가 명확하고 BPF 타이밍 문제도 없음
- 단점: BPF + userspace 양쪽 수정이 필요해 PR 범위 확대

### 성능 비교 요약

| 구분 | zeroing 크기 | 현재 대비 |
|---|---|---|
| 현재 (full_path 포함) | ~8,228 B | 1× |
| path_helper 없을 때 | ~316 B | ~26× 감소 |
| 방향 A (depth 기반 partial) | ~1,275 B (평균 5 depth) | ~6× 감소 |
| 방향 B (옵션 분리, 기본 모드) | ~316 B | ~26× 감소 |

PR 5506 reviewer의 opensnoop 성능 우려는 `path_helper`가 이벤트 크기를 26배 부풀린
구조에서 비롯된 것으로, zero_buf 자체보다 `struct full_path`의 고정 크기 할당이
근본 원인입니다.

---

## 추가 검토: 커널 path iter(`bpf_d_path`)로 `path_helper` 구조 개선 가능성

### 현재 `path_helper`의 구조적 문제

`path_helpers.bpf.h`의 `bpf_dentry_full_path()`는 dentry 트리를 BPF에서
수동으로 순회하면서 각 컴포넌트를 255 byte 슬롯에 복사합니다.

```
32 슬롯 × 255 byte = 8,160 byte (고정, 실제 경로 길이 무관)
```

이 구조는 경로 깊이가 3이든 32이든 **항상 8,160 byte를 점유**합니다.

### 커널 `bpf_d_path()` 헬퍼 (Linux 5.9+)

`bpf_d_path(struct path *path, char *buf, u32 sz)` 헬퍼는
커널 내부에서 전체 경로 문자열을 단일 `buf`에 직접 씁니다.

```c
// 단 한 번의 호출로 /a/b/c/filename 형태의 전체 경로 획득
// 버퍼는 실제 경로 길이 + '\0' 만큼만 채워짐
long bpf_d_path(const struct path *path, char *buf, u32 sz);
```

사용할 경우 이벤트 구조체 변화:

```c
struct event {
    // ... 기존 필드 ~60 byte
    char fname[PATH_MAX];  // 4,096 byte (최대) - 하지만 실제 쓴 만큼만 의미 있음
};
// zeroing: PATH_MAX 기준이라도 255×32=8,160 → 4,096 (약 2배 개선)
// 실제 경로 길이 기반으로 zeroing 제한하면 추가 개선 가능
```

### `bpf_d_path()`를 opensnoop에 적용할 수 없는 이유

**결정적 제약**: `bpf_d_path()`는 **tracepoint 프로그램에서 사용 불가**합니다.

man page 기준 허용 프로그램 타입:
- `fentry`/`fexit` (특정 VFS 함수에 attach)
- LSM hooks
- `raw_tracepoint` 일부

opensnoop은 `tracepoint/syscalls/sys_exit_open*`을 사용하며, 이 타입에서는
검증기(verifier)가 `bpf_d_path()` 호출을 **거부**합니다. 이는 해당 컨텍스트에서
`struct path *`가 trusted pointer로 보장되지 않기 때문입니다.

`bpf_getcwd()` (현재 `path_helpers.bpf.h`에서 사용 중) 역시 같은 이유로
`bpf_get_current_task_btf()` → 수동 dentry walk 방식을 택하고 있습니다.

### opensnoop의 fentry/fexit 전환 가능성 검토

BCC libbpf-tools 내에서 fentry/fexit는 이미 `biosnoop`, `cachestat`, `fsslower`,
`fsdist`, `klockstat` 등에서 **실제 사용 중**입니다. 따라서 opensnoop도 원칙적으로
전환 가능합니다.

#### 적합한 attach 지점

opensnoop이 트래킹하는 것은 "파일 열기 syscall의 결과"입니다.
fentry/fexit로 이를 구현하려면 적합한 커널 내부 함수가 필요합니다.

**후보 1: `do_sys_openat2()`**
```c
// 시그니처
long do_sys_openat2(int dfd, const char __user *filename, struct open_how *how);
```
- `fentry`: `filename`(user ptr), `dfd`, `how` 접근 가능 → 현재 entry tracepoint와 동등
- `fexit`: return 값은 **fd(long)** — `struct path *` 없음
- fd → `struct file *` 변환을 위해 `current->files->fdt->fd[ret]` 접근 필요
  (`BPF_CORE_READ` 체인, 검증기 복잡도 증가)

**후보 2: `do_filp_open()`** ← bpf_d_path 활용에 적합
```c
// 시그니처
struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);
```
- `fexit` 시 return 값이 **`struct file *`** → `file->f_path`로 `bpf_d_path()` 직접 호출 가능
- 단, `sys_open` → `do_sys_open` → `do_sys_openat2` → `do_filp_open` 경로로 호출되므로
  entry 정보(flags, mode 등)를 별도 map으로 전달해야 함

```c
// fexit/do_filp_open 에서 가능한 패턴
SEC("fexit/do_filp_open")
int BPF_PROG(opensnoop_exit, int dfd, struct filename *name,
             const struct open_flags *op, struct file *ret)
{
    // ret이 ERR_PTR이 아닐 때만 유효
    if (IS_ERR(ret))
        goto cleanup;

    // bpf_d_path 호출 가능 (fentry/fexit 컨텍스트이므로)
    bpf_d_path(&ret->f_path, event->fname, PATH_MAX);
    ...
}
```

#### fentry/fexit 전환 시 실제 장애물

| 항목 | 상세 |
|---|---|
| 커널 함수 ABI 비안정성 | `do_filp_open`, `do_sys_openat2` 는 내부 함수 — 시그니처가 커널 버전마다 변경될 수 있음 |
| 인라인 위험 | `do_sys_openat2`가 LTO 커널에서 인라인되면 fentry attach 불가 |
| 트레이스포인트 ABI 안정성 상실 | 현재 `tracepoint/syscalls/*` 은 사용자 공간 ABI 수준으로 안정 |
| fsslower의 실제 경로 처리 방식 | fsslower는 fentry/fexit를 쓰면서도 `bpf_d_path()`를 쓰지 않고 `BPF_CORE_READ(fp, f_path.dentry)` → `d_name.name`(파일명만) 방식을 씀 — 전체 경로 재구성은 여전히 어려운 문제임 |
| 스택 entry/exit 상관 관계 | `tracepoint` 방식은 `sys_enter`/`sys_exit`가 명확히 쌍을 이루지만, 커널 내부 함수는 재진입 또는 다른 경로로 호출될 수 있음 |

#### 현재 libbpf-tools에서 `bpf_d_path` 사용 현황

```
$ grep -r bpf_d_path libbpf-tools/
(결과 없음)
```

`fsslower`, `fsdist` 등 fentry/fexit를 사용하는 도구들도 **전체 경로 재구성에는
`bpf_d_path()`를 쓰지 않습니다**. 파일명(`d_name.name`)만 읽거나 현재 opensnoop처럼
수동 dentry walk를 씁니다. 이는 fentry/fexit에서도 전체 경로 reconstruction이 단순하지
않음을 보여줍니다.

### `bpf_d_path` 기반으로 구조 변경 가능한 조건

| 항목 | 현재 (tracepoint) | fentry/fexit + bpf_d_path |
|---|---|---|
| path_helper 필요 | 수동 dentry walk 필수 | `bpf_d_path()` 직접 호출 가능 |
| 이벤트 크기 | 8,228 B (고정) | PATH_MAX(4,096 B) 이하 |
| zeroing 대상 | 8,228 B | 실제 경로 길이 기반 축소 가능 |
| 최소 커널 버전 | CO-RE 기준 5.4+ | `bpf_d_path` 5.9+, fentry 5.5+ |
| syscall ABI 안정성 | 안정 (tracepoint ABI) | 불안정 (내부 함수 시그니처) |
| 코드 변경 범위 | — | BPF 프로그램 타입 전면 변경 |
| 기존 libbpf-tools 선례 | — | fentry/fexit 자체는 사용 중, bpf_d_path는 미사용 |

### 결론

- fentry/fexit 방식은 기술적으로 opensnoop에도 적용 **가능**합니다.
- 그러나 커널 내부 함수 ABI 불안정성, 인라인 위험, fsslower 등 기존 도구에서도
  `bpf_d_path()`를 실제로 사용하지 않는다는 사실이 구조 변경의 실익을 제한합니다.
- `bpf_d_path()`는 현재 libbpf-tools 전체에서 아무도 쓰지 않습니다 — 이 API가
  실용적이면 누군가가 이미 채택했을 것입니다.
- **단기 현실적 개선**: `full_path` 옵션 비활성화 시 `struct full_path` 제외 (Direction B),
  또는 depth 기반 partial zeroing (Direction A)이 PR 5506 범위 내 해결책으로 적합합니다.

---

## 제안 답변(초안)

Thanks for clarifying the threat model. I agree this is not a KASLR/security leak,
but a cross-record stale-data exposure and output-sanitization concern.

Could you add a short reproducible note for opensnoop (steps + a small quantitative
result), and slightly adjust PR wording from "leak" to "stale data exposure"?
That should make the intent precise and reduce reviewer confusion.
