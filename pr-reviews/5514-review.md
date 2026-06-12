# PR #5514 코드 리뷰

**제목**: [libbpf-tools/trace_helpers.c: free() called more than once](https://github.com/iovisor/bcc/pull/5514)  
**저자**: @isabert  
**리뷰 날짜**: 2026-06-12

---

## Findings (Severity 순)

### 없음 (No blocking findings)

현재 PR의 최종 diff 기준(`libbpf-tools/trace_helpers.c`, `dso__free_fields`)에서,
이전 리뷰에서 지적된 핵심 불변식 문제가 보완되어 치명/중대 이슈를 찾지 못했습니다.

확인한 보완점:
- free 후 포인터 NULL 처리: `name`, `ranges`, `syms`, `btf`
- 메타데이터 동기화: `range_sz`, `syms_sz`, `syms_cap`
- 재로딩/잘못된 경로 방지용 상태 리셋: `type`, `sh_addr`, `sh_offset`

이 조합으로 다음 위험이 완화됩니다:
- 이중 free/댕글링 포인터 재해제
- `ranges == NULL`인데 `range_sz > 0`인 상태에서의 NULL 역참조
- free 이후 lazy reload 경로에서 stale metadata를 바탕으로 잘못된 재할당/재해석

---

## Residual Risks / Test Gaps

- 자동화 회귀 테스트 부재:
  - `dso__load_sym_table_*()` 에러 경로 후 `syms__free()` 호출 시 double-free가 재발하지 않는지 검증하는 테스트가 현재 PR에 포함되어 있지 않습니다.
  - 특히 `profile` 같은 호출자에서 err_out 이후 finalizer 경로를 함께 타는 시나리오를 재현하는 단위/통합 테스트가 있으면 안정성이 더 높아집니다.

---

## 결론

- **Approve 관점**: 현재 변경은 목적(이중 free 방지) 대비 충분히 타당하고, 수정 범위도 최소화되어 있습니다.
- **권장 후속(선택)**: 실패 경로 재진입 관련 회귀 테스트 1건 추가.
