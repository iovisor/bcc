# BCC PR Code Review

Review the changes in this pull request against the BCC project standards.

## Step 1: Identify Changed File Categories

Determine which categories apply based on changed files:
- `tools/**/*.py` → apply tools/ rules
- `libbpf-tools/**/*` → apply libbpf-tools/ rules
- `src/cc/**` → apply core library rules
- `examples/**` → apply examples rules

## Step 2: General Checks (All PRs)

### Commit Message
- [ ] Has correct prefix (e.g., `tools/toolname:`, `libbpf-tools/toolname:`, `src/cc:`, `doc:`, `build:`, `tests/python:`)
- [ ] Body explains **WHY** the change is needed, not just what changed

## Step 3: Category-Specific Checks

### If tools/*.py changed:
- [ ] BPF C code: NULL checks after every map lookup
- [ ] BPF C code: bounds checks before array access
- [ ] Default output < 80 chars wide
- [ ] Filtering done in BPF, not Python
- [ ] Man page (`man/man8/`), example file, README entry present (new tools — blocker)
- [ ] Smoke test added to `tests/python/test_tools_smoke.py` (new tools)

### If libbpf-tools/* changed:
- [ ] Uses `BPF_CORE_READ()` — no direct struct field access
- [ ] Uses `vmlinux.h` — no manual struct redefinitions
- [ ] Split open → load → attach lifecycle (flag `open_and_load()` if rodata is configured)
- [ ] NULL checks after all map lookups
- [ ] NULL checks after all `malloc()`, `realloc()`, `strdup()` calls
- [ ] Bounds checks before all array accesses
- [ ] BPF stack usage ≤ 512 bytes
- [ ] BTF-style map definitions (not old-style `bpf_map_def`)
- [ ] All resources freed on all paths (`goto cleanup`)
- [ ] Return values of all attach calls checked (`bpf_program__attach_*`)
- [ ] No hard-coded kernel version numbers or struct offsets
- [ ] Makefile entry for skeleton generation
- [ ] fentry and kprobe handlers are symmetric (same functions in both)
- [ ] No duplicate BPF programs (prefer runtime attach target selection)
- [ ] Man page (`man/man8/`), README entry present (new tools — blocker)

### If src/cc/** changed:
- [ ] Public C++ API unchanged or deprecated gracefully
- [ ] Python bindings updated if C++ signature changed
- [ ] No memory leaks (RAII, smart pointers); NULL checks after all allocations
- [ ] LLVM version compatibility maintained (`#if LLVM_VERSION_MAJOR >= N`)
- [ ] `docs/reference_guide.md` updated for new public APIs

### If examples/** changed:
- [ ] ≤ 150 lines; focuses on a single BCC concept
- [ ] Inline comments explain BPF logic
- [ ] Header comment with purpose and concept demonstrated
- [ ] License header present

## Step 4: Output Format

Start your response with the headings and table below (no introductory text before `### 📝 Review Summary`).

### 📝 Review Summary

[Add overall assessment and summary of the review here]

### 🔍 Detailed Findings

| Severity | Location | Issue | Recommendation |
|---|---|---|---|
| 🔴 Critical<br>🟡 Warning<br>🔵 Info | `file.c:line` | [Description of the issue] | `[Suggested code snippet to fix]` |

**Overall Assessment:** Approve / Request Changes / Comment
