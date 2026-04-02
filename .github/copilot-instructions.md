# BCC Project — GitHub Copilot Instructions

BCC is a toolkit for creating efficient kernel tracing and manipulation programs using eBPF. Tools run in **mission-critical environments as root**.

## Global Review Principles (Applied to all PRs)

### Commit Message Format

```
<prefix>: <short summary>

<WHY this change is needed — not just what changed>
- Problem being solved
- Why this approach was chosen
```

**Prefixes:** `tools/toolname:`, `libbpf-tools/toolname:`, `src/cc:`, `build:`, `ci:`, `doc:`, `tests/python:`

### Style Checks

- **Python:** `scripts/py-style-check.sh` (pycodestyle, ignore E123/E125/E126/E127/E128/E302)
- **C/C++:** `scripts/c-style-check.sh` (git clang-format against master)

<CriticalRules>
- MUST perform a NULL check after any BPF C Map lookup.
- MUST perform a NULL check after every `malloc()`, `calloc()`, `realloc()`, and `strdup()` call in userspace C code.
- MUST perform a bounds check for all array accesses.
- BPF C functions: flag if stack usage appears to approach or exceed 512 bytes (eBPF verifier hard limit).
- Default output format MUST be under 80 characters wide.
</CriticalRules>

### Documentation Requirements (New Tools)

All **new tools** require these **minimum** files (enforce as blocker):
1. Tool script
2. Man page (`man/man8/`) with **OVERHEAD** and **CAVEATS** sections
3. `README.md` entry

Additional per-subsystem requirements apply — defer to the relevant
`instructions/*.instructions.md` file (e.g., `tools.instructions.md` also
requires `tests/python/test_tools_smoke.py`; `*_example.txt` is required for
`tools/` but recommended for `libbpf-tools/`).

For **bug-fix or enhancement PRs on existing tools**: flag missing docs as 🟡 Warning, not a blocker.
> Note: ~14% of libbpf-tools currently ship without a man page — this is a known gap, not a reason to skip the requirement for new tools.

### Unix Philosophy

- Do one thing and do it well
- Default output **< 80 characters wide**
- Prefer short tool names; avoid underscores for new tools unless needed for
  clarity or to match an existing naming pattern (e.g., `mysqld_qslower`)
- Prefer a positional argument for the most common parameter (e.g., interval) over a flag,
  where it makes sense for the tool's use case
