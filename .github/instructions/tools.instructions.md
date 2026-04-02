---
applyTo: "tools/**/*.py"
---

# BCC Tools (Python/BCC API) Review Instructions

Tools run in **mission-critical environments as root** — correctness and safety are mandatory.

<CriticalRules>
- BPF C code: MUST NULL-check every `map.lookup(&key)` result before dereferencing.
- BPF C code: MUST bounds-check every array index before access.
- BPF C code: flag if stack usage appears to approach or exceed 512 bytes (eBPF verifier hard limit).
- Default output MUST be under 80 characters wide.
- New tools MUST include man page (`man/man8/`) with **OVERHEAD** and **CAVEATS** sections.
</CriticalRules>

## BCC API Safety

- Map lookup: use `table[key]` with `try/except KeyError`, or `table.get(key)` — check result is not `None` before use
- BPF C macro `map.lookup(&key)` returns a pointer — NULL means key not found; always guard before dereference
- Prefer map-based aggregation over per-event output for high-frequency events; filter in BPF, not Python

## Required Documentation (New Tools)

1. `man/man8/toolname.8` — with **OVERHEAD** and **CAVEATS** sections
2. `tools/toolname_example.txt` — example output
3. `README.md` — entry added
4. `tests/python/test_tools_smoke.py` — smoke test entry

## Kernel Compatibility

- Use `BPF.kernel_struct_has_field()` for runtime struct field detection — never hard-code kernel version numbers
- New options must not break existing default behavior
