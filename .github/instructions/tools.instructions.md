---
applyTo: "tools/**"
---

# BCC Tools (Python/BCC API) Review Instructions

Tools run in **mission-critical environments as root** — correctness and safety are mandatory.

> The global rules in `copilot-instructions.md` apply (NULL checks, bounds checks, 512-byte
> stack limit, 80-char output width). The rules below are additional requirements specific to
> this subsystem.

<CriticalRules>
- BPF C code: MUST NULL-check every `map.lookup(&key)` result before dereferencing.
- New tools MUST include man page (`man/man8/`) with an **OVERHEAD** section.
</CriticalRules>

## BCC API Safety

- Map lookup: use `table[key]` with `try/except KeyError`, or `table.get(key)` — check result is not `None` before use
- BPF C macro `map.lookup(&key)` returns a pointer — NULL means key not found; always guard before dereference
- Prefer map-based aggregation over per-event output for high-frequency events; filter in BPF, not Python

## Required Documentation (New Tools)

1. `man/man8/toolname.8` — with an **OVERHEAD** section
2. `tools/toolname_example.txt` — example output
3. `README.md` — entry added
4. `tests/python/test_tools_smoke.py` — smoke test entry

## Kernel Compatibility

- Use `BPF.kernel_struct_has_field()` for runtime struct field detection — never hard-code kernel version numbers
- New options must not break existing default behavior
