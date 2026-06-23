---
applyTo: "examples/**"
---

# BCC Examples Review Instructions

Examples are **educational** — prioritize clarity over production robustness.

<CriticalRules>
- Focus on **one concept** per example; target **< 150 lines** total.
- Every major BPF step MUST have an inline comment explaining **why**, not just what.
- Header comment MUST describe the concept demonstrated and usage.
- Do NOT add complex argument parsing or production-grade error handling — it obscures the learning point.
- License header MUST be present.
</CriticalRules>

## Required Header Comment

Every example must start with:
```
# example_name.py   Brief one-line description
# Demonstrates: [what BCC/eBPF concept this shows]
# USAGE: example_name.py
# Copyright [year] [author] / Licensed under Apache 2.0
```

## Pedagogical Quality

- One BCC concept per example; builds naturally on simpler ones
- Clear learning objective; do not mix maps + arrays + perf buffers + USDT in one example
- Output is labeled (column headers); explain what's being traced
- Minimal error handling: catch `BPF()` failure and `KeyboardInterrupt` only

## Kernel Compatibility

- Note kernel requirements in a comment when using features requiring ≥ 4.x
- Use `BPF.kernel_struct_has_field()` for runtime field detection; never hard-code kernel versions

## File Organization

- `networking/` — network-related examples
- `tracing/` — kernel/userspace tracing
- `usdt_sample/` — USDT examples
- `lua/` — Lua API examples
- `cpp/` — C++ API examples

## What Examples Do NOT Require

Unlike `tools/`, examples do **not** need:
- Man pages, `*_example.txt` files, README.md entries (optional)
- Comprehensive argparse argument handling
- Overhead documentation

## Review Checklist

- [ ] ≤ 150 lines; focuses on a single BCC concept
- [ ] Inline comments explain each BPF step
- [ ] Header comment describes purpose and concept demonstrated
- [ ] License header present
- [ ] Output is labeled and explained
- [ ] Basic error handling present (BPF compile failure, KeyboardInterrupt)
- [ ] Correct subdirectory placement
- [ ] Python 3 compatible
- [ ] No undocumented external dependencies

## Red Flags — Always Flag

1. > 150 lines or mixes too many concepts (belongs in `tools/` instead)
2. Missing inline comments on BPF logic
3. No header comment describing the concept demonstrated
4. Missing license header
5. No output or unexplained/unlabeled output
6. Python 2-only code (`print "..."`, `except Exception, e:`)
7. Undocumented external Python dependencies
