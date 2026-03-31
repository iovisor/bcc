---
applyTo: ".github/instructions/*.instructions.md"
---

# Authoring BCC Instruction Files

These files define Copilot review rules for the BCC project.
When editing them, follow the steps below to avoid writing rules that contradict
the actual codebase.

## Before Writing or Updating Any Rule

1. **API / function examples** — read the actual source before writing:
   - Python BCC API → check `src/python/bcc/table.py`
   - BPF helper signatures → check `libbpf-tools/*.bpf.c` examples
   - Userspace libbpf patterns → check `libbpf-tools/*.c` examples

2. **Conventions (shebang, imports, prefixes, etc.)** — sample the real files:
   - `tools/*.py` for Python conventions (shebang)
   - `libbpf-tools/*.c` / `*.bpf.c` for C conventions
   - `git log --oneline origin/master | head -30` for commit prefix convention (format: `subsystem/toolname:`)

3. **Do not invent or assume** an API method, macro, or convention exists —
   verify it in the repo first.

## Scope of Each Instructions File

| File | `applyTo` | Triggers when… |
|------|-----------|----------------|
| `tools.instructions.md` | `tools/**/*.py` | editing a Python tool |
| `libbpf-tools.instructions.md` | `libbpf-tools/**/*` | editing a libbpf tool |
| `core.instructions.md` | `src/cc/**` | editing BCC core library |
| `examples.instructions.md` | `examples/**` | editing an example |
| `instructions.instructions.md` | `.github/instructions/*.instructions.md` | editing these rule files |

## Style

- Keep `<CriticalRules>` short — Copilot has a ~4,000 character review window
- One rule per bullet; no redundancy across files
- Flag blockers explicitly; use 🟡 Warning for non-blockers
