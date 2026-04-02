---
applyTo: "libbpf-tools/**/*"
---

# libbpf-tools (CO-RE) Review Instructions

These are CO-RE (Compile Once - Run Everywhere) tools using libbpf.

<CriticalRules>
- MUST use `vmlinux.h` for kernel types — do NOT redefine structs manually.
- MUST use `BPF_CORE_READ` (or `BPF_CORE_READ_USER` for user-space pointers)
  for kernel struct field access — no direct `task->pid` style access.
- MUST NULL-check every BPF map lookup result before dereferencing.
- MUST NULL-check every `malloc()`, `calloc()`, `realloc()`, and `strdup()` in userspace C.
- MUST bounds-check every array index before access.
- BPF functions: flag if stack usage appears to approach or exceed 512 bytes (eBPF verifier hard limit).
- Use `bpf_core_field_exists()` for kernel version compatibility — never `#if LINUX_VERSION_CODE`.
- Use split lifecycle: `__open()` → configure rodata/map sizes → `__load()` → `__attach()`.
  Flag `open_and_load()` if rodata fields or map max_entries are configured before load.
- Check return values of ALL attachment calls (`bpf_program__attach_*`).
- Do NOT use old-style map definitions (`bpf_map_def SEC("maps")`).
- Do NOT use hard-coded kernel version numbers or struct offsets.
- Do NOT create duplicate BPF programs with identical logic — use `bpf_program__set_attach_target()` instead.
- When providing both fentry and kprobe fallback paths: both paths must attach to the same
  set of kernel functions. Use `bpf_program__set_attach_target()` in the kprobe path to
  match the fentry path's attach targets.
</CriticalRules>

## libbpf Object Lifecycle

- Always split: `__open()` → set rodata/map config → `__load()` → `__attach()`
- Flag any use of `open_and_load()` where rodata or map `max_entries` are configured
- Check all return values; use `goto cleanup` pattern
- All resources (skel, FDs, links) freed on all exit paths including errors

## BPF Memory Safety

- NULL-check every `bpf_map_lookup_elem()` result before dereferencing
- Bounds-check every array index: `if (idx >= MAX_ENTRIES) return 0;`
- Check `bpf_probe_read_kernel()` return value: `if (ret < 0) return 0;`
- Keep per-function BPF stack usage well under 512 bytes; use per-CPU maps for large structs
- String reads: always use bounded helpers (`bpf_probe_read_kernel_str`, `bpf_get_current_comm`)

## Userspace Rules

- Output: default **< 80 characters wide**
- Error messages: clear, actionable, include `strerror(errno)` where applicable
- Map FD: check `bpf_map__fd()` result is ≥ 0 before use
- Use existing helpers (`trace_helpers.h`, `map_helpers.h`) — don't duplicate

## Required Files (New Tools)

### Code
1. `libbpf-tools/tool.bpf.c` — BPF program
2. `libbpf-tools/tool.c` — userspace program
3. `libbpf-tools/tool.h` — shared header (if needed)
4. Makefile entry for skeleton generation

### Documentation (enforce as blocker)
5. `man/man8/tool.8` — with **OVERHEAD** and **CAVEATS** sections
6. `README.md` — entry added
7. `libbpf-tools/tool_example.txt` — example output *(recommended; may be omitted if an
   equivalent Python tools/ example already exists)*

## Review Checklist

- [ ] CO-RE: `vmlinux.h` used; `BPF_CORE_READ` family for all kernel struct access
- [ ] Lifecycle: split open → configure → load → attach (flag premature `open_and_load`)
- [ ] BPF memory safety: NULL checks after map lookups, bounds checks, stack well under 512 bytes
- [ ] Userspace: NULL checks after all `malloc`/`calloc`/`realloc`/`strdup`
- [ ] All attach/map FD return values checked
- [ ] Resources freed on all paths (`goto cleanup`)
- [ ] BTF-style map definitions (no `bpf_map_def`)
- [ ] No hard-coded kernel versions or offsets
- [ ] No duplicate BPF programs; fentry and kprobe paths cover same attach targets
- [ ] Output < 80 chars wide
- [ ] Makefile skeleton generation entry present
- [ ] Documentation: man page + README entry (new tools); example file recommended

## References

- [libbpf Documentation](https://github.com/libbpf/libbpf)
- [BPF CO-RE Reference](https://nakryiko.com/posts/bpf-portability-and-co-re/)
