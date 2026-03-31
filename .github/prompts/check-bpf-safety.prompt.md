# BPF Safety Check

Perform a focused BPF safety and verifier-compliance check on the provided BPF C code.

## Memory Safety Checks

For each BPF map operation, verify:

```c
// Required pattern for map lookups:
struct val_t *val = map.lookup(&key);   // BCC C macro (only inside BPF programs, not Python)
if (!val)                               // ← MUST exist
    return 0;
val->field = ...;                       // Safe to access now

// libbpf BPF helper style (BPF program, libbpf-tools):
struct val_t *val = bpf_map_lookup_elem(&map, &key);
if (!val)                               // ← MUST exist
    return 0;
```

For each array/buffer access, verify:
```c
u32 idx = ...;
if (idx >= MAX_ENTRIES)  // ← MUST exist
    return 0;
array[idx] = value;
```

For each `bpf_probe_read_*` / `bpf_probe_read_kernel_str`, verify the return value is checked.

## Stack Usage Check

- Estimate total stack usage (sum of all local variables in each BPF function)
- Flag if any single function likely exceeds **512 bytes**
- Suggest moving large structs into per-CPU maps

## CO-RE Compliance (libbpf-tools only)

- All kernel struct accesses use `BPF_CORE_READ()` — flag any `task->pid` style access
- Kernel version checks use `bpf_core_field_exists()` — flag any `#if LINUX_VERSION_CODE`
- No manual struct redefinitions — all types come from `vmlinux.h`

## Helper Function Usage

For each BPF helper call, verify:
- Arguments are of the correct type (no passing user pointers to kernel-only helpers)
- Return values are checked where the helper can fail
- `bpf_get_current_comm()`, `bpf_probe_read_*`, etc. use `sizeof()` for size arguments

## Output Format

List each finding as:

| Severity | Location | Issue | Fix |
|---|---|---|---|
| 🔴 Critical | `file.bpf.c:42` | Missing NULL check after map lookup | Add `if (!val) return 0;` |
| 🟡 Warning | `file.bpf.c:78` | Unchecked bpf_probe_read_kernel return | Check `ret < 0` |
| 🔵 Info | `file.bpf.c:12` | Stack struct ~400 bytes, approaching limit | Monitor; move to map if adding fields |

End with: **PASS** (no critical issues) or **FAIL** (critical issues found).
