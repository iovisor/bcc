# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in BCC, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Email the maintainers at the [IOVisor mailing list](https://lists.iovisor.org/g/iovisor-dev) with a description of the issue.
3. Include steps to reproduce, affected versions, and any potential mitigations.
4. Allow reasonable time for a fix before public disclosure.

## Security Advisories

### BCC-2026-001: BPF C Code Injection via CLI Arguments

**Severity:** High
**Affected versions:** All versions prior to this fix
**CVSSv3 estimate:** 7.8 (Local / High)

**Description:**
43 Python-based BCC tools accepted command-line arguments (PIDs, TIDs, UIDs, signal numbers) as unvalidated strings and interpolated them directly into BPF C source code via `bpf_text.replace()`. A local attacker with the ability to influence tool invocation (e.g., through wrapper scripts, cron jobs, or shared automation) could inject arbitrary C code into kernel-loaded BPF programs.

**Example:**
```
# Before fix: this would inject C code into the BPF program
sudo tcptop.py -p '1234; } malicious(); if (0'
```

**Fix:**
All vulnerable `argparse` arguments now use `type=int` (or a custom `positive_int_list` validator for comma-separated signal lists), ensuring non-numeric input is rejected at argument parsing time before it reaches string interpolation.

**Affected tools:** tcptop, tcpconnlat, tcplife, tcpaccept, capable, cpudist, statsnoop, filelife, filegone, compactsnoop, vfsstat, ext4dist, shmsnoop, sofdsnoop, numasched, klockstat, opensnoop, drsnoop, tcpconnect, bindsnoop, nfsslower, xfsslower, zfsslower, ext4slower, btrfsslower, f2fsslower, execsnoop, killsnoop, ttysnoop, and 14 tools in `tools/old/`.

---

### BCC-2026-002: World-Writable Directory Permissions

**Severity:** Medium
**Affected versions:** All versions prior to this fix
**CVSSv3 estimate:** 5.5 (Local / Medium)

**Description:**
`src/cc/bpf_module.cc` created the BPF program tag cache directory (`/var/tmp/bcc/`) and its subdirectories with mode `0777` (world-writable). A local attacker could:

1. Create symlinks in the world-writable directory pointing to sensitive files.
2. When BCC writes cached BPF program source files, it would follow symlinks and overwrite arbitrary files owned by root.

**Fix:**
- Directory creation now uses mode `0700` (owner-only access).
- All `open()` calls include `O_NOFOLLOW` to refuse to follow symlinks.
- All `write()` return values are now checked for errors.

---

## Secure Usage Guidelines

1. **Always run BCC tools directly** — avoid passing user-controlled input to BCC tool arguments without validation.
2. **Restrict access** — BCC tools require root or `CAP_BPF`/`CAP_SYS_ADMIN`. Limit who can execute them.
3. **Keep BCC updated** — apply security patches promptly.
4. **Audit wrapper scripts** — if you wrap BCC tools in scripts that accept external input, validate all numeric arguments before passing them through.
