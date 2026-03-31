---
applyTo: "src/cc/**"
---

# BCC Core Library Review Instructions

All BCC tools depend on this code — stability and backward compatibility are critical.

> The global rules in `copilot-instructions.md` apply (NULL checks after allocations, bounds
> checks, 80-char output width). The rules below are additional requirements specific to the
> core library.

<CriticalRules>
- MUST NOT break public C++ APIs without a deprecation cycle.
- When changing a C++ function signature, MUST update `src/python/bcc/libbcc.py` ctypes bindings.
- MUST keep error handling consistent with the surrounding API's existing convention (negative return codes where that API uses them, or `StatusTuple` where that API uses `StatusTuple`).
- MUST guard all architecture-specific code with `#ifdef __x86_64__` / `#ifdef __aarch64__` etc.
</CriticalRules>

## API & ABI Stability

- Deprecate gracefully: use `__attribute__((deprecated("…")))` and a one-time `fprintf(stderr, "Warning: …")` in the old function body
- All new C++ APIs must be exposed to Python via ctypes; `argtypes` / `restype` must exactly match the C++ signature
- Handle `bytes` vs `str` encoding for Python 3 in all string-passing paths

## Memory & Resource Safety

- Use RAII / smart pointers (`std::unique_ptr`, `std::shared_ptr`) — no raw owning pointers
- Every allocation freed on **all** paths, including error paths (no FD/memory leaks)
- Thread-shared state protected with mutexes or atomics; document thread-safety guarantees

## LLVM/Clang Compatibility

- Check minimum LLVM version in `CMakeLists.txt` before using new APIs
- Gate version-specific code with `#if LLVM_VERSION_MAJOR >= N`

## Build System

- New optional dependencies guarded with `find_package` + `#ifdef HAVE_*`
- New deps added to both `CMakeLists.txt` and `debian/control`

## Documentation

- Update `docs/reference_guide.md` for new or changed public APIs
- Public functions: Doxygen-style comments (`@param`, `@return`)

## Review Checklist

- [ ] Public C++ API unchanged or deprecated gracefully
- [ ] Python bindings updated to match any C++ signature change
- [ ] No memory/FD leaks; RAII used
- [ ] NULL checks after every `malloc`/`calloc`/`realloc`/`strdup`
- [ ] Error handling consistent (follows surrounding API convention: negative return codes or `StatusTuple`)
- [ ] Thread safety considered for shared state
- [ ] Architecture-specific code guarded with `#ifdef`
- [ ] LLVM version compatibility maintained
- [ ] `docs/reference_guide.md` updated for new public APIs
- [ ] Build system changes correct (optional deps guarded)
- [ ] Code style consistent (run `scripts/c-style-check.sh`)

## Red Flags — Always Flag

1. Breaking C++ API change without deprecation
2. C++ signature changed but Python bindings not updated
3. Memory or FD leak (missing `close()`, `free()`, destructor)
4. Missing NULL check after allocation
5. Thread-safety violation on shared state
6. Platform-specific code without `#ifdef` guard
7. New LLVM API used without version guard
