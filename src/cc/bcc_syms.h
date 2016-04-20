#ifndef LIBBCC_SYMS_H
#define LIBBCC_SYMS_H

#ifdef __cplusplus
extern "C" {
#endif

struct bcc_symbol {
  const char *name;
  const char *module;
  uint64_t offset;
};

void *bcc_symcache_new(int pid);
int bcc_symcache_resolve(void *symcache, uint64_t addr, struct bcc_symbol *sym);
int bcc_symcache_resolve_name(void *resolver, const char *name, uint64_t *addr);
void bcc_symcache_refresh(void *resolver);

#ifdef __cplusplus
}
#endif
#endif
