#ifndef LIBBCC_ELF_H
#define LIBBCC_ELF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct bcc_symbol {
	const char *name;
	const char *module;
	uint64_t offset;
};

struct bcc_elf_usdt {
	uint64_t pc;
	uint64_t base_addr;
	uint64_t semaphore;

	const char *provider;
	const char *name;
	const char *arg_fmt;
};

typedef void (*bcc_elf_probecb)(const char *, const struct bcc_elf_usdt *, void *);
typedef int (*bcc_elf_symcb)(const char *, uint64_t, uint64_t, int, void *);

int bcc_elf_foreach_usdt(const char *path, bcc_elf_probecb callback, void *payload);
int bcc_elf_loadaddr(const char *path, uint64_t *address);
int bcc_elf_foreach_sym(const char *path, bcc_elf_symcb callback, void *payload);
int bcc_elf_is_shared_obj(const char *path);


typedef void (*bcc_procutils_modulecb)(const char *, uint64_t, uint64_t, void *);
typedef void (*bcc_procutils_ksymcb)(const char *, uint64_t, void *);

const char *bcc_procutils_which_so(const char *libname);
char *bcc_procutils_which(const char *binpath);
int bcc_procutils_each_module(int pid, bcc_procutils_modulecb callback, void *payload);
int bcc_procutils_each_ksym(bcc_procutils_ksymcb callback, void *payload);

int bcc_resolve_symname(const char *module, const char *symname, const uint64_t addr,
		struct bcc_symbol *sym);
void *bcc_symcache_new(int pid);
int bcc_symcache_resolve(void *symcache, uint64_t addr, struct bcc_symbol *sym);
int bcc_symcache_resolve_name(void *resolver, const char *name, uint64_t *addr);
void bcc_symcache_refresh(void *resolver);

#ifdef __cplusplus
}
#endif
#endif
