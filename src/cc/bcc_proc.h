#ifndef LIBBCC_PROC_H
#define LIBBCC_PROC_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*bcc_procutils_modulecb)(const char *, uint64_t, uint64_t,
                                       void *);
typedef void (*bcc_procutils_ksymcb)(const char *, uint64_t, void *);

const char *bcc_procutils_which_so(const char *libname);
char *bcc_procutils_which(const char *binpath);
int bcc_procutils_each_module(int pid, bcc_procutils_modulecb callback,
                              void *payload);
int bcc_procutils_each_ksym(bcc_procutils_ksymcb callback, void *payload);

int bcc_resolve_symname(const char *module, const char *symname,
                        const uint64_t addr, struct bcc_symbol *sym);

#ifdef __cplusplus
}
#endif
#endif
