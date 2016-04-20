#ifndef LIBBCC_ELF_H
#define LIBBCC_ELF_H

#ifdef __cplusplus
extern "C" {
#endif

struct bcc_elf_usdt {
  uint64_t pc;
  uint64_t base_addr;
  uint64_t semaphore;

  const char *provider;
  const char *name;
  const char *arg_fmt;
};

typedef void (*bcc_elf_probecb)(const char *, const struct bcc_elf_usdt *,
                                void *);
typedef int (*bcc_elf_symcb)(const char *, uint64_t, uint64_t, int, void *);

int bcc_elf_foreach_usdt(const char *path, bcc_elf_probecb callback,
                         void *payload);
int bcc_elf_loadaddr(const char *path, uint64_t *address);
int bcc_elf_foreach_sym(const char *path, bcc_elf_symcb callback,
                        void *payload);
int bcc_elf_is_shared_obj(const char *path);

#ifdef __cplusplus
}
#endif
#endif
