/*
 * Copyright (c) 2016 GitHub, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LIBBCC_ELF_H
#define LIBBCC_ELF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

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
