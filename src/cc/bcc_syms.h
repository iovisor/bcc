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
#ifndef LIBBCC_SYMS_H
#define LIBBCC_SYMS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct bcc_symbol {
  const char *name;
  const char *demangle_name;
  const char *module;
  uint64_t offset;
};

typedef int(* SYM_CB)(const char *symname, uint64_t addr);

void *bcc_symcache_new(int pid);
void bcc_free_symcache(void *symcache, int pid);

int bcc_symcache_resolve(void *symcache, uint64_t addr, struct bcc_symbol *sym);
int bcc_symcache_resolve_name(void *resolver, const char *name, uint64_t *addr);
void bcc_symcache_refresh(void *resolver);

int bcc_resolve_global_addr(int pid, const char *module, const uint64_t address,
                            uint64_t *global);
int bcc_foreach_symbol(const char *module, SYM_CB cb);
int bcc_find_symbol_addr(struct bcc_symbol *sym);
int bcc_resolve_symname(const char *module, const char *symname,
                        const uint64_t addr, int pid, struct bcc_symbol *sym);
#ifdef __cplusplus
}
#endif
#endif
