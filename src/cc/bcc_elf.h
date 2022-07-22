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

#include <stddef.h>
#include <stdint.h>

struct bcc_elf_usdt {
  uint64_t pc;
  uint64_t base_addr;
  // Virtual address semaphore is found at
  uint64_t semaphore;

  const char *provider;
  const char *name;
  const char *arg_fmt;

  // Offset from start of file where the semaphore is at
  uint64_t semaphore_offset;
};

// Binary module path, bcc_elf_usdt struct, payload
typedef void (*bcc_elf_probecb)(const char *, const struct bcc_elf_usdt *,
                                void *);
// Symbol name, start address, length, payload
// Callback returning a negative value indicates to stop the iteration
typedef int (*bcc_elf_symcb)(const char *, uint64_t, uint64_t, void *);
// Section idx, str table idx, str length, start address, length, payload
typedef int (*bcc_elf_symcb_lazy)(size_t, size_t, size_t, uint64_t, uint64_t,
             int, void *);
// Segment virtual address, memory size, file offset, payload
// Callback returning a negative value indicates to stop the iteration
typedef int (*bcc_elf_load_sectioncb)(uint64_t, uint64_t, uint64_t, void *);

// Iterate over all USDT probes noted in a binary module
// Returns -1 on error, and 0 on success
int bcc_elf_foreach_usdt(const char *path, bcc_elf_probecb callback,
                         void *payload);
// Iterate over all executable load sections of an ELF
// Returns -1 on error, 1 if stopped by callback, and 0 on success
int bcc_elf_foreach_load_section(const char *path,
                                 bcc_elf_load_sectioncb callback,
                                 void *payload);
// Iterate over symbol table of a binary module
// Parameter "option" points to a bcc_symbol_option struct to indicate whether
// and how to use debuginfo file, and what types of symbols to load.
// Returns -1 on error, and 0 on success or stopped by callback
int bcc_elf_foreach_sym(const char *path, bcc_elf_symcb callback, void *option,
                        void *payload);
// Similar to bcc_elf_foreach_sym, but pass reference to symbolized string along
// with symbolized string length
int bcc_elf_foreach_sym_lazy(const char *path, bcc_elf_symcb_lazy callback,
                             void *option, void *payload);
// Iterate over all symbols from current system's vDSO
// Returns -1 on error, and 0 on success or stopped by callback
int bcc_elf_foreach_vdso_sym(bcc_elf_symcb callback, void *payload);

int bcc_elf_get_text_scn_info(const char *path, uint64_t *addr,
                              uint64_t *offset);

int bcc_elf_get_type(const char *path);
int bcc_elf_is_shared_obj(const char *path);
int bcc_elf_is_exe(const char *path);
int bcc_elf_is_vdso(const char *name);
int bcc_free_memory();
int bcc_elf_get_buildid(const char *path, char *buildid);
int bcc_elf_symbol_str(const char *path, size_t section_idx,
                       size_t str_table_idx, char *out, size_t len,
                       int debugfile);

#ifdef __cplusplus
}
#endif
#endif
