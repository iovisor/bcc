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
#ifndef LIBBCC_PROC_H
#define LIBBCC_PROC_H

#include "bcc_syms.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>


typedef struct mod_info {
  char *name;
  uint64_t start_addr;
  uint64_t end_addr;
  long long unsigned int file_offset;
  uint64_t dev_major;
  uint64_t dev_minor;
  uint64_t inode;
} mod_info;

// Module info, whether to check mount namespace, payload
// Callback returning a negative value indicates to stop the iteration
typedef int (*bcc_procutils_modulecb)(mod_info *, int, void *);

// Symbol name, address, payload
typedef void (*bcc_procutils_ksymcb)(const char *, const char *, uint64_t, void *);

char *bcc_procutils_which_so(const char *libname, int pid);
char *bcc_procutils_which(const char *binpath);
int bcc_mapping_is_file_backed(const char *mapname);
// Iterate over all executable memory mapping sections of a Process.
// All anonymous and non-file-backed mapping sections, namely those
// listed in bcc_mapping_is_file_backed, will be ignored.
// Returns -1 on error, and 0 on success
int bcc_procutils_each_module(int pid, bcc_procutils_modulecb callback,
                              void *payload);

int _procfs_maps_each_module(FILE *procmaps, int pid,
                             bcc_procutils_modulecb callback, void *payload);
// Iterate over all non-data Kernel symbols.
// Returns -1 on error, and 0 on success
int bcc_procutils_each_ksym(bcc_procutils_ksymcb callback, void *payload);
void bcc_procutils_free(const char *ptr);
const char *bcc_procutils_language(int pid);

#ifdef __cplusplus
}
#endif
#endif
