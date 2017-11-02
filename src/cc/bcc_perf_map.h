/*
 * Copyright (c) 2016 Facebook, Inc.
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
#ifndef LIBBCC_PERF_MAP_H
#define LIBBCC_PERF_MAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

// Symbol name, start address, length, payload
typedef int (*bcc_perf_map_symcb)(const char *, uint64_t, uint64_t, void *);

bool bcc_is_perf_map(const char *path);
bool bcc_is_valid_perf_map(const char *path);

int bcc_perf_map_nstgid(int pid);
bool bcc_perf_map_path(char *map_path, size_t map_len, int pid);
int bcc_perf_map_foreach_sym(const char *path, bcc_perf_map_symcb callback,
                             void* payload);

#ifdef __cplusplus
}
#endif
#endif
