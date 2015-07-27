/*
 * Copyright (c) 2015 PLUMgrid, Inc.
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

#ifndef BPF_COMMON_H
#define BPF_COMMON_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

void * bpf_module_create(const char *filename, const char *proto_filename, unsigned flags);
void * bpf_module_create_from_string(const char *text, unsigned flags);
void bpf_module_destroy(void *program);
char * bpf_module_license(void *program);
unsigned bpf_module_kern_version(void *program);
void * bpf_function_start(void *program, const char *name);
size_t bpf_function_size(void *program, const char *name);
int bpf_table_fd(void *program, const char *table_name);
const char * bpf_table_key_desc(void *program, const char *table_name);
const char * bpf_table_leaf_desc(void *program, const char *table_name);

#ifdef __cplusplus
}
#endif

#endif
