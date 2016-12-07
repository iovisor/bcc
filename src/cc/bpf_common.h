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

void * bpf_module_create_b(const char *filename, const char *proto_filename, unsigned flags);
void * bpf_module_create_c(const char *filename, unsigned flags, const char *cflags[], int ncflags);
void * bpf_module_create_c_from_string(const char *text, unsigned flags, const char *cflags[], int ncflags);
void bpf_module_destroy(void *program);
char * bpf_module_license(void *program);
unsigned bpf_module_kern_version(void *program);
size_t bpf_num_functions(void *program);
const char * bpf_function_name(void *program, size_t id);
void * bpf_function_start_id(void *program, size_t id);
void * bpf_function_start(void *program, const char *name);
size_t bpf_function_size_id(void *program, size_t id);
size_t bpf_function_size(void *program, const char *name);
size_t bpf_num_tables(void *program);
size_t bpf_table_id(void *program, const char *table_name);
int bpf_table_fd(void *program, const char *table_name);
int bpf_table_fd_id(void *program, size_t id);
int bpf_table_type(void *program, const char *table_name);
int bpf_table_type_id(void *program, size_t id);
size_t bpf_table_max_entries(void *program, const char *table_name);
size_t bpf_table_max_entries_id(void *program, size_t id);
int bpf_table_flags(void *program, const char *table_name);
int bpf_table_flags_id(void *program, size_t id);
const char * bpf_table_name(void *program, size_t id);
const char * bpf_table_key_desc(void *program, const char *table_name);
const char * bpf_table_key_desc_id(void *program, size_t id);
const char * bpf_table_leaf_desc(void *program, const char *table_name);
const char * bpf_table_leaf_desc_id(void *program, size_t id);
size_t bpf_table_key_size(void *program, const char *table_name);
size_t bpf_table_key_size_id(void *program, size_t id);
size_t bpf_table_leaf_size(void *program, const char *table_name);
size_t bpf_table_leaf_size_id(void *program, size_t id);
int bpf_table_key_snprintf(void *program, size_t id, char *buf, size_t buflen, const void *key);
int bpf_table_leaf_snprintf(void *program, size_t id, char *buf, size_t buflen, const void *leaf);
int bpf_table_key_sscanf(void *program, size_t id, const char *buf, void *key);
int bpf_table_leaf_sscanf(void *program, size_t id, const char *buf, void *leaf);

#ifdef __cplusplus
}
#endif

#endif
