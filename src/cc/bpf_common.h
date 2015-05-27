#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void * bpf_module_create(const char *filename, const char *proto_filename, unsigned flags);
void bpf_module_destroy(void *program);
char * bpf_module_license(void *program);
unsigned bpf_module_kern_version(void *program);
void * bpf_function_start(void *program, const char *name);
size_t bpf_function_size(void *program, const char *name);
int bpf_table_fd(void *program, const char *table_name);

#ifdef __cplusplus
}
#endif
