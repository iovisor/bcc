#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void * bpf_program_create(const char *filename, const char *proto_filename, unsigned flags);
void bpf_program_destroy(void *program);
void * bpf_program_start(void *program, const char *name);
size_t bpf_program_size(void *program, const char *name);
char * bpf_program_license(void *program);
unsigned bpf_program_kern_version(void *program);
int bpf_program_table_fd(void *program, const char *table_name);

#ifdef __cplusplus
}
#endif
