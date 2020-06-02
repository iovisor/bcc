/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SYSCALL_HELPERS_H
#define __SYSCALL_HELPERS_H

#include <stddef.h>

void init_syscall_names(void);
void free_syscall_names(void);
void list_syscalls(void);
void syscall_name(unsigned n, char *buf, size_t size);

#endif /* __SYSCALL_HELPERS_H */
