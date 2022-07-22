/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Google LLC. */
#ifndef __UPROBE_HELPERS_H
#define __UPROBE_HELPERS_H

#include <sys/types.h>
#include <unistd.h>
#include <gelf.h>

int get_pid_binary_path(pid_t pid, char *path, size_t path_sz);
int get_pid_lib_path(pid_t pid, const char *lib, char *path, size_t path_sz);
int resolve_binary_path(const char *binary, pid_t pid, char *path, size_t path_sz);
off_t get_elf_func_offset(const char *path, const char *func);
Elf *open_elf(const char *path, int *fd_close);
Elf *open_elf_by_fd(int fd);
void close_elf(Elf *e, int fd_close);

#endif /* __UPROBE_HELPERS_H */
