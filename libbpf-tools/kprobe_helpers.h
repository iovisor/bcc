/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Chenyue Zhou */
#ifndef KPROBE_HELPERS_H
#define KPROBE_HELPERS_H

#ifdef __cplusplus
extern "C" {
#endif

#define KPROBE_LIMIT          1024
#define KPROBE_BLACKLIST_FILE "/sys/kernel/debug/kprobes/blacklist"

int get_kprobe_functions(const char *pattern, char ***list, size_t *sz);

void free_kprobe_functions(char **list, size_t sz);

#ifdef __cplusplus
}
#endif
#endif /* KPROBE_HELPERS_H */
