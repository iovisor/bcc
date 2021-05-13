/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Chenyue Zhou */
#ifndef STRING_HELPERS_H
#define STRING_HELPERS_H

#include <stddef.h>

void string_free_split(char **argv, int count);
int string_splitlen(const char *s, ssize_t len, const char *seq, int seqlen,
                    char ***res, int *count);
int string_join(char **argv, int argc, char *sep, int seqlen, char **res,
                ssize_t *res_len);
int string_replace(char *s, ssize_t s_len, char *from, char *to, char **res,
                   ssize_t *res_len);

#endif /* STRING_HELPERS_H */
