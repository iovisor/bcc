/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Facebook */
#ifndef __BASHREADLINE_H
#define __BASHREADLINE_H

#define MAX_LINE_SIZE 80

struct str_t {
	__u32 pid;
	char str[MAX_LINE_SIZE];
};

#endif /* __BASHREADLINE_H */
