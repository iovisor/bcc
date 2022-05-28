// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Hengqi Chen */
#ifndef __MYSQLD_QSLOWER_H
#define __MYSQLD_QSLOWER_H

#define QUERY_MAX	256

struct start {
	__u64 ts;
	const char *query;
};

struct event {
	__u64 ts;
	__u64 lat_ns;
	__u32 pid;
	char query[QUERY_MAX];
};

#endif /* __MYSQLD_QSLOWER_H */
