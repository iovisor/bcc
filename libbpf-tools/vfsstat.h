// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
#ifndef __VFSSTAT_H
#define __VFSSTAT_H

enum stat_types {
	S_READ,
	S_WRITE,
	S_FSYNC,
	S_OPEN,
	S_CREATE,
	S_UNLINK,
	S_MKDIR,
	S_RMDIR,
	S_MAXSTAT,
};

#endif /* __VFSSTAT_H */
