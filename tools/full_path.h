// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Rong Tao */
/**
 * This code only for bcc/tools/, not for bcc/libbpf-tools/
 */
#pragma once
#ifndef __FULL_PATH_H
#define __FULL_PATH_H

#define NAME_MAX 255
#define MAX_ENTRIES 32

/**
 * Example: "/CCCCC/BB/AAAA"
 * name[]: "AAAA000000000000BB0000000000CCCCC00000000000"
 *          |<- NAME_MAX ->|
 *
 * name[] must be u8, because char [] will be truncated by ctypes.cast(),
 * such as above example, will be truncated to "AAAA0".
 */
#define FULL_PATH_FIELD(name)	u8 name[NAME_MAX * MAX_ENTRIES];
#endif
