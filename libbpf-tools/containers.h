/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __CONTAINERS_H
#define __CONTAINERS_H

#include <stdint.h>

#define MAX_CONTAINERS_PER_NODE 1024
#define NAME_MAX_LENGTH 256

struct container {
	char container_id[NAME_MAX_LENGTH];
	char kubernetes_namespace[NAME_MAX_LENGTH];
	char kubernetes_pod[NAME_MAX_LENGTH];
	char kubernetes_container[NAME_MAX_LENGTH];
	// this field is not present in the containers map so it's added as the last one here
	char node[NAME_MAX_LENGTH];
};

struct container get_container_info(int map_fd, uint64_t mtnnsid);

void print_container_info_header(void);

#endif /* __CONTAINERS_H */
