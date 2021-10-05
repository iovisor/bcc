#include "containers.h"

#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>

struct container get_container_info(int map_fd, uint64_t mtnnsid) {
	struct container container = {
		.kubernetes_namespace = "<>",
		.kubernetes_pod = "<>",
		.kubernetes_container = "<>",
		.node = "<>"
	};

	bpf_map_lookup_elem(map_fd, &mtnnsid, &container);

	strncpy(container.node, getenv("NODE_NAME"), NAME_MAX_LENGTH - 1);

	return container;
}

const char *NODE_HEADER = "NODE";
const char *NAMESPACE_HEADER = "NAMESPACE";
const char *POD_HEADER = "POD";
const char *CONTAINER_HEADER = "CONTAINER";

void print_container_info_header(void) {
	/*
	 * Format options used are the following:
	 * - is used to left justify the data printed.
	 * 16 is used to indicate the minimal width of the data printed, if data are
	 * less than 16, spaces will be added.
	 *
	 * These options ensures data printed will be, at least, 16 characters long
	 * left justified.
	 */
	printf("%-16s %-16s %-16s %-16s ", NODE_HEADER, NAMESPACE_HEADER,
	       POD_HEADER, CONTAINER_HEADER);
}
