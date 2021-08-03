#include "containers.h"

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
