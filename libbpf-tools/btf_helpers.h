/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __BTF_HELPERS_H
#define __BTF_HELPERS_H

#include <bpf/libbpf.h>

int ensure_core_btf(struct bpf_object_open_opts *opts);
void cleanup_core_btf(struct bpf_object_open_opts *opts);

#endif /* __BTF_HELPERS_H */
