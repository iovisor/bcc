#pragma once

#ifdef HAVE_EXTERNAL_LIBBPF
# include <bpf/uapi/linux/bpf.h>
# include <bpf/uapi/linux/bpf_common.h>
# include <bpf/uapi/linux/btf.h>
#else
# include <linux/bpf.h>
# include <linux/bpf_common.h>
# include <linux/btf.h>
#endif
