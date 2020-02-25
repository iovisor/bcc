#pragma once

#ifdef HAVE_EXTERNAL_LIBBPF
# include <bpf/bpf.h>
# include <bpf/btf.h>
# include <bpf/libbpf.h>
#else
# include "libbpf/src/bpf.h"
# include "libbpf/src/btf.h"
# include "libbpf/src/libbpf.h"
#endif
