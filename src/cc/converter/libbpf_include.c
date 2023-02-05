#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "maps.bpf.h"
#include "bits.bpf.h"
// #include "core_fixes.bpf.h"

#define REQ_OP_BITS	8
#define REQ_OP_MASK	((1 << REQ_OP_BITS) - 1)
#define REQ_FLAG_BITS	24

#define AF_INET	2
#define AF_INET6 10
#define NSEC_PER_SEC		1000000000ULL

