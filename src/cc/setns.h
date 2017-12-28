// This file is only needed to support build for CentOS 6
// Remove it when no longer needed.
// File is trivial and therefore is in public domain.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <sys/syscall.h>

#define setns(FD, NSTYPE) syscall(__NR_setns, (int)(FD), (int)(NSTYPE))
