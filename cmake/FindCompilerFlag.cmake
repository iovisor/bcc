# Copyright (c) 2017 Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

if (CMAKE_C_COMPILER_ID MATCHES "Clang")
	set(COMPILER_NOPIE_FLAG "-nopie")
else()
	set(_backup_c_flags "${CMAKE_REQUIRED_FLAGS}")
	set(CMAKE_REQUIRED_FLAGS "-no-pie")
	CHECK_CXX_SOURCE_COMPILES("int main() {return 0;}"
				  HAVE_NO_PIE_FLAG)
	if (HAVE_NO_PIE_FLAG)
		set(COMPILER_NOPIE_FLAG "-no-pie")
	else()
		set(COMPILER_NOPIE_FLAG "")
	endif()
	set(CMAKE_REQUIRED_FLAGS "${_backup_c_flags}")
endif()

# check whether reallocarray availability
# this is used to satisfy reallocarray usage under src/cc/libbpf/
CHECK_CXX_SOURCE_COMPILES(
"
#define _GNU_SOURCE
#include <stdlib.h>

int main(void)
{
        return !!reallocarray(NULL, 1, 1);
}
" HAVE_REALLOCARRAY_SUPPORT)
