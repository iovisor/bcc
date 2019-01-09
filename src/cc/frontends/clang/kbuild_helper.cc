/*
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <fcntl.h>
#include <stdlib.h>
#include <iostream>
#include "kbuild_helper.h"

namespace ebpf {

using std::string;
using std::vector;

KBuildHelper::KBuildHelper(const std::string &kdir, bool has_source_dir) : kdir_(kdir),
                                                                           has_source_dir_(has_source_dir) {
}

// read the flags from cache or learn
int KBuildHelper::get_flags(const char *uname_machine, vector<string> *cflags) {
  //uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/sun4u/sparc64/ -e s/arm.*/arm/
  //               -e s/sa110/arm/ -e s/s390x/s390/ -e s/parisc64/parisc/
  //               -e s/ppc.*/powerpc/ -e s/mips.*/mips/ -e s/sh[234].*/sh/
  //               -e s/aarch64.*/arm64/

  string arch;
  const char *archenv = getenv("ARCH");
  // If ARCH env is defined, use it over uname
  if (archenv)
    arch = string(archenv);
  else
    arch = string(uname_machine);

  if (!arch.compare(0, 6, "x86_64")) {
    arch = "x86";
  } else if (arch[0] == 'i' && !arch.compare(2, 2, "86")) {
    arch = "x86";
  } else if (!arch.compare(0, 3, "arm")) {
    arch = "arm";
  } else if (!arch.compare(0, 5, "sa110")) {
    arch = "arm";
  } else if (!arch.compare(0, 5, "s390x")) {
    arch = "s390";
  } else if (!arch.compare(0, 8, "parisc64")) {
    arch = "parisc";
  } else if (!arch.compare(0, 3, "ppc")) {
    arch = "powerpc";
  } else if (!arch.compare(0, 4, "mips")) {
    arch = "mips";
  } else if (!arch.compare(0, 2, "sh")) {
    arch = "sh";
  } else if (!arch.compare(0, 7, "aarch64")) {
    arch = "arm64";
  }

  cflags->push_back("-nostdinc");
  cflags->push_back("-isystem");
  cflags->push_back("/virtual/lib/clang/include");

  // some module build directories split headers between source/ and build/
  if (has_source_dir_) {
    cflags->push_back("-I" + kdir_ + "/build/arch/"+arch+"/include");
    cflags->push_back("-I" + kdir_ + "/build/arch/"+arch+"/include/generated/uapi");
    cflags->push_back("-I" + kdir_ + "/build/arch/"+arch+"/include/generated");
    cflags->push_back("-I" + kdir_ + "/build/include");
    cflags->push_back("-I" + kdir_ + "/build/./arch/"+arch+"/include/uapi");
    cflags->push_back("-I" + kdir_ + "/build/arch/"+arch+"/include/generated/uapi");
    cflags->push_back("-I" + kdir_ + "/build/include/uapi");
    cflags->push_back("-I" + kdir_ + "/build/include/generated");
    cflags->push_back("-I" + kdir_ + "/build/include/generated/uapi");
  }

  cflags->push_back("-I./arch/"+arch+"/include");
  cflags->push_back("-Iarch/"+arch+"/include/generated/uapi");
  cflags->push_back("-Iarch/"+arch+"/include/generated");
  cflags->push_back("-Iinclude");
  cflags->push_back("-I./arch/"+arch+"/include/uapi");
  cflags->push_back("-Iarch/"+arch+"/include/generated/uapi");
  cflags->push_back("-I./include/uapi");
  cflags->push_back("-Iinclude/generated/uapi");
  cflags->push_back("-include");
  cflags->push_back("./include/linux/kconfig.h");
  cflags->push_back("-D__KERNEL__");
  cflags->push_back("-D__HAVE_BUILTIN_BSWAP16__");
  cflags->push_back("-D__HAVE_BUILTIN_BSWAP32__");
  cflags->push_back("-D__HAVE_BUILTIN_BSWAP64__");

  // If ARCH env variable is set, pass this along.
  if (archenv)
	cflags->push_back("-D__TARGET_ARCH_" + arch);

  cflags->push_back("-Wno-unused-value");
  cflags->push_back("-Wno-pointer-sign");
  cflags->push_back("-fno-stack-protector");

  return 0;
}

}  // namespace ebpf
