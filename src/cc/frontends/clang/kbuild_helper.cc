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
#include <fstream>
#include <iostream>

#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <unistd.h>

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
  } else if (!arch.compare(0, 7, "aarch64") || !arch.compare(0, 5, "arm64")) {
    arch = "arm64";
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
  }

  cflags->push_back("-nostdinc");
  cflags->push_back("-isystem");
  cflags->push_back("/virtual/lib/clang/include");

  // The include order from kernel top Makefile:
  //
  // # Use USERINCLUDE when you must reference the UAPI directories only.
  // USERINCLUDE    := \
  //                 -I$(srctree)/arch/$(SRCARCH)/include/uapi \
  //                 -I$(objtree)/arch/$(SRCARCH)/include/generated/uapi \
  //                 -I$(srctree)/include/uapi \
  //                 -I$(objtree)/include/generated/uapi \
  //                 -include $(srctree)/include/linux/kconfig.h
  //
  // # Use LINUXINCLUDE when you must reference the include/ directory.
  // # Needed to be compatible with the O= option
  // LINUXINCLUDE    := \
  //                 -I$(srctree)/arch/$(SRCARCH)/include \
  //                 -I$(objtree)/arch/$(SRCARCH)/include/generated \
  //                 $(if $(building_out_of_srctree),-I$(srctree)/include) \
  //                 -I$(objtree)/include \
  //                 $(USERINCLUDE)
  //
  // Some distros such as openSUSE/SUSE and Debian splits the headers between
  // source/ and build/. In this case, just $(srctree) is source/ and
  // $(objtree) is build/.
  if (has_source_dir_) {
    cflags->push_back("-Iarch/"+arch+"/include/");
    cflags->push_back("-I" + kdir_ + "/build/arch/"+arch+"/include/generated");
    cflags->push_back("-Iinclude");
    cflags->push_back("-I" + kdir_ + "/build/include");
    cflags->push_back("-Iarch/"+arch+"/include/uapi");
    cflags->push_back("-I" + kdir_ + "/build/arch/"+arch+"/include/generated/uapi");
    cflags->push_back("-Iinclude/uapi");
    cflags->push_back("-I" + kdir_ + "/build/include/generated/uapi");
  } else {
    cflags->push_back("-Iarch/"+arch+"/include/");
    cflags->push_back("-Iarch/"+arch+"/include/generated");
    cflags->push_back("-Iinclude");
    cflags->push_back("-Iarch/"+arch+"/include/uapi");
    cflags->push_back("-Iarch/"+arch+"/include/generated/uapi");
    cflags->push_back("-Iinclude/uapi");
    cflags->push_back("-Iinclude/generated/uapi");
  }

  cflags->push_back("-include");
  cflags->push_back("./include/linux/kconfig.h");
  cflags->push_back("-D__KERNEL__");
  cflags->push_back("-D__HAVE_BUILTIN_BSWAP16__");
  cflags->push_back("-D__HAVE_BUILTIN_BSWAP32__");
  cflags->push_back("-D__HAVE_BUILTIN_BSWAP64__");
  cflags->push_back("-DKBUILD_MODNAME=\"bcc\"");

  // If ARCH env variable is set, pass this along.
  if (archenv)
	cflags->push_back("-D__TARGET_ARCH_" + arch);

  cflags->push_back("-Wno-unused-value");
  cflags->push_back("-Wno-pointer-sign");
  cflags->push_back("-fno-stack-protector");

  return 0;
}

static inline int file_exists(const char *f)
{
  struct stat buffer;
  return (stat(f, &buffer) == 0);
}

static inline int proc_kheaders_exists(void)
{
  return file_exists(PROC_KHEADERS_PATH);
}

static inline int extract_kheaders(const std::string &dirpath,
                                   const struct utsname &uname_data)
{
  char tar_cmd[256], dirpath_tmp[256];
  int ret;
  bool module = false;

  if (!proc_kheaders_exists()) {
    ret = system("modprobe kheaders");
    if (ret)
      return ret;
    module = true;
    if (!proc_kheaders_exists()) {
      ret = -1;
      goto cleanup;
    }
  }

  snprintf(dirpath_tmp, sizeof(dirpath_tmp), "/tmp/kheaders-%s-XXXXXX", uname_data.release);
  if (mkdtemp(dirpath_tmp) == NULL) {
    ret = -1;
    goto cleanup;
  }

  if ((size_t)snprintf(tar_cmd, sizeof(tar_cmd), "tar -xf %s -C %s", PROC_KHEADERS_PATH, dirpath_tmp) >= sizeof(tar_cmd)) {
    ret = -1;
    goto cleanup;
  }
  ret = system(tar_cmd);
  if (ret) {
    system(("rm -rf " + std::string(dirpath_tmp)).c_str());
    goto cleanup;
  }

  /*
   * If the new directory exists, it could have raced with a parallel
   * extraction, in this case just delete the old directory and ignore.
   */
  ret = rename(dirpath_tmp, dirpath.c_str());
  if (ret)
    ret = system(("rm -rf " + std::string(dirpath_tmp)).c_str());

cleanup:
  if (module) {
    int ret1 = system("rmmod kheaders");
    if (ret1)
      return ret1;
  }

  return ret;
}

int get_proc_kheaders(std::string &dirpath)
{
  struct utsname uname_data;
  char dirpath_tmp[256];

  if (uname(&uname_data))
    return -errno;

  snprintf(dirpath_tmp, 256, "/tmp/kheaders-%s", uname_data.release);
  dirpath = std::string(dirpath_tmp);

  if (file_exists(dirpath_tmp))
    return 0;

  // First time so extract it
  return extract_kheaders(dirpath, uname_data);
}

}  // namespace ebpf
