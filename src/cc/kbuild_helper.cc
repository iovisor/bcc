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
#include <ftw.h>
#include "kbuild_helper.h"

namespace ebpf {

using std::string;
using std::vector;

KBuildHelper::KBuildHelper() {
  char *home = ::getenv("HOME");
  if (home)
    cache_dir_ = string(home) + "/.cache/bcc";
  else
    cache_dir_ = "/var/run/bcc";
}

// Makefile helper for kbuild_flags
int KBuildHelper::learn_flags(const string &tmpdir, const char *uname_release, const char *cachefile) {
  {
    // Create a kbuild file to generate the flags
    string makefile = tmpdir + "/Makefile";
    FILEPtr mf(::fopen(makefile.c_str(), "w"));
    if (!mf)
      return -1;
    fprintf(&*mf, "obj-y := dummy.o\n");
    fprintf(&*mf, "CACHEDIR=$(dir %s)\n", cachefile);
    fprintf(&*mf, "$(CACHEDIR):\n");
    fprintf(&*mf, "\t@mkdir -p $(CACHEDIR)\n");
    fprintf(&*mf, "$(obj)/%%.o: $(src)/%%.c $(CACHEDIR)\n");
    fprintf(&*mf, "\t@echo -n \"$(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) "
                    "-D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \" > %s\n", cachefile);
  }
  {
    string cfile = tmpdir + "/dummy.c";
    FILEPtr cf(::fopen(cfile.c_str(), "w"));
    if (!cf)
      return -1;
  }
  string cmd = "make -s";
  cmd += " -C " KERNEL_MODULES_DIR "/" + string(uname_release) + "/build";
  cmd += " M=" + tmpdir + " dummy.o";
  int rc = ::system(cmd.c_str());
  if (rc < 0) {
    ::perror("system");
    return -1;
  }
  return ::open(cachefile, O_RDONLY);
}

// read the flags from cache or learn
int KBuildHelper::get_flags(const char *uname_release, vector<string> *cflags) {
  char cachefile[256];
  snprintf(cachefile, sizeof(cachefile), "%s/%s.flags", cache_dir_.c_str(), uname_release);
  int cachefd = ::open(cachefile, O_RDONLY);
  if (cachefd < 0) {
    TmpDir tmpdir;
    if (!tmpdir.ok())
      return -1;
    cachefd = learn_flags(tmpdir.str(), uname_release, cachefile);
    if (cachefd < 0)
      return -1;
  }
  FILEPtr f(::fdopen(cachefd, "r"));
  size_t len = 0;
  char *line = NULL;
  ssize_t nread;
  while ((nread = getdelim(&line, &len, ' ', &*f)) >= 0) {
    if (nread == 0 || (nread == 1 && line[0] == ' ')) continue;
    if (line[nread - 1] == ' ')
      --nread;
    cflags->push_back(string(line, nread));
  }
  free(line);
  return 0;
}

}  // namespace ebpf
