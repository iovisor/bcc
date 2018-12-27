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
#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include <unistd.h>
#include <errno.h>
#include <ftw.h>

namespace ebpf {

struct FileDeleter {
  void operator() (FILE *fp) {
    fclose(fp);
  }
};
typedef std::unique_ptr<FILE, FileDeleter> FILEPtr;

// Helper with pushd/popd semantics
class DirStack {
 public:
  explicit DirStack(const std::string &dst) : ok_(false) {
    if (getcwd(cwd_, sizeof(cwd_)) == NULL) {
      ::perror("getcwd");
      return;
    }
    if (::chdir(dst.c_str())) {
      fprintf(stderr, "chdir(%s): %s\n", dst.c_str(), strerror(errno));
      return;
    }
    ok_ = true;
  }
  ~DirStack() {
    if (!ok_) return;
    if (::chdir(cwd_)) {
      fprintf(stderr, "chdir(%s): %s\n", cwd_, strerror(errno));
    }
  }
  bool ok() const { return ok_; }
  const char * cwd() const { return cwd_; }
 private:
  bool ok_;
  char cwd_[256];
};

static int ftw_cb(const char *path, const struct stat *, int, struct FTW *) {
  return ::remove(path);
}

// Scoped class to manage the creation/deletion of tmpdirs
class TmpDir {
 public:
  explicit TmpDir(const std::string &prefix = "/tmp/bcc-")
      : ok_(false), prefix_(prefix) {
    prefix_ += "XXXXXX";
    if (::mkdtemp((char *)prefix_.data()) == NULL)
      ::perror("mkdtemp");
    else
      ok_ = true;
  }
  ~TmpDir() {
    if (::nftw(prefix_.c_str(), ftw_cb, 20, FTW_DEPTH) < 0)
      ::perror("ftw");
    else
      ::remove(prefix_.c_str());
  }
  bool ok() const { return ok_; }
  const std::string & str() const { return prefix_; }
 private:
  bool ok_;
  std::string prefix_;
};

// Compute the kbuild flags for the currently running kernel
// Do this by:
//   1. Create temp Makefile with stub dummy.c
//   2. Run module build on that makefile, saving the computed flags to a file
//   3. Cache the file for fast flag lookup in subsequent runs
//  Note: Depending on environment, different cache locations may be desired. In
//  case we eventually support non-root user programs, cache in $HOME.
class KBuildHelper {
 public:
  explicit KBuildHelper(const std::string &kdir, bool has_source_dir);
  int get_flags(const char *uname_machine, std::vector<std::string> *cflags);
 private:
  std::string kdir_;
  bool has_source_dir_;
};

}  // namespace ebpf
