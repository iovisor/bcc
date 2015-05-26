#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include <unistd.h>

#define KERNEL_MODULES_DIR "/lib/modules"

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
  explicit DirStack(const char *dst) : ok_(false) {
    if (getcwd(cwd_, sizeof(cwd_)) == NULL) {
      ::perror("getcwd");
      return;
    }
    if (::chdir(dst)) {
      fprintf(stderr, "chdir(%s): %s\n", dst, strerror(errno));
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
    auto fn = [] (const char *path, const struct stat *, int) -> int {
      return ::remove(path);
    };
    if (::ftw(prefix_.c_str(), fn, 20) < 0)
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
 private:
  int learn_flags(const std::string &tmpdir, const char *uname_release, const char *cachefile);
 public:
  KBuildHelper();
  int get_flags(const char *uname_release, std::vector<std::string> *cflags);
 private:
  std::string cache_dir_;
};

}  // namespace ebpf
