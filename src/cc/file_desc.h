/*
 * Copyright (c) 2017 Facebook, Inc.
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

#pragma once

#include <unistd.h>

namespace ebpf {

/// FileDesc is a helper class for managing open file descriptors. Copy is
/// disallowed (call dup instead), and cleanup happens automatically.
class FileDesc {
 public:
  explicit FileDesc(int fd = -1) : fd_(fd) {}
  FileDesc(FileDesc &&that) : fd_(-1) { *this = std::move(that); }
  FileDesc(const FileDesc &that) = delete;

  ~FileDesc() {
    if (fd_ >= 0)
      ::close(fd_);
  }

  FileDesc &operator=(int fd) {
    if (fd_ >= 0)
      ::close(fd_);
    fd_ = fd;
    return *this;
  }
  FileDesc &operator=(FileDesc &&that) {
    if (fd_ >= 0)
      ::close(fd_);
    fd_ = that.fd_;
    that.fd_ = -1;
    return *this;
  }
  FileDesc &operator=(const FileDesc &that) = delete;

  FileDesc dup() const {
    int dup_fd = ::dup(fd_);
    return FileDesc(dup_fd);
  }

  operator int() { return fd_; }
  operator int() const { return fd_; }

 private:
  int fd_;
};

}  // namespace ebpf
