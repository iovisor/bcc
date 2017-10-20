/*
 * Copyright (c) 2017 Facebook, Inc.
 * Copyright (c) 2017 VMware, Inc.
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

#include <memory>

#include "file_desc.h"

class ProcMountNSGuard;

// ProcMountNS opens an fd corresponding to the current mount namespace and the
// mount namespace of the target process.
// The fds will remain uninitialized (<0) if the open fails, or if the current
// and target namespaces are identical.
class ProcMountNS {
 public:
  explicit ProcMountNS(int pid);
  int self() const { return self_fd_; }
  int target() const { return target_fd_; }
  ino_t target_ino() const { return target_ino_; }

 private:
  ebpf::FileDesc self_fd_;
  ebpf::FileDesc target_fd_;
  ino_t target_ino_;
};

// ProcMountNSGuard switches to the target mount namespace and restores the
// original upon going out of scope.
class ProcMountNSGuard {
 public:
  explicit ProcMountNSGuard(ProcMountNS *mount_ns);
  explicit ProcMountNSGuard(int pid);

  ~ProcMountNSGuard();

 private:
  void init();

  std::unique_ptr<ProcMountNS> mount_ns_instance_;
  ProcMountNS *mount_ns_;
  bool entered_;
};
