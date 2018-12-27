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

#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <string>

#include "ns_guard.h"

// TODO: Remove this when CentOS 6 support is not needed anymore
#include "setns.h"

ProcMountNS::ProcMountNS(int pid) : target_ino_(0) {
  if (pid < 0)
    return;

  std::string target_path = "/proc/" + std::to_string(pid) + "/ns/mnt";
  ebpf::FileDesc target_fd(open(target_path.c_str(), O_RDONLY));
  ebpf::FileDesc self_fd(open("/proc/self/ns/mnt", O_RDONLY));

  if (self_fd < 0 || target_fd < 0)
    return;

  struct stat self_stat, target_stat;
  if (fstat(self_fd, &self_stat) != 0)
    return;
  if (fstat(target_fd, &target_stat) != 0)
    return;

  target_ino_ = target_stat.st_ino;
  if (self_stat.st_ino == target_stat.st_ino)
    // Both current and target Process are in same mount namespace
    return;

  self_fd_ = std::move(self_fd);
  target_fd_ = std::move(target_fd);
}

ProcMountNSGuard::ProcMountNSGuard(ProcMountNS *mount_ns)
    : mount_ns_instance_(nullptr), mount_ns_(mount_ns), entered_(false) {
  init();
}

ProcMountNSGuard::ProcMountNSGuard(int pid)
    : mount_ns_instance_(pid > 0 ? new ProcMountNS(pid) : nullptr),
      mount_ns_(mount_ns_instance_.get()),
      entered_(false) {
  init();
}

void ProcMountNSGuard::init() {
  if (!mount_ns_ || mount_ns_->self() < 0 || mount_ns_->target() < 0)
    return;

  if (setns(mount_ns_->target(), CLONE_NEWNS) == 0)
    entered_ = true;
}

ProcMountNSGuard::~ProcMountNSGuard() {
  if (mount_ns_ && entered_ && mount_ns_->self() >= 0)
    setns(mount_ns_->self(), CLONE_NEWNS);
}
