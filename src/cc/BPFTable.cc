/*
 * Copyright (c) 2016 Facebook, Inc.
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

#include <sys/epoll.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <memory>

#include "BPFTable.h"

#include "bcc_exception.h"
#include "bcc_syms.h"
#include "common.h"
#include "libbpf.h"
#include "perf_reader.h"

namespace ebpf {

BPFStackTable::~BPFStackTable() {
  for (auto it : pid_sym_)
    bcc_free_symcache(it.second, it.first);
}

std::vector<intptr_t> BPFStackTable::get_stack_addr(int stack_id) {
  std::vector<intptr_t> res;
  stacktrace_t stack;
  if (!lookup(&stack_id, &stack))
    return res;
  for (int i = 0; (i < BPF_MAX_STACK_DEPTH) && (stack.ip[i] != 0); i++)
    res.push_back(stack.ip[i]);
  return res;
}

std::vector<std::string> BPFStackTable::get_stack_symbol(int stack_id,
                                                         int pid) {
  auto addresses = get_stack_addr(stack_id);
  std::vector<std::string> res;
  res.reserve(addresses.size());

  if (pid < 0)
    pid = -1;
  if (pid_sym_.find(pid) == pid_sym_.end())
    pid_sym_[pid] = bcc_symcache_new(pid);
  void* cache = pid_sym_[pid];

  bcc_symbol symbol;
  for (auto addr : addresses)
    if (bcc_symcache_resolve(cache, addr, &symbol) != 0)
      res.push_back("[UNKNOWN]");
    else
      res.push_back(symbol.demangle_name);

  return res;
}

StatusTuple BPFPerfBuffer::open_on_cpu(perf_reader_raw_cb cb,
                                       perf_reader_lost_cb lost_cb,
                                       int cpu, void* cb_cookie, int page_cnt) {
  if (cpu_readers_.find(cpu) != cpu_readers_.end())
    return StatusTuple(-1, "Perf buffer already open on CPU %d", cpu);

  auto reader = static_cast<perf_reader*>(
      bpf_open_perf_buffer(cb, lost_cb, cb_cookie, -1, cpu, page_cnt));
  if (reader == nullptr)
    return StatusTuple(-1, "Unable to construct perf reader");

  int reader_fd = perf_reader_fd(reader);
  if (!update(&cpu, &reader_fd)) {
    perf_reader_free(static_cast<void*>(reader));
    return StatusTuple(-1, "Unable to open perf buffer on CPU %d: %s", cpu,
                       std::strerror(errno));
  }

  struct epoll_event event = {};
  event.events = EPOLLIN;
  event.data.ptr = static_cast<void*>(reader);
  if (epoll_ctl(epfd_, EPOLL_CTL_ADD, reader_fd, &event) != 0) {
    perf_reader_free(static_cast<void*>(reader));
    return StatusTuple(-1, "Unable to add perf_reader FD to epoll: %s",
                       std::strerror(errno));
  }

  cpu_readers_[cpu] = reader;
  return StatusTuple(0);
}

StatusTuple BPFPerfBuffer::open_all_cpu(perf_reader_raw_cb cb,
                                        perf_reader_lost_cb lost_cb,
                                        void* cb_cookie, int page_cnt) {
  if (cpu_readers_.size() != 0 || epfd_ != -1)
    return StatusTuple(-1, "Previously opened perf buffer not cleaned");

  std::vector<int> cpus = get_online_cpus();
  ep_events_.reset(new epoll_event[cpus.size()]);
  epfd_ = epoll_create1(EPOLL_CLOEXEC);

  for (int i : cpus) {
    auto res = open_on_cpu(cb, lost_cb, i, cb_cookie, page_cnt);
    if (res.code() != 0) {
      TRY2(close_all_cpu());
      return res;
    }
  }
  return StatusTuple(0);
}

StatusTuple BPFPerfBuffer::close_on_cpu(int cpu) {
  auto it = cpu_readers_.find(cpu);
  if (it == cpu_readers_.end())
    return StatusTuple(0);
  perf_reader_free(static_cast<void*>(it->second));
  if (!remove(const_cast<int*>(&(it->first))))
    return StatusTuple(-1, "Unable to close perf buffer on CPU %d", it->first);
  cpu_readers_.erase(it);
  return StatusTuple(0);
}

StatusTuple BPFPerfBuffer::close_all_cpu() {
  std::string errors;
  bool has_error = false;

  int close_res = close(epfd_);
  epfd_ = -1;
  ep_events_.reset();
  if (close_res != 0) {
    has_error = true;
    errors += std::string(std::strerror(errno)) + "\n";
  }

  std::vector<int> opened_cpus;
  for (auto it : cpu_readers_)
    opened_cpus.push_back(it.first);
  for (int i : opened_cpus) {
    auto res = close_on_cpu(i);
    if (res.code() != 0) {
      errors += "Failed to close CPU" + std::to_string(i) + " perf buffer: ";
      errors += res.msg() + "\n";
      has_error = true;
    }
  }

  if (has_error)
    return StatusTuple(-1, errors);
  return StatusTuple(0);
}

void BPFPerfBuffer::poll(int timeout) {
  if (epfd_ < 0)
    return;
  int cnt = epoll_wait(epfd_, ep_events_.get(), cpu_readers_.size(), timeout);
  if (cnt <= 0)
    return;
  for (int i = 0; i < cnt; i++)
    perf_reader_event_read(static_cast<perf_reader*>(ep_events_[i].data.ptr));
}

BPFPerfBuffer::~BPFPerfBuffer() {
  auto res = close_all_cpu();
  if (res.code() != 0)
    std::cerr << "Failed to close all perf buffer on destruction: " << res.msg()
              << std::endl;
}

}  // namespace ebpf
