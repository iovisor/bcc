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

#include <errno.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

#include "BPFTable.h"

#include "bcc_exception.h"
#include "bcc_syms.h"
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

StatusTuple BPFPerfBuffer::open_on_cpu(perf_reader_raw_cb cb, int cpu,
                                       void* cb_cookie) {
  if (cpu_readers_.find(cpu) != cpu_readers_.end())
    return StatusTuple(-1, "Perf buffer already open on CPU %d", cpu);
  auto reader =
      static_cast<perf_reader*>(bpf_open_perf_buffer(cb, cb_cookie, -1, cpu));
  if (reader == nullptr)
    return StatusTuple(-1, "Unable to construct perf reader");
  int reader_fd = perf_reader_fd(reader);
  if (!update(&cpu, &reader_fd)) {
    perf_reader_free(static_cast<void*>(reader));
    return StatusTuple(-1, "Unable to open perf buffer on CPU %d: %s", cpu,
                       strerror(errno));
  }
  cpu_readers_[cpu] = static_cast<perf_reader*>(reader);
  return StatusTuple(0);
}

StatusTuple BPFPerfBuffer::open(perf_reader_raw_cb cb, void* cb_cookie) {
  for (int i = 0; i < sysconf(_SC_NPROCESSORS_ONLN); i++)
    TRY2(open_on_cpu(cb, i, cb_cookie));
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

StatusTuple BPFPerfBuffer::close() {
  std::string errors;
  bool has_error = false;
  for (int i = 0; i < sysconf(_SC_NPROCESSORS_ONLN); i++) {
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
  perf_reader* readers[cpu_readers_.size()];
  int i = 0;
  for (auto it : cpu_readers_)
    readers[i++] = it.second;
  perf_reader_poll(cpu_readers_.size(), readers, timeout);
}

BPFPerfBuffer::~BPFPerfBuffer() {
  auto res = close();
  if (res.code() != 0)
    std::cerr << "Failed to close all perf buffer on destruction: "
              << res.msg() << std::endl;
}

}  // namespace ebpf
