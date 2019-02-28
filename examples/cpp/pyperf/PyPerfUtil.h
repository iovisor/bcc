/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#pragma once

#include <string>
#include <vector>

#include <linux/perf_event.h>
#include <sys/types.h>

#include "BPF.h"
#include "PyPerfType.h"

namespace ebpf {
namespace pyperf {

class PyPerfUtil {
 public:
  enum class PyPerfResult : int {
    SUCCESS = 0,
    INIT_FAIL,
    PERF_BUF_OPEN_FAIL,
    NO_INIT,
    EVENT_ATTACH_FAIL,
    EVENT_DETACH_FAIL
  };

  struct Sample {
    pid_t pid;
    pid_t tid;
    std::string comm;
    uint8_t threadStateMatch;
    uint8_t gilState;
    uint8_t pthreadIDMatch;
    uint8_t stackStatus;
    std::vector<int32_t> pyStackIds;

    explicit Sample(const Event* raw, int rawSize)
        : pid(raw->pid),
          tid(raw->tid),
          comm(raw->comm),
          threadStateMatch(raw->thread_state_match),
          gilState(raw->gil_state),
          pthreadIDMatch(raw->pthread_id_match),
          stackStatus(raw->stack_status),
          pyStackIds(raw->stack, raw->stack + raw->stack_len) {}
  };

  // init must be invoked exactly once before invoking profile
  PyPerfResult init();

  PyPerfResult profile(int64_t sampleRate, int64_t durationMs);

 private:
  uint32_t lostSymbols_ = 0, totalSamples_ = 0, lostSamples_ = 0, truncatedStack_ = 0;

  ebpf::BPF bpf_{0, nullptr, false, "", true};
  std::vector<Sample> samples_;
  bool initCompleted_{false};

  void handleSample(const void* data, int dataSize);
  void handleLostSamples(int lostCnt);
  friend void handleLostSamplesCallback(void*, uint64_t);
  friend void handleSampleCallback(void*, void*, int);

  std::string getSymbolName(Symbol& sym) const;

  bool tryTargetPid(int pid, PidData& data);
};
}  // namespace pyperf
}  // namespace ebpf
