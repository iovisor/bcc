/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include <linux/perf_event.h>
#include <sys/types.h>

#include "BPF.h"
#include "PyPerfSampleProcessor.h"
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

  // init must be invoked exactly once before invoking profile
  PyPerfResult init();

  PyPerfResult profile(int64_t sampleRate, int64_t durationMs,
                       PyPerfSampleProcessor* processor);

  std::unordered_map<int32_t, std::string> getSymbolMapping();

  uint32_t getTotalSamples() const { return totalSamples_; }

  uint32_t getLostSamples() const { return lostSamples_; }

 private:
  uint32_t totalSamples_ = 0, lostSamples_ = 0;

  ebpf::BPF bpf_{0, nullptr, false, "", true};
  std::vector<PyPerfSample> samples_;
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
