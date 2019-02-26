/*
 * PyPerf Profile Python Processes with Python stack-trace.
 *        For Linux, uses BCC, eBPF. Embedded C.
 *
 * Example of using BPF to profile Python Processes with Python stack-trace.
 *
 * USAGE: PyPerf [-d|--duration DURATION_MS] [-c|--sample-rate SAMPLE_RATE]
 *               [-v|--verbosity LOG_VERBOSITY]
 *
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <cinttypes>
#include <cstdlib>
#include <string>
#include <vector>

#include "PyPerfLoggingHelper.h"
#include "PyPerfUtil.h"

int main(int argc, char** argv) {
  int pos = 1;

  auto parseIntArg = [&](std::vector<std::string> argNames, uint64_t& target) {
    std::string arg(argv[pos]);
    for (const auto& name : argNames) {
      if (arg == name) {
        if (pos == argc) {
          std::fprintf(stderr, "Expect value after %s\n", arg.c_str());
          std::exit(1);
        }
        pos++;
        std::string value(argv[pos]);
        try {
          target = std::stoi(value);
        } catch (const std::exception& e) {
          std::fprintf(stderr, "Expect integer value after %s, got %s: %s\n",
                       arg.c_str(), value.c_str(), e.what());
          std::exit(1);
        }
        return true;
      }
    }
    return false;
  };

  uint64_t sampleRate = 1000000;
  uint64_t durationMs = 1000;
  uint64_t verbosityLevel = 0;
  while (true) {
    if (pos >= argc) {
      break;
    }
    bool found = false;
    found = found || parseIntArg({"-c", "--sample-rate"}, sampleRate);
    found = found || parseIntArg({"-d", "--duration"}, durationMs);
    found = found || parseIntArg({"-v", "--verbose"}, verbosityLevel);
    if (!found) {
      std::fprintf(stderr, "Unexpected argument: %s\n", argv[pos]);
      std::exit(1);
    }
    pos++;
  }

  ebpf::pyperf::setVerbosity(verbosityLevel);
  ebpf::pyperf::logInfo(1, "Profiling Sample Rate: %" PRIu64 "\n", sampleRate);
  ebpf::pyperf::logInfo(1, "Profiling Duration: %" PRIu64 "ms\n", durationMs);

  ebpf::pyperf::PyPerfUtil util;
  util.init();
  util.profile(sampleRate, durationMs);

  return 0;
}
