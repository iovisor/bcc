/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <map>
#include <string>

#include "PyPerfDefaultPrinter.h"
#include "PyPerfUtil.h"

namespace ebpf {
namespace pyperf {

const static std::string kLostSymbol = "[Lost Symbol]";
const static std::string kIncompleteStack = "[Truncated Stack]";
const static std::string kErrorStack = "[Stack Error]";
const static std::string kNonPythonStack = "[Non-Python Code]";

void PyPerfDefaultPrinter::processSamples(
    const std::vector<PyPerfSample>& samples, PyPerfUtil* util) {
  auto symbols = util->getSymbolMapping();
  uint32_t lostSymbols = 0;
  uint32_t truncatedStack = 0;

  for (auto& sample : samples) {
    if (sample.threadStateMatch != THREAD_STATE_THIS_THREAD_NULL &&
        sample.threadStateMatch != THREAD_STATE_BOTH_NULL) {
      for (const auto stackId : sample.pyStackIds) {
        auto symbIt = symbols.find(stackId);
        if (symbIt != symbols.end()) {
          std::printf("    %s\n", symbIt->second.c_str());
        } else {
          std::printf("    %s\n", kLostSymbol.c_str());
          lostSymbols++;
        }
      }
      switch (sample.stackStatus) {
      case STACK_STATUS_TRUNCATED:
        std::printf("    %s\n", kIncompleteStack.c_str());
        truncatedStack++;
        break;
      case STACK_STATUS_ERROR:
        std::printf("    %s\n", kErrorStack.c_str());
        break;
      default:
        break;
      }
    } else {
      std::printf("    %s\n", kNonPythonStack.c_str());
    }

    std::printf("PID: %d TID: %d (%s)\n", sample.pid, sample.tid,
                sample.comm.c_str());
    std::printf("GIL State: %d Thread State: %d PthreadID Match State: %d\n\n",
                sample.threadStateMatch, sample.gilState,
                sample.pthreadIDMatch);
  }

  std::printf("%d samples collected\n", util->getTotalSamples());
  std::printf("%d samples lost\n", util->getLostSamples());
  std::printf("%d samples with truncated stack\n", truncatedStack);
  std::printf("%d times Python symbol lost\n", lostSymbols);
}

}  // namespace pyperf
}  // namespace ebpf
