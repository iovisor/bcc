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

const static std::map<int, const char*> kGILStateValues = {
    {GIL_STATE_NO_INFO, "No GIL Info"},
    {GIL_STATE_ERROR, "Error Reading GIL State"},
    {GIL_STATE_UNINITIALIZED, "GIL Uninitialized"},
    {GIL_STATE_NOT_LOCKED, "GIL Not Locked"},
    {GIL_STATE_THIS_THREAD, "GIL on This Thread"},
    {GIL_STATE_GLOBAL_CURRENT_THREAD,
     "GIL on Global _PyThreadState_Current Thread"},
    {GIL_STATE_OTHER_THREAD, "GIL on Unexpected Thread"},
    {GIL_STATE_NULL, "GIL State Empty"}};

const static std::map<int, const char*> kThreadStateValues = {
    {THREAD_STATE_UNKNOWN, "ThreadState Unknown"},
    {THREAD_STATE_MATCH, "TLS ThreadState is Global _PyThreadState_Current"},
    {THREAD_STATE_MISMATCH,
     "TLS ThreadState is not Global _PyThreadState_Current"},
    {THREAD_STATE_THIS_THREAD_NULL, "TLS ThreadState is NULL"},
    {THREAD_STATE_GLOBAL_CURRENT_THREAD_NULL,
     "Global _PyThreadState_Current is NULL"},
    {THREAD_STATE_BOTH_NULL,
     "Both TLS ThreadState and Global _PyThreadState_Current is NULL"},
};

const static std::map<int, const char*> kPthreadIDStateValues = {
    {PTHREAD_ID_UNKNOWN, "Pthread ID Unknown"},
    {PTHREAD_ID_MATCH, "System Pthread ID is Python ThreadState Pthread ID"},
    {PTHREAD_ID_MISMATCH,
     "System Pthread ID is not Python ThreadState Pthread ID"},
    {PTHREAD_ID_THREAD_STATE_NULL, "No Pthread ID: TLS ThreadState is NULL"},
    {PTHREAD_ID_NULL, "Pthread ID on TLS ThreadState is NULL"},
    {PTHREAD_ID_ERROR, "Error Reading System Pthread ID"}};

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
    if (showGILState_)
      std::printf("GIL State: %s\n", kGILStateValues.at(sample.gilState));
    if (showThreadState_)
      std::printf("Thread State: %s\n",
                  kThreadStateValues.at(sample.threadStateMatch));
    if (showPthreadIDState_)
      std::printf("Pthread ID State: %s\n",
                  kPthreadIDStateValues.at(sample.pthreadIDMatch));

    std::printf("\n");
  }

  std::printf("%d samples collected\n", util->getTotalSamples());
  std::printf("%d samples lost\n", util->getLostSamples());
  std::printf("%d samples with truncated stack\n", truncatedStack);
  std::printf("%d times Python symbol lost\n", lostSymbols);
}

}  // namespace pyperf
}  // namespace ebpf
