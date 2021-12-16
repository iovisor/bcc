/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#pragma once

#include <vector>

#include "PyPerfType.h"

namespace ebpf {
namespace pyperf {

class PyPerfUtil;

class PyPerfSampleProcessor {
 public:
  virtual void processSamples(const std::vector<PyPerfSample>& samples,
                              PyPerfUtil* util) = 0;
};

}  // namespace pyperf
}  // namespace ebpf
