/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#pragma once

#include "PyPerfSampleProcessor.h"

namespace ebpf {
namespace pyperf {

class PyPerfDefaultPrinter : public PyPerfSampleProcessor {
 public:
  void processSamples(const std::vector<PyPerfSample>& samples,
                      PyPerfUtil* util) override;
};

}  // namespace pyperf
}  // namespace ebpf
