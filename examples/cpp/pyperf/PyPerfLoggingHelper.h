/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#pragma once

#include <cstdint>

namespace ebpf {
namespace pyperf {

void setVerbosity(uint64_t verbosityLevel);
void logInfo(uint64_t logLevel, const char* fmt, ...);

}  // namespace pyperf
}  // namespace ebpf
