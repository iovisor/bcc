/*
 * Copyright (c) 2015 PLUMgrid, Inc.
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

#pragma once

#include <exception>
#include <string>
#include <tuple>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#undef NDEBUG

namespace ebpf {

template <typename... Args>
std::tuple<int, std::string> mkstatus(int ret, const char *fmt, Args... args) {
  char buf[1024];
  snprintf(buf, sizeof(buf), fmt, args...);
  return std::make_tuple(ret, std::string(buf));
}

static inline std::tuple<int, std::string> mkstatus(int ret, const char *msg) {
  return std::make_tuple(ret, std::string(msg));
}

static inline std::tuple<int, std::string> mkstatus(int ret) {
  return std::make_tuple(ret, std::string());
}

#define TRY(CMD) \
  do { \
    int __status = (CMD); \
    if (__status != 0) { \
      return __status; \
    } \
  } while (0)

#define TRY2(CMD) \
  do { \
    std::tuple<int, std::string> __stp = (CMD); \
    if (std::get<0>(__stp) != 0) { \
      return __stp; \
    } \
  } while (0)

}  // namespace ebpf
