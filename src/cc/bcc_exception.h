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

#include <cstdio>
#include <string>

namespace ebpf {

class StatusTuple {
public:
  StatusTuple(int ret) : ret_(ret) {}

  StatusTuple(int ret, const char *msg) : ret_(ret), msg_(msg) {}

  StatusTuple(int ret, const std::string &msg) : ret_(ret), msg_(msg) {}

  template <typename... Args>
  StatusTuple(int ret, const char *fmt, Args... args) : ret_(ret) {
    char buf[2048];
    snprintf(buf, sizeof(buf), fmt, args...);
    msg_ = std::string(buf);
  }

  void append_msg(const std::string& msg) {
    msg_ += msg;
  }

  int code() { return ret_; }

  std::string msg() { return msg_; }

private:
  int ret_;
  std::string msg_;
};

#define TRY2(CMD)              \
  do {                         \
    StatusTuple __stp = (CMD); \
    if (__stp.code() != 0) {   \
      return __stp;            \
    }                          \
  } while (0)

}  // namespace ebpf
