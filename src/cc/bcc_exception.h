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
  enum class Code {
    // Not an error, indicates success.
    OK = 0,
    // For any error that is not covered in the existing codes.
    UNKNOWN,

    INVALID_ARGUMENT,
    PERMISSION_DENIED,
    // For any error that was raised when making syscalls.
    SYSTEM,
  };

  static StatusTuple OK() {
    return StatusTuple(Code::OK, "");
  }

  StatusTuple(int ret) : ret_(ret) {}

  StatusTuple(int ret, const char *msg) : ret_(ret), msg_(msg) {}

  StatusTuple(int ret, const std::string &msg) : ret_(ret), msg_(msg) {}

  template <typename... Args>
  StatusTuple(int ret, const char *fmt, Args... args) : ret_(ret) {
    char buf[2048];
    snprintf(buf, sizeof(buf), fmt, args...);
    msg_ = std::string(buf);
  }

  StatusTuple(Code code, const std::string &msg) : use_enum_code_(true), code_(code), msg_(msg) {}

  void append_msg(const std::string& msg) {
    msg_ += msg;
  }

  bool ok() const {
    if (use_enum_code_) {
      return code_ == Code::OK;
    }
    return ret_ == 0;
  }

  int code() const {
    if (use_enum_code_) {
      return static_cast<int>(code_);
    }
    return ret_;
  }

  const std::string& msg() const { return msg_; }

private:
  int ret_;

  bool use_enum_code_ = false;
  Code code_;

  std::string msg_;
};

#define TRY2(CMD)                    \
  do {                               \
    ebpf::StatusTuple __stp = (CMD); \
    if (__stp.code() != 0) {         \
      return __stp;                  \
    }                                \
  } while (0)

namespace error {

#define DECLARE_ERROR(FN, CODE)                                                 \
  inline StatusTuple FN(const std::string& msg) {                                      \
    return StatusTuple(::ebpf::StatusTuple::Code::CODE, msg);                   \
  }                                                                             \
  inline bool Is##FN(const StatusTuple& status) {                               \
    return status.code() == static_cast<int>(::ebpf::StatusTuple::Code::CODE);  \
  }

DECLARE_ERROR(Unknown, UNKNOWN)
DECLARE_ERROR(InvalidArgument, INVALID_ARGUMENT)
DECLARE_ERROR(PermissionDenied, PERMISSION_DENIED)
DECLARE_ERROR(System, SYSTEM)

}  // namespace error

}  // namespace ebpf
