/*
 * ====================================================================
 * Copyright (c) 2012, PLUMgrid, http://plumgrid.com
 *
 * This source is subject to the PLUMgrid License.
 * All rights reserved.
 *
 * THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF
 * ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * PLUMgrid confidential information, delete if you are not the
 * intended recipient.
 *
 * ====================================================================
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

class Exception : public std::exception {
 public:
  virtual ~Exception() throw() {}
};

class StringException : public Exception {
 public:
  StringException() : errstr_("unknown") {}
  virtual ~StringException() throw() {}
  explicit StringException(const std::string& s) : errstr_(s) {}
  explicit StringException(const char* s) : errstr_(s) {}
  template <typename... Args>
  StringException(const char* s, Args... args) {
    char x[1024];
    snprintf(x, sizeof(x), s, args...);
    errstr_.assign(x);
  }
  virtual const char* what() const throw() {
    return errstr_.c_str();
  }
 protected:
  std::string errstr_;
};

class ErrnoException : public StringException {
 public:
  ErrnoException() : StringException(strerror(errno)) {}
  explicit ErrnoException(const std::string& s) : StringException(s + ": " + strerror(errno)) {}
  explicit ErrnoException(const std::string& s, int err) : StringException(s + ": " + strerror(err)) {}
};

class SystemException : public StringException {
 public:
  explicit SystemException(int status) {
    if (status == -1) {
      errstr_.assign("command not found");
    } else {
      errstr_.assign("command exited with ");
      errstr_ += std::to_string(WEXITSTATUS(status));
    }
  }
  SystemException(int status, const std::string& s) {
    if (status == -1) {
      errstr_.assign("command not found");
    } else {
      errstr_.assign("command exited with ");
      errstr_ += std::to_string(WEXITSTATUS(status));
    }
    errstr_ += "; " + s + ": " + strerror(errno);
  }
};

class CompilerException : public StringException {
 public:
  explicit CompilerException(const std::string& s) : StringException(s) {}
  template <typename... Args>
  CompilerException(const char* s, Args... args) : StringException(s, args...) {}
};

class WatermarkException : public Exception {
 public:
  WatermarkException() {}
  virtual const char* what() const throw() {
    return "Reached High Watermark";
  }
};

class TerminateException : public Exception {
 public:
  TerminateException() {}
  virtual const char* what() const throw() {
    return "Terminated";
  }
};

class StatusException : public Exception {
 public:
  explicit StatusException(int st, const std::string &msg) : st_(st), msg_(msg) {}
  virtual const char* what() const throw() {
    return msg_.c_str();
  }
  int status() const { return st_; }
  const std::string & message() { return msg_; }
 protected:
  int st_;
  std::string msg_;
};

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

#define TRYT(CMD) \
  do { \
    int __status = (CMD); \
    if (__status != 0) { \
      throw StatusException(__status); \
    } \
  } while (0)

#define TRY2T(CMD) \
  do { \
    std::tuple<int, std::string> __stp = (CMD); \
    if (std::get<0>(__stp) != 0) { \
      throw StatusException(std::get<0>(__stp)); \
    } \
  } while (0)

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
