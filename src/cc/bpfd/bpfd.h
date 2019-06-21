/*
 * BPFd (Berkeley Packet Filter daemon)
 * This header is only supposed to be used by bpfd.c
 *
 * Copyright (C) 2017 Joel Fernandes <agnel.joel@gmail.com>
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

#include "base64.h"
#include "cmd_parsers.h"
#include "libbpf.h"
#include "utils.h"

#define PARSE_INT(var)                            \
  {                                               \
    int p = parse_int_arg(in, arg_index++, &var); \
    if (p)                                        \
      goto invalid_command;                       \
  }

#define PARSE_UINT(var)                            \
  {                                                \
    int p = parse_uint_arg(in, arg_index++, &var); \
    if (p)                                         \
      goto invalid_command;                        \
  }

#define PARSE_UINT32(var)                            \
  {                                                  \
    int p = parse_uint32_arg(in, arg_index++, &var); \
    if (p)                                           \
      goto invalid_command;                          \
  }

#define PARSE_UINT64(var)                            \
  {                                                  \
    int p = parse_uint64_arg(in, arg_index++, &var); \
    if (p)                                           \
      goto invalid_command;                          \
  }

#define PARSE_ULL(var)                            \
  {                                               \
    int p = parse_ull_arg(in, arg_index++, &var); \
    if (p)                                        \
      goto invalid_command;                       \
  }

#define PARSE_STR(var)                            \
  {                                               \
    int p = parse_str_arg(in, arg_index++, &var); \
    if (p)                                        \
      goto invalid_command;                       \
  }

int bpf_remote_open_perf_buffer(int pid, int cpu, int page_cnt);
int remote_perf_reader_poll(int *fds, int num_readers, int timeout);
