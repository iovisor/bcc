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

#ifndef PERF_READER_H
#define PERF_READER_H

#include "libbpf.h"

#ifdef __cplusplus
extern "C" {
#endif

struct perf_reader;

struct perf_reader * perf_reader_new(perf_reader_raw_cb raw_cb,
                                     perf_reader_lost_cb lost_cb,
                                     void *cb_cookie, int page_cnt);
void perf_reader_free(void *ptr);
int perf_reader_mmap(struct perf_reader *reader);
void perf_reader_event_read(struct perf_reader *reader);
int perf_reader_poll(int num_readers, struct perf_reader **readers, int timeout);
int perf_reader_fd(struct perf_reader *reader);
void perf_reader_set_fd(struct perf_reader *reader, int fd);

#ifdef __cplusplus
}
#endif

#endif
