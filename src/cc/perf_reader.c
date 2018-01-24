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

#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/perf_event.h>

#include "libbpf.h"
#include "perf_reader.h"

enum {
  RB_NOT_USED = 0, // ring buffer not usd
  RB_USED_IN_MUNMAP = 1, // used in munmap
  RB_USED_IN_READ = 2, // used in read
};

struct perf_reader {
  perf_reader_cb cb;
  perf_reader_raw_cb raw_cb;
  perf_reader_lost_cb lost_cb;
  void *cb_cookie; // to be returned in the cb
  void *buf; // for keeping segmented data
  size_t buf_size;
  void *base;
  int rb_use_state;
  int page_size;
  int page_cnt;
  int fd;
  uint32_t type;
  uint64_t sample_type;
};

struct perf_reader * perf_reader_new(perf_reader_cb cb,
                                     perf_reader_raw_cb raw_cb,
                                     perf_reader_lost_cb lost_cb,
                                     void *cb_cookie, int page_cnt) {
  struct perf_reader *reader = calloc(1, sizeof(struct perf_reader));
  if (!reader)
    return NULL;
  reader->cb = cb;
  reader->raw_cb = raw_cb;
  reader->lost_cb = lost_cb;
  reader->cb_cookie = cb_cookie;
  reader->fd = -1;
  reader->page_size = getpagesize();
  reader->page_cnt = page_cnt;
  return reader;
}

void perf_reader_free(void *ptr) {
  if (ptr) {
    struct perf_reader *reader = ptr;
    while (!__sync_bool_compare_and_swap(&reader->rb_use_state, RB_NOT_USED, RB_USED_IN_MUNMAP));
    munmap(reader->base, reader->page_size * (reader->page_cnt + 1));
    if (reader->fd >= 0) {
      ioctl(reader->fd, PERF_EVENT_IOC_DISABLE, 0);
      close(reader->fd);
    }
    free(reader->buf);
    free(ptr);
  }
}

int perf_reader_mmap(struct perf_reader *reader, unsigned type, unsigned long sample_type) {
  int mmap_size = reader->page_size * (reader->page_cnt + 1);

  if (reader->fd < 0) {
    fprintf(stderr, "%s: reader fd is not set\n", __FUNCTION__);
    return -1;
  }

  reader->base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE , MAP_SHARED, reader->fd, 0);
  if (reader->base == MAP_FAILED) {
    perror("mmap");
    return -1;
  }
  reader->type = type;
  reader->sample_type = sample_type;

  return 0;
}

struct perf_sample_trace_common {
  uint16_t id;
  uint8_t flags;
  uint8_t preempt_count;
  int pid;
};

struct perf_sample_trace_kprobe {
  struct perf_sample_trace_common common;
  uint64_t ip;
};

static void parse_tracepoint(struct perf_reader *reader, void *data, int size) {
  uint8_t *ptr = data;
  struct perf_event_header *header = (void *)data;

  struct perf_sample_trace_kprobe *tk = NULL;
  uint64_t *callchain = NULL;
  uint64_t num_callchain = 0;

  ptr += sizeof(*header);
  if (ptr > (uint8_t *)data + size) {
    fprintf(stderr, "%s: corrupt sample header\n", __FUNCTION__);
    return;
  }

  if (reader->sample_type & PERF_SAMPLE_CALLCHAIN) {
    struct {
      uint64_t nr;
      uint64_t ips[0];
    } *cc = (void *)ptr;
    ptr += sizeof(cc->nr) + sizeof(*cc->ips) * cc->nr;
    // size sanity check
    if (ptr > (uint8_t *)data + size) {
      fprintf(stderr, "%s: corrupt callchain sample\n", __FUNCTION__);
      return;
    }
    int i;
    // don't include magic numbers in the call chain
    for (i = 0; i < cc->nr; ++i) {
      if (cc->ips[i] == PERF_CONTEXT_USER)
        break;
      if (cc->ips[i] >= PERF_CONTEXT_MAX)
        continue;
      if (!callchain)
        callchain = &cc->ips[i];
      ++num_callchain;
    }
  }
  // for kprobes, raw samples just include the common data structure and the
  // instruction pointer
  if (reader->sample_type & PERF_SAMPLE_RAW) {
    struct {
      uint32_t size;
      char data[0];
    } *raw = (void *)ptr;
    ptr += sizeof(raw->size) + raw->size;
    if (ptr > (uint8_t *)data + size) {
      fprintf(stderr, "%s: corrupt raw sample\n", __FUNCTION__);
      return;
    }
    tk = (void *)raw->data;
  }

  // sanity check
  if (ptr != (uint8_t *)data + size) {
    fprintf(stderr, "%s: extra data at end of sample\n", __FUNCTION__);
    return;
  }

  // call out to the user with the parsed data
  if (reader->cb)
    reader->cb(reader->cb_cookie, tk ? tk->common.pid : -1, num_callchain, callchain);
}

static void parse_sw(struct perf_reader *reader, void *data, int size) {
  uint8_t *ptr = data;
  struct perf_event_header *header = (void *)data;

  struct {
      uint32_t size;
      char data[0];
  } *raw = NULL;

  ptr += sizeof(*header);
  if (ptr > (uint8_t *)data + size) {
    fprintf(stderr, "%s: corrupt sample header\n", __FUNCTION__);
    return;
  }

  if (reader->sample_type & PERF_SAMPLE_RAW) {
    raw = (void *)ptr;
    ptr += sizeof(raw->size) + raw->size;
    if (ptr > (uint8_t *)data + size) {
      fprintf(stderr, "%s: corrupt raw sample\n", __FUNCTION__);
      return;
    }
  }

  // sanity check
  if (ptr != (uint8_t *)data + size) {
    fprintf(stderr, "%s: extra data at end of sample\n", __FUNCTION__);
    return;
  }

  if (reader->raw_cb)
    reader->raw_cb(reader->cb_cookie, raw->data, raw->size);
}

static uint64_t read_data_head(struct perf_event_mmap_page *perf_header) {
  uint64_t data_head = *((volatile uint64_t *)&perf_header->data_head);
  asm volatile("" ::: "memory");
  return data_head;
}

static void write_data_tail(struct perf_event_mmap_page *perf_header, uint64_t data_tail) {
  asm volatile("" ::: "memory");
  perf_header->data_tail = data_tail;
}

void perf_reader_event_read(struct perf_reader *reader) {
  struct perf_event_mmap_page *perf_header = reader->base;
  uint64_t buffer_size = (uint64_t)reader->page_size * reader->page_cnt;
  uint64_t data_head;
  uint8_t *base = (uint8_t *)reader->base + reader->page_size;
  uint8_t *sentinel = (uint8_t *)reader->base + buffer_size + reader->page_size;
  uint8_t *begin, *end;

  if (!__sync_bool_compare_and_swap(&reader->rb_use_state, RB_NOT_USED, RB_USED_IN_READ))
    return;

  // Consume all the events on this ring, calling the cb function for each one.
  // The message may fall on the ring boundary, in which case copy the message
  // into a malloced buffer.
  for (data_head = read_data_head(perf_header); perf_header->data_tail != data_head;
      data_head = read_data_head(perf_header)) {
    uint64_t data_tail = perf_header->data_tail;
    uint8_t *ptr;

    begin = base + data_tail % buffer_size;
    // event header is u64, won't wrap
    struct perf_event_header *e = (void *)begin;
    ptr = begin;
    end = base + (data_tail + e->size) % buffer_size;
    if (end < begin) {
      // perf event wraps around the ring, make a contiguous copy
      reader->buf = realloc(reader->buf, e->size);
      size_t len = sentinel - begin;
      memcpy(reader->buf, begin, len);
      memcpy(reader->buf + len, base, e->size - len);
      ptr = reader->buf;
    }

    if (e->type == PERF_RECORD_LOST) {
      /*
       * struct {
       *    struct perf_event_header    header;
       *    u64                id;
       *    u64                lost;
       *    struct sample_id        sample_id;
       * };
       */
      uint64_t lost = *(uint64_t *)(ptr + sizeof(*e) + sizeof(uint64_t));
      if (reader->lost_cb) {
        reader->lost_cb(reader->cb_cookie, lost);
      } else {
        fprintf(stderr, "Possibly lost %" PRIu64 " samples\n", lost);
      }
    } else if (e->type == PERF_RECORD_SAMPLE) {
      if (reader->type == PERF_TYPE_TRACEPOINT)
        parse_tracepoint(reader, ptr, e->size);
      else if (reader->type == PERF_TYPE_SOFTWARE)
        parse_sw(reader, ptr, e->size);
    } else {
      fprintf(stderr, "%s: unknown sample type %d\n", __FUNCTION__, e->type);
    }

    write_data_tail(perf_header, perf_header->data_tail + e->size);
  }
  reader->rb_use_state = RB_NOT_USED;
}

int perf_reader_poll(int num_readers, struct perf_reader **readers, int timeout) {
  struct pollfd pfds[num_readers];
  int i;

  for (i = 0; i <num_readers; ++i) {
    pfds[i].fd = readers[i]->fd;
    pfds[i].events = POLLIN;
  }

  if (poll(pfds, num_readers, timeout) > 0) {
    for (i = 0; i < num_readers; ++i) {
      if (pfds[i].revents & POLLIN)
        perf_reader_event_read(readers[i]);
    }
  }
  return 0;
}

void perf_reader_set_fd(struct perf_reader *reader, int fd) {
  reader->fd = fd;
}

int perf_reader_fd(struct perf_reader *reader) {
  return reader->fd;
}
