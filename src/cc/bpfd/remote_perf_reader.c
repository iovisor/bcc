/*
 * BPFd (Berkeley Packet Filter daemon)
 * Support for perf readers.
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

/*
 * This file's functionality should be properly abstracted
 * within libbpf.c and perf_reader.c. For now, duplicate the
 * struct here
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "bpfd.h"
#include "perf_reader.h"

#define MAX_READERS 1024

struct perf_reader *remote_readers[MAX_READERS];

void remote_raw_reader_cb(void *cookie, void *raw, int size) {
  struct perf_reader *reader = cookie;
  char *raw_str;

  raw_str = malloc(size * 4);

  if (!base64_encode(raw, size, raw_str, size * 4))
    printf("raw_cb: b64 encode failed for reader fd=%d\n", reader->fd);

  printf("%d %d %s\n", reader->fd, size, raw_str);

  free(raw_str);
}

int bpf_remote_open_perf_buffer(int pid, int cpu, int page_cnt) {
  struct perf_reader *reader;

  reader = bpf_open_perf_buffer(remote_raw_reader_cb, NULL, NULL, pid, cpu,
                                page_cnt);
  if (!reader)
    return -1;

  reader->cb_cookie = reader;
  remote_readers[reader->fd] = reader;
  return reader->fd;
}

int remote_perf_reader_poll(int *fds, int num_readers, int timeout) {
  struct pollfd pfds[num_readers + 1];
  int i, fd;

  for (i = 0; i < num_readers; i++) {
    fd = fds[i];
    if (!remote_readers[fd])
      continue;
    pfds[i].fd = fd;
    pfds[i].events = POLLIN;
  }

  // Include stdin in the collection of file descriptors to poll.
  // This is so that user input to bpfd via stdin can still be acted
  // on immediately. Not doing this will lead to bpfd being unable to
  // respond to user input until after poll() returns.
  pfds[num_readers].fd = 0;
  pfds[num_readers].events = POLLIN;

  if (poll(pfds, num_readers + 1, timeout) > 0) {
    for (i = 0; i < num_readers + 1; i++) {
      fd = pfds[i].fd;
      if (fd != 0 && pfds[i].revents & POLLIN)
        perf_reader_event_read(remote_readers[fd]);
    }
  }

  return 0;
}
