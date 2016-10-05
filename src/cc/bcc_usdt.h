/*
 * Copyright (c) 2016 GitHub, Inc.
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
#ifndef LIBBCC_USDT_H
#define LIBBCC_USDT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void *bcc_usdt_new_frompid(int pid);
void *bcc_usdt_new_frompath(const char *path);
void bcc_usdt_close(void *usdt);

struct bcc_usdt {
    const char *provider;
    const char *name;
    const char *bin_path;
    uint64_t semaphore;
    int num_locations;
    int num_arguments;
};

typedef void (*bcc_usdt_cb)(struct bcc_usdt *);
void bcc_usdt_foreach(void *usdt, bcc_usdt_cb callback);

int bcc_usdt_enable_probe(void *, const char *, const char *);
const char *bcc_usdt_genargs(void *);
const char *bcc_usdt_get_probe_argctype(
  void *ctx, const char* probe_name, const int arg_index
);

typedef void (*bcc_usdt_uprobe_cb)(const char *, const char *, uint64_t, int);
void bcc_usdt_foreach_uprobe(void *usdt, bcc_usdt_uprobe_cb callback);

#ifdef __cplusplus
}
#endif
#endif
