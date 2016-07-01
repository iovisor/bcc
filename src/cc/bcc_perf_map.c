/*
 * Copyright (c) 2016 Facebook, Inc.
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
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bcc_perf_map.h"

int bcc_perf_map_nspid(int pid) {
  char status_path[64];
  FILE *status;

  snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
  status = fopen(status_path, "r");

  if (!status)
    return -1;

  // return the original PID if the NSpid line is missing
  int nspid = pid;

  size_t size = 0;
  char *line = NULL;
  while (getline(&line, &size, status) != -1) {
    if (strstr(line, "NSpid:") != NULL)
      // PID namespaces can be nested -- last number is innermost PID
      nspid = (int)strtol(strrchr(line, '\t'), NULL, 10);
  }
  free(line);

  return nspid;
}

bool bcc_perf_map_path(char *map_path, size_t map_len, int pid) {
  char source[64];
  snprintf(source, sizeof(source), "/proc/%d/root", pid);

  char target[4096];
  ssize_t target_len = readlink(source, target, sizeof(target) - 1);
  if (target_len == -1)
    return false;

  target[target_len] = '\0';
  if (strcmp(target, "/") == 0)
    target[0] = '\0';

  int nspid = bcc_perf_map_nspid(pid);

  snprintf(map_path, map_len, "%s/tmp/perf-%d.map", target, nspid);
  return true;
}

int bcc_perf_map_foreach_sym(const char *path, bcc_perf_map_symcb callback,
                             void* payload) {
  FILE* file = fopen(path, "r");
  if (!file)
    return -1;

  char *line = NULL;
  size_t size = 0;
  long long begin, len;
  while (getline(&line, &size, file) != -1) {
    char *cursor = line;
    char *newline, *sep;

    begin = strtoull(cursor, &sep, 16);
    if (*sep != ' ' || (sep == cursor && begin == 0))
      continue;
    cursor = sep;
    while (*cursor && isspace(*cursor)) cursor++;

    len = strtoull(cursor, &sep, 16);
    if (*sep != ' ' || (sep == cursor && begin == 0))
      continue;
    cursor = sep;
    while (*cursor && isspace(*cursor)) cursor++;

    newline = strchr(cursor, '\n');
    if (newline)
        newline[0] = '\0';

    callback(cursor, begin, len, 0, payload);
  }

  free(line);
  fclose(file);

  return 0;
}
