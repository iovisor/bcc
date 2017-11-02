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
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bcc_perf_map.h"

bool bcc_is_perf_map(const char *path) {
  char* pos = strstr(path, ".map");
  // Path ends with ".map"
  return (pos != NULL) && (*(pos + 4)== 0);
}

bool bcc_is_valid_perf_map(const char *path) {
  return bcc_is_perf_map(path) && (access(path, R_OK) == 0);
}

int bcc_perf_map_nstgid(int pid) {
  char status_path[64];
  FILE *status;

  snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
  status = fopen(status_path, "r");

  if (!status)
    return -1;

  // return the original PID if we fail to work out the TGID
  int nstgid = pid;

  size_t size = 0;
  char *line = NULL;
  while (getline(&line, &size, status) != -1) {
    // check Tgid line first in case CONFIG_PID_NS is off
    if (strstr(line, "Tgid:") != NULL)
      nstgid = (int)strtol(strrchr(line, '\t'), NULL, 10);
    if (strstr(line, "NStgid:") != NULL)
      // PID namespaces can be nested -- last number is innermost PID
      nstgid = (int)strtol(strrchr(line, '\t'), NULL, 10);
  }
  free(line);
  fclose(status);

  return nstgid;
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

  int nstgid = bcc_perf_map_nstgid(pid);

  snprintf(map_path, map_len, "%s/tmp/perf-%d.map", target, nstgid);
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
    if (begin == 0 || *sep != ' ' || (begin == ULLONG_MAX && errno == ERANGE))
      continue;
    cursor = sep;
    while (*cursor && isspace(*cursor)) cursor++;

    len = strtoull(cursor, &sep, 16);
    if (*sep != ' ' ||
        (sep == cursor && len == 0) ||
        (len == ULLONG_MAX && errno == ERANGE))
      continue;
    cursor = sep;
    while (*cursor && isspace(*cursor)) cursor++;

    newline = strchr(cursor, '\n');
    if (newline)
        newline[0] = '\0';

    callback(cursor, begin, len, payload);
  }

  free(line);
  fclose(file);

  return 0;
}
