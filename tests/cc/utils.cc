/*
 * Copyright (c) 2017 IBM Corporation
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
#include <stdarg.h>
#include <stdio.h>

int cmd_scanf(const char *cmd, const char *fmt, ...) {
  va_list args;
  FILE *pipe;

  va_start(args, fmt);
  pipe = popen(cmd, "r");
  if (pipe == NULL) {
    va_end(args);
    return -1;
  }

  vfscanf(pipe, fmt, args);
  va_end(args);
  pclose(pipe);
  return 0;
}
