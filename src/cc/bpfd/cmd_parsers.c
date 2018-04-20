/*
 * BPFd (Berkeley Packet Filter daemon)
 *
 * Copyright (C) 2018 Jazel Canseco <jcanseco@google.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd_parsers.h"

int count_num_tokens(const char *str) {
  char *str_copy = NULL;
  int num_tokens = 0;
  char *token = NULL;

  str_copy = (char *)malloc(strlen(str) + 1);
  strcpy(str_copy, str);

  for (token = strtok(str_copy, " "); token != NULL;
       token = strtok(NULL, " ")) {
    num_tokens++;
  }

  free(str_copy);
  return num_tokens;
}

struct user_input *parse_user_input(const char *str) {
  struct user_input *in = NULL;
  char *str_copy = NULL, *token = NULL;
  int arg_index = 0, num_tokens = 0;

  num_tokens = count_num_tokens(str);

  in = (struct user_input *)malloc(sizeof(struct user_input));
  in->num_args = num_tokens > 1 ? num_tokens - 1 : 0;
  in->args =
      in->num_args > 0 ? (char **)malloc(in->num_args * sizeof(char *)) : NULL;

  if (num_tokens == 0) {
    in->cmd = NULL;
    return in;
  }

  str_copy = (char *)malloc(strlen(str) + 1);
  strcpy(str_copy, str);

  token = strtok(str_copy, " ");
  in->cmd = (char *)malloc(strlen(token) + 1);
  strcpy(in->cmd, token);

  if (in->num_args > 0) {
    while ((token = strtok(NULL, " "))) {
      in->args[arg_index] = (char *)malloc(strlen(token) + 1);
      strcpy(in->args[arg_index], token);
      arg_index++;
    }
  }

  free(str_copy);
  return in;
}

void free_user_input(struct user_input *in) {
  int i;

  if (!in)
    return;

  if (in->cmd)
    free(in->cmd);

  if (in->args) {
    for (i = 0; i < in->num_args; i++)
      free(in->args[i]);

    free(in->args);
  }

  free(in);
}

int parse_int_arg(const struct user_input *in, int index, int *val) {
  if (index < 0 || index > in->num_args - 1)
    return -1;

  return !(sscanf(in->args[index], "%d", val) == 1);
}

int parse_uint_arg(const struct user_input *in, int index, unsigned int *val) {
  if (index < 0 || index > in->num_args - 1)
    return -1;

  return !(sscanf(in->args[index], "%u", val) == 1);
}

int parse_uint32_arg(const struct user_input *in, int index, uint32_t *val) {
  if (index < 0 || index > in->num_args - 1)
    return -1;

  return !(sscanf(in->args[index], "%" SCNu32 "", val) == 1);
}

int parse_uint64_arg(const struct user_input *in, int index, uint64_t *val) {
  if (index < 0 || index > in->num_args - 1)
    return -1;

  return !(sscanf(in->args[index], "%" SCNu64 "", val) == 1);
}

int parse_ull_arg(const struct user_input *in, int index,
                  unsigned long long *val) {
  if (index < 0 || index > in->num_args - 1)
    return -1;

  return !(sscanf(in->args[index], "%llu", val) == 1);
}

int parse_str_arg(const struct user_input *in, int index, char **val) {
  if (index < 0 || index > in->num_args - 1)
    return -1;

  *val = in->args[index];
  return 0;
}
