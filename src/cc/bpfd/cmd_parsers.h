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

struct user_input {
  char *cmd;
  char **args;
  int num_args;
};

/*
 * Parses the string into a user_input struct object.
 * The string is assumed to take the format of
 *
 *   cmd arg1 arg2 arg3 ... argn
 *
 * If no cmd is provided (i.e. an empty string), the 'cmd' and 'args' fields are
 * set to NULL.
 * If a cmd is provided, but with no args, only the 'args' field is set to NULL.
 */
struct user_input *parse_user_input(const char *str);

/*
 * Frees user_input struct objects and their contents.
 */
void free_user_input(struct user_input *in);

/*
 * Functions for parsing arguments encapsulated by the user_input struct.
 * Returns 0 on success.
 */
int parse_int_arg(const struct user_input *in, int index, int *val);
int parse_uint_arg(const struct user_input *in, int index, unsigned int *val);
int parse_uint32_arg(const struct user_input *in, int index, uint32_t *val);
int parse_uint64_arg(const struct user_input *in, int index, uint64_t *val);
int parse_ull_arg(const struct user_input *in, int index,
                  unsigned long long *val);
int parse_str_arg(const struct user_input *in, int index, char **val);
