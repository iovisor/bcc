/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Chenyue Zhou */
#include <set>
#include <algorithm>
#include <string>
#include <regex>
#include <fstream>
#include <sstream>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "kprobe_helpers.h"

using namespace std;

#define startswith(str, prefix) ((str).find(prefix) == 0)

/**
 * get_kprobe_functions - get matched functions from `/proc/kallsyms`.
 * @pattern: Pattern string used for regular matching.
 * @list:    Pointer to an array of string used to store the matched function name.
 * @sz:      The initial/final length of the array (*list).
 *
 * RETURN VALUE
 *
 *  On success 0 is returned.
 *
 * ERRORS
 *  ERANGE: The number of matched functions is large than `KPROBE_LIMIT`.
 *          `sz` was set to `KPROBE_LIMIT`, and `KPROBE_LIMIT` matched
 *          functions in `list`.
 *  ENOMEM: Not enough memory for intermediate variables or final results.
 *  OTHERR: Failed to read from `/proc/kallsyms`. `sz` was set to 0.
 */
int get_kprobe_functions(const char *pattern, char ***list, size_t *sz) {
  string line;
  set<string> kprobe_blacklist_set, matched_function_set;
  ifstream kprobe_blacklist_stream { KPROBE_BLACKLIST_FILE };

  while (getline(kprobe_blacklist_stream, line)) {
    size_t pos = line.find("\t");
    if (pos != string::npos) {
      line = line.substr(pos + 1);
      kprobe_blacklist_set.insert(line);
    }
  }

  size_t count = 0, list_size = (*sz) < 0 ? 0 : (*sz);
  int in_init_section = 0, in_irq_section = 0;
  regex pt("^.*\\.cold(\\.\\d+)?$");
  regex event_re (pattern);
  ifstream kallsyms_stream { "/proc/kallsyms" };
  if (!kallsyms_stream) {
    *sz = 0;
    return errno;
  }

  while (getline(kallsyms_stream, line)) {
    string tp;
    size_t type_pos = line.find(" ");
    if (type_pos == string::npos)
      continue;

    line = line.substr(type_pos + 1);
    size_t name_pos = line.find(" ");
    if (name_pos == string::npos)
      continue;

    tp = line.substr(0, name_pos);
    transform(tp.begin(), tp.end(), tp.begin(),
              [](unsigned char c){ return tolower(c); });
    line = line.substr(name_pos + 1);
    size_t name_pos_end = line.find(" ");
    if (name_pos_end != string::npos) {
      line = line.substr(0, name_pos_end);
    }

    /*
     * Skip all functions defined between __init_begin and __init_end
     */
    if (in_init_section == 0) {
      if (!line.compare("__init_begin")) {
        in_init_section = 1;
        continue;
      }
    } else if (in_init_section == 1) {
      if (!line.compare("__init_end"))
        in_init_section = 2;
      continue;
    }

    /*
     * Skip all functions defined between __irqentry_text_start and
     * __irqentry_text_end
     */
    if (in_irq_section == 0) {
      if (!line.compare("__irqentry_text_start")) {
        in_irq_section = 1;
        continue;
      } else if (!line.compare("__irqentry_text_end")) {
        /*
         * __irqentry_text_end is not always after
         * __irqentry_text_start. But only happens when
         * no functions between two irqentry_text
         */
        in_irq_section = 2;
        continue;
      }
    } else if (in_irq_section == 1) {
      if (!line.compare("__irqentry_text_end"))
        in_irq_section = 2;
      continue;
    }

    /*
     * All functions defined as NOKPROBE_SYMBOL() start with the
     * prefix _kbl_addr_*, blacklisting them by looking at the name
     * allows to catch also those symbols that are defined in kernel
     * modules.
     *
     * Explicitly blacklist perf-related functions, they are all
     * non-attachable.
     */
    if (startswith(line, "_kbl_addr_") ||
        startswith(line, "__perf") ||
        startswith(line, "perf_"))
      continue;

    /* Exclude all gcc 8's extra .cold functions */
    if (regex_match(line, pt))
      continue;

    if (!tp.compare("t") || !tp.compare("w")) {
      if (regex_match(line, event_re) &&
          kprobe_blacklist_set.find(line) == kprobe_blacklist_set.end()) {
        if (matched_function_set.find(line) == matched_function_set.end()) {
          matched_function_set.insert(line);
          if (++count > list_size) {
            char **tmp;
            if (list_size == 0) {
              list_size = 1;
              (*list) = NULL;
            }
            list_size *= 2;
            tmp = (char **) realloc((*list), list_size * sizeof(char *));
            if (!tmp) {
              free_kprobe_functions((*list), count - 2);
              return ENOMEM;
            }
            (*list) = tmp;
          }

          (*list)[count - 1] = strdup(line.c_str());
        }

        if (count >= KPROBE_LIMIT) {
          *sz = count;
          return ERANGE;
        }
      }
    }
  }

  *sz = count;

  return 0;
}

void free_kprobe_functions(char **list, size_t sz) {
  size_t i;

  for (i = 0; i < sz; i++) {
    free(list[i]);
  }

  free(list);
}
