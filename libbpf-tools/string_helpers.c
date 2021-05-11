/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Chenyue Zhou */
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "string_helpers.h"

void string_free_split(char **array, int count) {
  int i;

  for (i = 0; i < count; i++) {
    free(array[i]);
  }
  free(array);
}

/**
 * string_splitlen - Splits a string according to the specified sequence,
 *                   and stores the result in an array of strings.
 * @s:      Given string.
 * @len:    Length of the given string.
 * @seq:    Given sequence.
 * @seqlen: Length of the given sequence.
 * @res:    Pointer to an array of strings used to store the result
 * @count:  The initial/final length of the array pointer (`*res`).
 *
 * RETURN VALUE
 *
 *  On success 0 is returned.
 *
 * ERRORS
 *
 *  EINVAL: Given `len` is less than 0 or `seqlen` is less than 1.
 *  ENOMEM: Not enough memory for intermediate variables or final results.
 */
int string_splitlen(const char *s, ssize_t len, const char *seq, int seqlen,
                    char ***res, int *count) {

  int elements = 0, slots = (*count) < 0 ? 0 : (*count) , err = 0;
  char **tmp;
  ssize_t i, start = 0;

  if (seqlen < 1 || len < 0)
    return EINVAL;

  for (i = 0; i < (len - (seqlen - 1)); i++) {
    /* Make sure there is room for the next element and the final one. */
    if (slots < elements + 2) {
      if (slots == 0) {
        slots = 1;
        (*res) = NULL;
      }
      slots *= 2;
      tmp = realloc((*res), sizeof(char *) * slots);
      if (!tmp) {
        err = ENOMEM;
        goto cleanup;
      }
      (*res) = tmp;
    }

    /* Search the separator. */
    if ((seqlen == 1 && *(s + i) == seq[0]) || !memcmp(s + i, seq, seqlen)) {
      (*res)[elements] = strndup(s + start, i - start);
      if (!(*res)[elements]) {
        err = ENOMEM;
        goto cleanup;
      }
      elements++;
      start = i + seqlen;
      /* i++ */
      i = i + seqlen - 1;
    }
  }

  /* Add the final element. We are sure there is room in the tokens array. */
  (*res)[elements] = strndup(s + start, len - start);
  if (!(*res)[elements]) {
    err = ENOMEM;
    goto cleanup;
  }
  elements++;
  *count = elements;

  return err;

cleanup:
  for (i = 0; i < elements; i++)
    free((*res)[i]);
  free((*res));
  *count = 0;

  return err;
}

/**
 * string_join - Joints an array of strings with the specified sequence.
 * @argv:    Given array of strings.
 * @argc:    Length of the given of array.
 * @seq:     Given sequence.
 * @seqlen:  Length of the given of sequence.
 * @res:     Pointer to a string used to store the result.
 * @res_len: The initial/final length of string (`*res`).
 *
 * RETURN VALUE
 *
 *  On success -1 is returned.
 *
 * ERRORS
 *
 *  EINVAL: Given `argc` is less than 1.
 *  ENOMEM: Not enough memory for intermediate variables or final results.
 */
int string_join(char **argv, int argc, char *seq, int seqlen, char **res,
                ssize_t *res_len) {
  ssize_t final_size = seqlen * (argc - 1), start = 0, current_len;
  char *tmp;
  int i;

  if (argc <= 0)
    return EINVAL;

  if ((*res_len) == 0)
    (*res) = NULL;

  if (argc == 1) {
    /* argv[0] + '\0' */
    current_len = strlen(argv[0]) + 1;
    if ((*res_len) < current_len) {
      tmp = realloc((*res), sizeof(char) * current_len);
      if (!tmp)
        return ENOMEM;
      (*res) = tmp;
      memcpy((*res), argv[0], current_len - 1);
      (*res)[current_len - 1] = '\0';
    }
  }

  for (i = 0; i < argc; i++) {
    final_size += strlen(argv[i]);
  }

  final_size += 1; /* \0 */
  if ((*res_len) < final_size) {
    tmp = realloc((*res), sizeof(char) * final_size);
    if (!tmp)
      return ENOMEM;
    (*res) = tmp;
  }

  for (i = 0; i < argc; i++) {
    memcpy((*res) + start, argv[i], strlen(argv[i]));
    start += strlen(argv[i]);
    if (i != argc - 1) {
      memcpy((*res) + start, seq, seqlen);
      start += seqlen;
    }
  }
  (*res)[final_size - 1] = '\0';

  return 0;
}

/**
 * string_replace - Replaces the specified sequence in a string with the target
 *                  sequence.
 * @s:       Given string.
 * @s_len:   Length of the given string (`s`).
 * @from:    Given sequence.
 * @to:      Target sequence.
 * @res:     Pointer to a string used to store the result.
 * @res_len: The initial/final length of string (`*res`).
 *
 * RETURN VALUE
 *
 *  On success 0 is returned.
 *
 * ERRORS
 *
 *  EINVAL: Given `s_len` is less than `from_len`.
 *  ENOMEM: Not enough memory for intermediate variables or final results.
 */
int string_replace(char *s, ssize_t s_len, char *from, char *to, char **res,
                   ssize_t *res_len) {
  int err = 0, from_len = strlen(from),
      to_len = strlen(to), count = 0, i;
  char **tmp, *tmp_s;

  if (from_len > s_len)
    return EINVAL;

  if ((*res_len) == 0)
    (*res) = NULL;

  if (from_len == to_len) {
    if ((*res_len) < s_len) {
      tmp_s = realloc((*res), s_len + 1);
      if (!tmp_s)
        return ENOMEM;
      (*res) = tmp_s;
      memcpy((*res), s, s_len);
    }
    for (i = 0; i < (s_len - (from_len - 1)); i++) {
      if (!memcmp((*res) + i, from, from_len)) {
        memcpy((*res) + i, to, to_len);
        /* i++ */
        i = i + to_len - 1;
      }
    }
    (*res)[s_len] = '\0';
    return 0;
  }

  if ((err = string_splitlen(s, s_len, from, from_len, &tmp, &count)))
    return err;

  err = string_join(tmp, count, to, to_len, res, res_len);
  string_free_split(tmp, count);

  return err;
}
