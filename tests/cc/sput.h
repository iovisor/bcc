/*
 *  sput - Simple, Portable Unit Testing Framework for C/C++ v1.3.1
 *
 *              http://www.lingua-systems.com/unit-testing/
 *
 *
 *  Copyright (c) 2011-2015 Lingua-Systems Software GmbH
 *
 *  All rights reserved.
 *
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 *  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef HAVE_SPUT_H
#define HAVE_SPUT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ===================================================================
 *                             definitions
 * =================================================================== */

#define SPUT_VERSION_MAJOR 1
#define SPUT_VERSION_MINOR 3
#define SPUT_VERSION_PATCH 1
#define SPUT_VERSION_STRING "1.3.1"

#define SPUT_DEFAULT_SUITE_NAME "Unlabeled Suite"
#define SPUT_DEFAULT_CHECK_NAME "Unlabeled Check"

#define SPUT_INITIALIZED 0x06 /* ACK */

/* ===================================================================
 *                        sput global variable
 * =================================================================== */

static struct sput {
  FILE *out;
  char initialized;

  struct sput_overall {
    unsigned long checks;
    unsigned long suites;
    unsigned long ok;
    unsigned long nok;
  } overall;

  struct sput_suite {
    const char *name;
    unsigned long nr;
    unsigned long checks;
    unsigned long ok;
    unsigned long nok;
  } suite;

  struct sput_test {
    const char *name;
    unsigned long nr;
  } test;

  struct sput_check {
    const char *name;
    const char *cond;
    const char *type;
    unsigned long line;
  } check;

  struct sput_time {
    time_t start;
    time_t end;
  } time;
} __sput;

/* ==================================================================
 *                        sput internal macros
 * ================================================================== */

#define _sput_die_unless_initialized()               \
  if (__sput.initialized != SPUT_INITIALIZED) {      \
    fputs("sput_start_testing() omitted\n", stderr); \
    exit(EXIT_FAILURE);                              \
  }

#define _sput_die_unless_suite_set()                   \
  if (!__sput.suite.name) {                            \
    fputs("sput_enter_suite() omitted\n", __sput.out); \
    exit(EXIT_FAILURE);                                \
  }

#define _sput_die_unless_test_set()                 \
  if (!__sput.test.name) {                          \
    fputs("sput_run_test() omitted\n", __sput.out); \
    exit(EXIT_FAILURE);                             \
  }

#define _sput_check_failed()                                        \
  {                                                                 \
    _sput_die_unless_initialized();                                 \
    _sput_die_unless_suite_set();                                   \
    __sput.suite.nok++;                                             \
    fprintf(__sput.out,                                             \
            "[%lu:%lu]  %s:#%lu  \"%s\"  FAIL\n"                    \
            "!    Type:      %s\n"                                  \
            "!    Condition: %s\n"                                  \
            "!    Line:      %lu\n",                                \
            __sput.suite.nr, __sput.suite.checks, __sput.test.name, \
            __sput.test.nr, __sput.check.name, __sput.check.type,   \
            __sput.check.cond, __sput.check.line);                  \
  }

#define _sput_check_succeeded()                                                \
  {                                                                            \
    _sput_die_unless_initialized();                                            \
    _sput_die_unless_suite_set();                                              \
    __sput.suite.ok++;                                                         \
    fprintf(__sput.out, "[%lu:%lu]  %s:#%lu  \"%s\"  pass\n", __sput.suite.nr, \
            __sput.suite.checks, __sput.test.name, __sput.test.nr,             \
            __sput.check.name);                                                \
  }

/* ==================================================================
 *                            user macros
 * ================================================================== */

#define sput_start_testing()               \
  do {                                     \
    memset(&__sput, 0, sizeof(__sput));    \
    __sput.out = stdout;                   \
    __sput.time.start = time(NULL);        \
    __sput.initialized = SPUT_INITIALIZED; \
  } while (0)

#define sput_leave_suite()                                                    \
  do {                                                                        \
    float failpls = 0.0f;                                                     \
    _sput_die_unless_initialized();                                           \
    _sput_die_unless_suite_set();                                             \
    failpls = __sput.suite.checks                                             \
                  ? (float)((__sput.suite.nok * 100.0) / __sput.suite.checks) \
                  : 0.0f;                                                     \
    fprintf(__sput.out, "\n--> %lu check(s), %lu ok, %lu failed (%.2f%%)\n",  \
            __sput.suite.checks, __sput.suite.ok, __sput.suite.nok, failpls); \
    __sput.overall.checks += __sput.suite.checks;                             \
    __sput.overall.ok += __sput.suite.ok;                                     \
    __sput.overall.nok += __sput.suite.nok;                                   \
    memset(&__sput.suite, 0, sizeof(__sput.suite));                           \
  } while (0)

#define sput_get_return_value() \
  (__sput.overall.nok > 0 ? EXIT_FAILURE : EXIT_SUCCESS)

#define sput_enter_suite(_name)                                          \
  do {                                                                   \
    _sput_die_unless_initialized();                                      \
    if (__sput.suite.name) {                                             \
      sput_leave_suite();                                                \
    }                                                                    \
    __sput.suite.name = _name != NULL ? _name : SPUT_DEFAULT_SUITE_NAME; \
    __sput.suite.nr = ++__sput.overall.suites;                           \
    fprintf(__sput.out, "\n== Entering suite #%lu, \"%s\" ==\n\n",       \
            __sput.suite.nr, __sput.suite.name);                         \
  } while (0)

#define sput_finish_testing()                                               \
  do {                                                                      \
    float failpft = 0.0f;                                                   \
    _sput_die_unless_initialized();                                         \
    if (__sput.suite.name) {                                                \
      sput_leave_suite();                                                   \
    }                                                                       \
    failpft =                                                               \
        __sput.overall.checks                                               \
            ? (float)((__sput.overall.nok * 100.0) / __sput.overall.checks) \
            : 0.0f;                                                         \
    __sput.time.end = time(NULL);                                           \
    fprintf(                                                                \
        __sput.out,                                                         \
        "\n==> %lu check(s) in %lu suite(s) finished after %.2f "           \
        "second(s),\n"                                                      \
        "    %lu succeeded, %lu failed (%.2f%%)\n"                          \
        "\n[%s]\n",                                                         \
        __sput.overall.checks, __sput.overall.suites,                       \
        difftime(__sput.time.end, __sput.time.start), __sput.overall.ok,    \
        __sput.overall.nok, failpft,                                        \
        (sput_get_return_value() == EXIT_SUCCESS) ? "SUCCESS" : "FAILURE"); \
  } while (0)

#define sput_set_output_stream(_fp)          \
  do {                                       \
    __sput.out = _fp != NULL ? _fp : stdout; \
  } while (0)

#define sput_fail_if(_cond, _name)                                       \
  do {                                                                   \
    _sput_die_unless_initialized();                                      \
    _sput_die_unless_suite_set();                                        \
    _sput_die_unless_test_set();                                         \
    __sput.check.name = _name != NULL ? _name : SPUT_DEFAULT_CHECK_NAME; \
    __sput.check.line = __LINE__;                                        \
    __sput.check.cond = #_cond;                                          \
    __sput.check.type = "fail-if";                                       \
    __sput.test.nr++;                                                    \
    __sput.suite.checks++;                                               \
    if ((_cond)) {                                                       \
      _sput_check_failed();                                              \
    } else {                                                             \
      _sput_check_succeeded();                                           \
    }                                                                    \
  } while (0)

#define sput_fail_unless(_cond, _name)                                   \
  do {                                                                   \
    _sput_die_unless_initialized();                                      \
    _sput_die_unless_suite_set();                                        \
    _sput_die_unless_test_set();                                         \
    __sput.check.name = _name != NULL ? _name : SPUT_DEFAULT_CHECK_NAME; \
    __sput.check.line = __LINE__;                                        \
    __sput.check.cond = #_cond;                                          \
    __sput.check.type = "fail-unless";                                   \
    __sput.test.nr++;                                                    \
    __sput.suite.checks++;                                               \
    if (!(_cond)) {                                                      \
      _sput_check_failed();                                              \
    } else {                                                             \
      _sput_check_succeeded();                                           \
    }                                                                    \
  } while (0)

#define sput_run_test(_func)                      \
  do {                                            \
    _sput_die_unless_initialized();               \
    _sput_die_unless_suite_set();                 \
    memset(&__sput.test, 0, sizeof(__sput.test)); \
    __sput.test.name = #_func;                    \
    _func();                                      \
  } while (0)

#ifdef __cplusplus
}
#endif

#endif /* HAVE_SPUT_H */

/* vim: set ft=c sts=4 sw=4 ts=4 ai et: */
