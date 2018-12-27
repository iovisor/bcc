/*
 * Copyright (c) 2018 Google, Inc.
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

#include <string.h>
#include <stdlib.h>

typedef enum {
  BCC_ARCH_PPC,
  BCC_ARCH_PPC_LE,
  BCC_ARCH_S390X,
  BCC_ARCH_ARM64,
  BCC_ARCH_X86
} bcc_arch_t;

typedef void *(*arch_callback_t)(bcc_arch_t arch);

static void *run_arch_callback(arch_callback_t fn)
{
  const char *archenv = getenv("ARCH");

  /* If ARCH is not set, detect from local arch clang is running on */
  if (!archenv) {
#if defined(__powerpc64__)
#if defined(_CALL_ELF) && _CALL_ELF == 2
    return fn(BCC_ARCH_PPC_LE);
#else
    return fn(BCC_ARCH_PPC);
#endif
#elif defined(__s390x__)
    return fn(BCC_ARCH_S390X);
#elif defined(__aarch64__)
    return fn(BCC_ARCH_ARM64);
#else
    return fn(BCC_ARCH_X86);
#endif
  }

  /* Otherwise read it from ARCH */
  if (!strcmp(archenv, "powerpc")) {
#if defined(_CALL_ELF) && _CALL_ELF == 2
    return fn(BCC_ARCH_PPC_LE);
#else
    return fn(BCC_ARCH_PPC);
#endif
  } else if (!strcmp(archenv, "s390x")) {
    return fn(BCC_ARCH_S390X);
  } else if (!strcmp(archenv, "arm64")) {
    return fn(BCC_ARCH_ARM64);
  } else {
    return fn(BCC_ARCH_X86);
  }
}
