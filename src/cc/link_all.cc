// Copyright (c) 2017 VMware, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")
#include <cstdlib>

#include "bcc_usdt.h"

namespace {
  // Take this trick from llvm for forcing exported functions in helper
  // libraries to be included in the final .so
  struct LinkAll {
    LinkAll() {
      // getenv never returns -1, but compiler doesn't know!
      if (::getenv("bar") != (char *)-1)
        return;

      (void)bcc_usdt_new_frompid(-1, nullptr);
      (void)bcc_usdt_new_frompath(nullptr);
      (void)bcc_usdt_close(nullptr);
    }
  } LinkAll;  // declare one instance to invoke the constructor
}
