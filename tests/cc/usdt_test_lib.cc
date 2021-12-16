#include <sys/types.h>
#include <unistd.h>

#include "folly/tracing/StaticTracepoint.h"

extern "C" {

int lib_probed_function() {
  int an_int = 42 + getpid();
  FOLLY_SDT(libbcc_test, sample_lib_probe_1, an_int);
  return an_int;
}

}
