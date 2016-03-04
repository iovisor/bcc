#include "bpf_common.h"

int main(int argc, char **argv) {
  void *mod = bpf_module_create_c_from_string("BPF_TABLE(\"array\", int, int, stats, 10);\n", 4, NULL, 0);
  return !(mod != NULL);
}
