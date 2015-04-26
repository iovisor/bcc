#include "cc/bpf_program.h"
#include "cc/bpf_common.h"

extern "C" {
void * bpf_program_create(const char *filename, const char *proto_filename, unsigned flags) {
  auto prog = new ebpf::BPFProgram(flags);
  if (prog->load(filename, proto_filename) != 0) {
    delete prog;
    return nullptr;
  }
  return prog;
}

void bpf_program_destroy(void *program) {
  auto prog = static_cast<ebpf::BPFProgram *>(program);
  if (!prog) return;
  delete prog;
}

void * bpf_program_start(void *program, const char *name) {
  auto prog = static_cast<ebpf::BPFProgram *>(program);
  if (!prog) return nullptr;
  return prog->start(name);
}

size_t bpf_program_size(void *program, const char *name) {
  auto prog = static_cast<ebpf::BPFProgram *>(program);
  if (!prog) return 0;
  return prog->size(name);
}

char * bpf_program_license(void *program) {
  auto prog = static_cast<ebpf::BPFProgram *>(program);
  if (!prog) return nullptr;
  return prog->license();
}

int bpf_program_table_fd(void *program, const char *table_name) {
  auto prog = static_cast<ebpf::BPFProgram *>(program);
  if (!prog) return -1;
  return prog->table_fd(table_name);
}

}
