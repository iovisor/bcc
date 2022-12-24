/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>

#include "BPF.h"
#include "bcc_version.h"

/// a simple loader for eunomia bpf program
int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <source>"
              << std::endl;
    return -1;
  }
  std::ifstream json_file(argv[1]);
  std::string json_str((std::istreambuf_iterator<char>(json_file)),
                       std::istreambuf_iterator<char>());
  ebpf::BPF bpf(0, nullptr, false, "", true, true);
  auto init_res = bpf.init(json_str);
  if (!init_res.ok()) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }
  return 0;
}
