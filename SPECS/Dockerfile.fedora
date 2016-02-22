# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

FROM fedora:rawhide

MAINTAINER Brenden Blanco <bblanco@plumgrid.com>

RUN dnf -y install bison cmake flex gcc gcc-c++ git libxml2-devel make python2-devel rpm-build wget zlib-devel

WORKDIR /root

RUN wget http://llvm.org/releases/3.7.1/{cfe,llvm}-3.7.1.src.tar.xz

RUN tar -xf llvm-3.7.1.src.tar.xz && mkdir llvm-3.7.1.src/tools/clang && tar -xf cfe-3.7.1.src.tar.xz -C llvm-3.7.1.src/tools/clang --strip 1 && mkdir llvm-3.7.1.src/build
RUN cd llvm-3.7.1.src/build && cmake .. -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="X86;BPF" -DCMAKE_INSTALL_PREFIX=/usr
RUN cd llvm-3.7.1.src/build && make -j8

COPY . bcc
WORKDIR /root/bcc
RUN PATH=/root/llvm-3.7.1.src/build/bin:$PATH ./scripts/build-rpm.sh
