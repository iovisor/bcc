// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#packed "false"

struct pt_regs {
  u64 r15:64;
  u64 r14:64;
  u64 r13:64;
  u64 r12:64;
  u64 bp:64;
  u64 bx:64;
  u64 r11:64;
  u64 r10:64;
  u64 r9:64;
  u64 r8:64;
  u64 ax:64;
  u64 cx:64;
  u64 dx:64;
  u64 si:64;
  u64 di:64;
};


