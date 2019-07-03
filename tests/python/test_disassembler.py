#!/usr/bin/env python
# Copyright (c) Clevernet
# Licensed under the Apache License, Version 2.0 (the "License")

# test program for the 'disassemble_func' and 'decode_table' methods

from bcc import BPF
from bcc import disassembler
import ctypes as ct
import random
from unittest import main, TestCase


class BPFInstr(ct.Structure):
    _pack_ = 1
    _fields_ = [
        ("opcode", ct.c_uint8),
        ("dst", ct.c_uint8, 4),
        ("src", ct.c_uint8, 4),
        ("offset", ct.c_int16),
        ("imm", ct.c_int32),
    ]


class TestDisassembler(TestCase):
    opcodes = [
        (0x04, "%dst += %imm"),
        (0x05, "goto %off <%jmp>"),
        (0x07, "%dst += %imm"),
        (0x0C, "%dst += %src"),
        (0x0F, "%dst += %src"),
        (0x14, "%dst -= %imm"),
        (0x15, "if %dst == %imm goto pc%off <%jmp>"),
        (0x17, "%dst -= %imm"),
        # (0x18, "lddw"),
        (0x1C, "%dst -= %src"),
        (0x1D, "if %dst == %src goto pc%off <%jmp>"),
        (0x1F, "%dst -= %src"),
        (0x20, "r0 = *(u32*)skb[%imm]"),
        (0x24, "%dst *= %imm"),
        (0x25, "if %dst > %imm goto pc%off <%jmp>"),
        (0x27, "%dst *= %imm"),
        (0x28, "r0 = *(u16*)skb[%imm]"),
        (0x2C, "%dst *= %src"),
        (0x2D, "if %dst > %src goto pc%off <%jmp>"),
        (0x2F, "%dst *= %src"),
        (0x30, "r0 = *(u8*)skb[%imm]"),
        (0x34, "%dst /= %imm"),
        (0x35, "if %dst >= %imm goto pc%off <%jmp>"),
        (0x37, "%dst /= %imm"),
        (0x38, "r0 = *(u64*)skb[%imm]"),
        (0x3C, "%dst /= %src"),
        (0x3D, "if %dst >= %src goto pc%off <%jmp>"),
        (0x3F, "%dst /= %src"),
        (0x40, "r0 = *(u32*)skb[%src %sim]"),
        (0x44, "%dst |= %ibw"),
        (0x45, "if %dst & %imm goto pc%off <%jmp>"),
        (0x47, "%dst |= %ibw"),
        (0x48, "r0 = *(u16*)skb[%src %sim]"),
        (0x4C, "%dst |= %src"),
        (0x4D, "if %dst & %src goto pc%off <%jmp>"),
        (0x4F, "%dst |= %src"),
        (0x50, "r0 = *(u8*)skb[%src %sim]"),
        (0x54, "%dst &= %ibw"),
        (0x55, "if %dst != %imm goto pc%off <%jmp>"),
        (0x57, "%dst &= %ibw"),
        (0x58, "r0 = *(u64*)skb[%src %sim]"),
        (0x5C, "%dst &= %src"),
        (0x5D, "if %dst != %src goto pc%off <%jmp>"),
        (0x5F, "%dst &= %src"),
        (0x61, "%dst = *(u32*)(%src %off)"),
        (0x62, "*(u32*)(%dst %off) = %imm"),
        (0x63, "*(u32*)(%dst %off) = %src"),
        (0x64, "%dst <<= %imm"),
        (0x65, "if %dst s> %imm goto pc%off <%jmp>"),
        (0x67, "%dst <<= %imm"),
        (0x69, "%dst = *(u16*)(%src %off)"),
        (0x6A, "*(u16*)(%dst %off) = %imm"),
        (0x6B, "*(u16*)(%dst %off) = %src"),
        (0x6C, "%dst <<= %src"),
        (0x6D, "if %dst s> %src goto pc%off <%jmp>"),
        (0x6F, "%dst <<= %src"),
        (0x71, "%dst = *(u8*)(%src %off)"),
        (0x72, "*(u8*)(%dst %off) = %imm"),
        (0x73, "*(u8*)(%dst %off) = %src"),
        (0x74, "%dst >>= %imm"),
        (0x75, "if %dst s>= %imm goto pc%off <%jmp>"),
        (0x77, "%dst >>= %imm"),
        (0x79, "%dst = *(u64*)(%src %off)"),
        (0x7A, "*(u64*)(%dst %off) = %imm"),
        (0x7B, "*(u64*)(%dst %off) = %src"),
        (0x7C, "%dst >>= %src"),
        (0x7D, "if %dst s>= %src goto pc%off <%jmp>"),
        (0x7F, "%dst >>= %src"),
        (0x84, "%dst = ~ (u32)%dst"),
        # (0x85, "call"),
        (0x87, "%dst = ~ (u64)%dst"),
        (0x94, "%dst %= %imm"),
        (0x95, "exit"),
        (0x97, "%dst %= %imm"),
        (0x9C, "%dst %= %src"),
        (0x9F, "%dst %= %src"),
        (0xA4, "%dst ^= %ibw"),
        (0xA5, "if %dst < %imm goto pc%off <%jmp>"),
        (0xA7, "%dst ^= %ibw"),
        (0xAC, "%dst ^= %src"),
        (0xAD, "if %dst < %src goto pc%off <%jmp>"),
        (0xAF, "%dst ^= %src"),
        (0xB4, "%dst = %imm"),
        (0xB5, "if %dst <= %imm goto pc%off <%jmp>"),
        (0xB7, "%dst = %imm"),
        (0xBC, "%dst = %src"),
        (0xBD, "if %dst <= %src goto pc%off <%jmp>"),
        (0xBF, "%dst = %src"),
        (0xC4, "%dst s>>= %imm"),
        (0xC5, "if %dst s< %imm goto pc%off <%jmp>"),
        (0xC7, "%dst s>>= %imm"),
        (0xCC, "%dst s>>= %src"),
        (0xCD, "if %dst s< %src goto pc%off <%jmp>"),
        (0xCF, "%dst s>>= %src"),
        (0xD5, "if %dst s<= %imm goto pc%off <%jmp>"),
        (0xDC, "%dst endian %src"),
        (0xDD, "if %dst s<= %imm goto pc%off <%jmp>"),
    ]

    @classmethod
    def build_instr(cls, op):
        dst = random.randint(0, 0xF)
        src = random.randint(0, 0xF)
        offset = random.randint(0, 0xFFFF)
        imm = random.randint(0, 0xFFFFFFFF)
        return BPFInstr(op, dst, src, offset, imm)

    @classmethod
    def format_instr(cls, instr, fmt):
        uimm = ct.c_uint32(instr.imm).value
        return (
            fmt.replace("%dst", "r%d" % (instr.dst))
            .replace("%src", "r%d" % (instr.src))
            .replace("%imm", "%d" % (instr.imm))
            .replace("%ibw", "0x%x" % (uimm))
            .replace("%sim", "%+d" % (instr.imm))
            .replace("%off", "%+d" % (instr.offset))
            .replace("%jmp", "%d" % (instr.offset + 1))
        )

    def test_func(self):
        b = BPF(
            text="""
            struct key_t {int a; short b; struct {int c:4; int d:8;} e;} __attribute__((__packed__));
            BPF_HASH(test_map, struct key_t);
            int test_func(void)
            {
                return 1;
            }"""
        )

        self.assertEqual(
            """Disassemble of BPF program test_func:
   0: (b7) r0 = 1
   1: (95) exit""",
            b.disassemble_func("test_func"),
        )

        self.assertEqual(
            """Layout of BPF map test_map (type HASH, FD 3, ID 0):
  struct {
    int a;
    short b;
    struct {
      int c:4;
      int d:8;
    } e;
  } key;
  unsigned long long value;""",
            b.decode_table("test_map"),
        )

    def test_bpf_isa(self):
        for op, instr_fmt in self.opcodes:
            instr_fmt
            if instr_fmt is None:
                continue
            instr = self.build_instr(op)
            instr_str = ct.string_at(ct.addressof(instr), ct.sizeof(instr))
            target_text = self.format_instr(instr, instr_fmt)
            self.assertEqual(
                disassembler.disassemble_str(instr_str)[0],
                "%4d: (%02x) %s" % (0, op, target_text),
            )


if __name__ == "__main__":
    main()
