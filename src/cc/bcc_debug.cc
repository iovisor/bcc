/*
 * Copyright (c) 2017 Facebook, Inc.
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

#include <map>
#include <string>
#include <tuple>
#include <vector>

#include <llvm/DebugInfo/DWARF/DWARFContext.h>
#include <llvm/DebugInfo/DWARF/DWARFDebugLine.h>
#include <llvm/IR/Module.h>
#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCObjectFileInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/Support/TargetRegistry.h>

#include "bcc_debug.h"

namespace ebpf {

// ld_pseudo can only be disassembled properly
// in llvm 6.0, so having this workaround now
// until disto llvm versions catch up
#define WORKAROUND_FOR_LD_PSEUDO

using std::get;
using std::map;
using std::string;
using std::tuple;
using std::vector;
using namespace llvm;
using DWARFLineTable = DWARFDebugLine::LineTable;

void SourceDebugger::adjustInstSize(uint64_t &Size, uint8_t byte0,
                                    uint8_t byte1) {
#ifdef WORKAROUND_FOR_LD_PSEUDO
  bool isLittleEndian = mod_->getDataLayout().isLittleEndian();
  if (byte0 == 0x18 && ((isLittleEndian && (byte1 & 0xf) == 0x1) ||
                        (!isLittleEndian && (byte1 & 0xf0) == 0x10)))
    Size = 16;
#endif
}

vector<string> SourceDebugger::buildLineCache() {
  vector<string> LineCache;
  size_t FileBufSize = mod_src_.size();

  for (uint32_t start = 0, end = start; end < FileBufSize; end++)
    if (mod_src_[end] == '\n' || end == FileBufSize - 1 ||
        (mod_src_[end] == '\r' && mod_src_[end + 1] == '\n')) {
      // Not including the endline
      LineCache.push_back(string(mod_src_.substr(start, end - start)));
      if (mod_src_[end] == '\r')
        end++;
      start = end + 1;
    }

  return LineCache;
}

void SourceDebugger::dumpSrcLine(const vector<string> &LineCache,
                                 const string &FileName, uint32_t Line,
                                 uint32_t &CurrentSrcLine,
                                 llvm::raw_ostream &os) {
  if (Line != 0 && Line != CurrentSrcLine && Line < LineCache.size() &&
      FileName == mod_->getSourceFileName()) {
    os << "; " << StringRef(LineCache[Line - 1]).ltrim()
       << format(
              " // Line"
              "%4" PRIu64 "\n",
              Line);
    CurrentSrcLine = Line;
  }
}

void SourceDebugger::getDebugSections(
    StringMap<std::unique_ptr<MemoryBuffer>> &DebugSections) {
  for (auto section : sections_) {
    if (strncmp(section.first.c_str(), ".debug", 6) == 0) {
      StringRef SecData(reinterpret_cast<const char *>(get<0>(section.second)),
                        get<1>(section.second));
      DebugSections[section.first.substr(1)] =
          MemoryBuffer::getMemBufferCopy(SecData);
    }
  }
}

void SourceDebugger::dump() {
  string Error;
  string TripleStr(mod_->getTargetTriple());
  Triple TheTriple(TripleStr);
  const Target *T = TargetRegistry::lookupTarget(TripleStr, Error);
  if (!T) {
    errs() << "Debug Error: cannot get target\n";
    return;
  }

  std::unique_ptr<MCRegisterInfo> MRI(T->createMCRegInfo(TripleStr));
  if (!MRI) {
    errs() << "Debug Error: cannot get register info\n";
    return;
  }
  std::unique_ptr<MCAsmInfo> MAI(T->createMCAsmInfo(*MRI, TripleStr));
  if (!MAI) {
    errs() << "Debug Error: cannot get assembly info\n";
    return;
  }

  MCObjectFileInfo MOFI;
  MCContext Ctx(MAI.get(), MRI.get(), &MOFI, nullptr);
  MOFI.InitMCObjectFileInfo(TheTriple, false, Ctx, false);
  std::unique_ptr<MCSubtargetInfo> STI(
      T->createMCSubtargetInfo(TripleStr, "", ""));

  std::unique_ptr<MCInstrInfo> MCII(T->createMCInstrInfo());
  MCInstPrinter *IP = T->createMCInstPrinter(TheTriple, 0, *MAI, *MCII, *MRI);
  if (!IP) {
    errs() << "Debug Error: unable to create instruction printer\n";
    return;
  }

  std::unique_ptr<const MCDisassembler> DisAsm(
      T->createMCDisassembler(*STI, Ctx));
  if (!DisAsm) {
    errs() << "Debug Error: no disassembler\n";
    return;
  }

  // Set up the dwarf debug context
  StringMap<std::unique_ptr<MemoryBuffer>> DebugSections;
  getDebugSections(DebugSections);
  std::unique_ptr<DWARFContext> DwarfCtx =
      DWARFContext::create(DebugSections, 8);
  if (!DwarfCtx) {
    errs() << "Debug Error: dwarf context creation failed\n";
    return;
  }

  // bcc has only one compilation unit
  // getCompileUnitAtIndex() was gone in llvm 8.0 (https://reviews.llvm.org/D49741)
#if LLVM_MAJOR_VERSION >= 8
  DWARFCompileUnit *CU = cast<DWARFCompileUnit>(DwarfCtx->getUnitAtIndex(0));
#else
  DWARFCompileUnit *CU = DwarfCtx->getCompileUnitAtIndex(0);
#endif
  if (!CU) {
    errs() << "Debug Error: dwarf context failed to get compile unit\n";
    return;
  }

  const DWARFLineTable *LineTable = DwarfCtx->getLineTableForUnit(CU);
  if (!LineTable) {
    errs() << "Debug Error: dwarf context failed to get line table\n";
    return;
  }

  // Build LineCache for later source code printing
  vector<string> LineCache = buildLineCache();

  // Start to disassemble with source code annotation section by section
  for (auto section : sections_)
    if (!strncmp(fn_prefix_.c_str(), section.first.c_str(),
                 fn_prefix_.size())) {
      MCDisassembler::DecodeStatus S;
      MCInst Inst;
      uint64_t Size;
      uint8_t *FuncStart = get<0>(section.second);
      uint64_t FuncSize = get<1>(section.second);
      ArrayRef<uint8_t> Data(FuncStart, FuncSize);
      uint32_t CurrentSrcLine = 0;
      string func_name = section.first.substr(fn_prefix_.size());

      errs() << "Disassembly of section " << section.first << ":\n"
             << func_name << ":\n";

      string src_dbg_str;
      llvm::raw_string_ostream os(src_dbg_str);
      for (uint64_t Index = 0; Index < FuncSize; Index += Size) {
        S = DisAsm->getInstruction(Inst, Size, Data.slice(Index), Index,
                                   nulls(), nulls());
        if (S != MCDisassembler::Success) {
          os << "Debug Error: disassembler failed: " << std::to_string(S)
             << '\n';
          break;
        } else {
          DILineInfo LineInfo;
          LineTable->getFileLineInfoForAddress(
              (uint64_t)FuncStart + Index, CU->getCompilationDir(),
              DILineInfoSpecifier::FileLineInfoKind::AbsoluteFilePath,
              LineInfo);

          adjustInstSize(Size, Data[Index], Data[Index + 1]);
          dumpSrcLine(LineCache, LineInfo.FileName, LineInfo.Line,
                      CurrentSrcLine, os);
          os << format("%4" PRIu64 ":", Index >> 3) << '\t';
          dumpBytes(Data.slice(Index, Size), os);
          IP->printInst(&Inst, os, "", *STI);
          os << '\n';
        }
      }
      os.flush();
      errs() << src_dbg_str << '\n';
      src_dbg_fmap_[func_name] = src_dbg_str;
    }
}

}  // namespace ebpf
