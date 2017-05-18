# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from p4_hlir.hlir import p4_counter, P4_DIRECT, P4_COUNTER_BYTES
from programSerializer import ProgramSerializer
from compilationException import *
import ebpfTable
import ebpfProgram


class EbpfCounter(object):
    # noinspection PyUnresolvedReferences
    def __init__(self, hlircounter, program):
        assert isinstance(hlircounter, p4_counter)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        self.name = hlircounter.name
        self.hlircounter = hlircounter

        width = hlircounter.min_width
        # ebpf counters only work on 64-bits
        if width <= 64:
            self.valueTypeName = program.config.uprefix + "64"
        else:
            raise NotSupportedException(
                "{0}: Counters with {1} bits", hlircounter, width)

        self.dataMapName = self.name

        if ((hlircounter.binding is None) or
            (hlircounter.binding[0] != P4_DIRECT)):
            raise NotSupportedException(
                "{0}: counter which is not direct", hlircounter)

        self.autoIncrement = (hlircounter.binding != None and
                              hlircounter.binding[0] == P4_DIRECT)

        if hlircounter.type is P4_COUNTER_BYTES:
            self.increment = "{0}->len".format(program.packetName)
        else:
            self.increment = "1"

    def getSize(self, program):
        if self.hlircounter.instance_count is not None:
            return self.hlircounter.instance_count
        if self.autoIncrement:
            return self.getTable(program).size
        program.emitWarning(
            "{0} does not specify a max_size; using 1024", self.hlircounter)
        return 1024

    def getTable(self, program):
        table = program.getTable(self.hlircounter.binding[1].name)
        assert isinstance(table, ebpfTable.EbpfTable)
        return table

    def serialize(self, serializer, program):
        assert isinstance(serializer, ProgramSerializer)

        # Direct counters have the same key as the associated table
        # Static counters have integer keys
        if self.autoIncrement:
            keyTypeName = "struct " + self.getTable(program).keyTypeName
        else:
            keyTypeName = program.config.uprefix + "32"
        program.config.serializeTableDeclaration(
            serializer, self.dataMapName, True, keyTypeName,
            self.valueTypeName, self.getSize(program))

    def serializeCode(self, keyname, serializer, program):
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        serializer.emitIndent()
        serializer.appendFormat("/* Update counter {0} */", self.name)
        serializer.newline()

        valueName = "ctrvalue"
        initValuename = "init_val"

        serializer.emitIndent()
        serializer.appendFormat("{0} *{1};", self.valueTypeName, valueName)
        serializer.newline()
        serializer.emitIndent()
        serializer.appendFormat("{0} {1};", self.valueTypeName, initValuename)
        serializer.newline()

        serializer.emitIndent()
        serializer.appendLine("/* perform lookup */")
        serializer.emitIndent()
        program.config.serializeLookup(
            serializer, self.dataMapName, keyname, valueName)
        serializer.newline()

        serializer.emitIndent()
        serializer.appendFormat("if ({0} != NULL) ", valueName)
        serializer.newline()
        serializer.increaseIndent()
        serializer.emitIndent()
        serializer.appendFormat("__sync_fetch_and_add({0}, {1});",
                                valueName, self.increment)
        serializer.newline()
        serializer.decreaseIndent()
        serializer.emitIndent()

        serializer.append("else ")
        serializer.blockStart()
        serializer.emitIndent()
        serializer.appendFormat("{0} = {1};", initValuename, self.increment)
        serializer.newline()

        serializer.emitIndent()
        program.config.serializeUpdate(
            serializer, self.dataMapName, keyname, initValuename)
        serializer.newline()
        serializer.blockEnd(True)
