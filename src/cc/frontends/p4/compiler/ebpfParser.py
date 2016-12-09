# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from p4_hlir.hlir import parse_call, p4_field, p4_parse_value_set, \
    P4_DEFAULT, p4_parse_state, p4_table, \
    p4_conditional_node, p4_parser_exception, \
    p4_header_instance, P4_NEXT
import ebpfProgram
import ebpfStructType
import ebpfInstance
import programSerializer
from compilationException import *


class EbpfParser(object):
    def __init__(self, hlirParser):  # hlirParser is a P4 parser
        self.parser = hlirParser
        self.name = hlirParser.name

    def serialize(self, serializer, program):
        assert isinstance(serializer, programSerializer.ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        serializer.emitIndent()
        serializer.appendFormat("{0}: ", self.name)
        serializer.blockStart()
        for op in self.parser.call_sequence:
            self.serializeOperation(serializer, op, program)

        self.serializeBranch(serializer, self.parser.branch_on,
                             self.parser.branch_to, program)

        serializer.blockEnd(True)

    def serializeSelect(self, selectVarName, serializer, branch_on, program):
        # selectVarName - name of temp variable to use for the select expression
        assert isinstance(selectVarName, str)
        assert isinstance(serializer, programSerializer.ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        totalWidth = 0
        switchValue = ""
        for e in branch_on:
            if isinstance(e, p4_field):
                instance = e.instance
                assert isinstance(instance, p4_header_instance)
                index = ""

                if ebpfProgram.EbpfProgram.isArrayElementInstance(instance):
                    ebpfStack = program.getStackInstance(instance.base_name)
                    assert isinstance(ebpfStack, ebpfInstance.EbpfHeaderStack)

                    if isinstance(instance.index, int):
                        index = "[" + str(instance.index) + "]"
                    elif instance.index is P4_NEXT:
                        index = "[" + ebpfStack.indexVar + "]"
                    else:
                        raise CompilationException(True,
                            "Unexpected index for array {0}", instance.index)
                    basetype = ebpfStack.basetype
                    name = ebpfStack.name
                else:
                    ebpfHeader = program.getInstance(instance.name)
                    assert isinstance(ebpfHeader, ebpfInstance.EbpfHeader)
                    basetype = ebpfHeader.type
                    name = ebpfHeader.name

                ebpfField = basetype.getField(e.name)
                assert isinstance(ebpfField, ebpfStructType.EbpfField)

                totalWidth += ebpfField.widthInBits()
                fieldReference = (program.headerStructName + "." + name +
                                  index + "." + ebpfField.name)

                if switchValue == "":
                    switchValue = fieldReference
                else:
                    switchValue = ("(" + switchValue + " << " +
                                   str(ebpfField.widthInBits()) + ")")
                    switchValue = switchValue + " | " + fieldReference
            elif isinstance(e, tuple):
                switchValue = self.currentReferenceAsString(e, program)
            else:
                raise CompilationException(
                    True, "Unexpected element in match {0}", e)

        if totalWidth > 32:
            raise NotSupportedException("{0}: Matching on {1}-bit value",
                                        branch_on, totalWidth)
        serializer.emitIndent()
        serializer.appendFormat("{0}32 {1} = {2};",
                                program.config.uprefix,
                                selectVarName, switchValue)
        serializer.newline()

    def generatePacketLoad(self, startBit, width, alignment, program):
        # Generates an expression that does a load_*, shift and mask
        # to load 'width' bits starting at startBit from the current
        # packet offset.
        # alignment is an integer <= 8 that holds the current alignment
        # of of the packet offset.
        assert width > 0
        assert alignment < 8
        assert isinstance(startBit, int)
        assert isinstance(width, int)
        assert isinstance(alignment, int)

        firstBitIndex = startBit + alignment
        lastBitIndex = startBit + width + alignment - 1
        firstWordIndex = firstBitIndex / 8
        lastWordIndex = lastBitIndex / 8

        wordsToRead = lastWordIndex - firstWordIndex + 1
        if wordsToRead == 1:
            load = "load_byte"
            loadSize = 8
        elif wordsToRead == 2:
            load = "load_half"
            loadSize = 16
        elif wordsToRead <= 4:
            load = "load_word"
            loadSize = 32
        elif wordsToRead <= 8:
            load = "load_dword"
            loadSize = 64
        else:
            raise CompilationException(True, "Attempt to load more than 1 word")

        readtype = program.config.uprefix + str(loadSize)
        loadInstruction = "{0}({1}, ({2} + {3}) / 8)".format(
            load, program.packetName, program.offsetVariableName, startBit)
        shift = loadSize - alignment - width
        load = "(({0}) >> ({1}))".format(loadInstruction, shift)
        if width != loadSize:
            mask = " & EBPF_MASK({0}, {1})".format(readtype, width)
        else:
            mask = ""
        return load + mask

    def currentReferenceAsString(self, tpl, program):
        # a string describing an expression of the form current(position, width)
        # The assumption is that at this point the packet cursor is ALWAYS
        # byte aligned.  This should be true because headers are supposed
        # to have sizes an integral number of bytes.
        assert isinstance(tpl, tuple)
        if len(tpl) != 2:
            raise CompilationException(
                True, "{0} Expected a tuple with 2 elements", tpl)

        minIndex = tpl[0]
        totalWidth = tpl[1]
        result = self.generatePacketLoad(
            minIndex, totalWidth, 0, program) # alignment is 0
        return result

    def serializeCases(self, selectVarName, serializer, branch_to, program):
        assert isinstance(selectVarName, str)
        assert isinstance(serializer, programSerializer.ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        branches = 0
        seenDefault = False
        for e in branch_to.keys():
            serializer.emitIndent()
            value = branch_to[e]

            if isinstance(e, int):
                serializer.appendFormat("if ({0} == {1})", selectVarName, e)
            elif isinstance(e, tuple):
                serializer.appendFormat(
                    "if (({0} & {1}) == {2})", selectVarName, e[0], e[1])
            elif isinstance(e, p4_parse_value_set):
                raise NotSupportedException("{0}: Parser value sets", e)
            elif e is P4_DEFAULT:
                seenDefault = True
                if branches > 0:
                    serializer.append("else")
            else:
                raise CompilationException(
                    True, "Unexpected element in match case {0}", e)

            branches += 1
            serializer.newline()
            serializer.increaseIndent()
            serializer.emitIndent()

            label = program.getLabel(value)

            if isinstance(value, p4_parse_state):
                serializer.appendFormat("goto {0};", label)
            elif isinstance(value, p4_table):
                serializer.appendFormat("goto {0};", label)
            elif isinstance(value, p4_conditional_node):
                serializer.appendFormat("goto {0};", label)
            elif isinstance(value, p4_parser_exception):
                raise CompilationException(True, "Not yet implemented")
            else:
                raise CompilationException(
                    True, "Unexpected element in match case {0}", value)

            serializer.decreaseIndent()
            serializer.newline()

        # Must create default if it is missing
        if not seenDefault:
            serializer.emitIndent()
            serializer.appendFormat(
                "{0} = p4_pe_unhandled_select;", program.errorName)
            serializer.newline()
            serializer.emitIndent()
            serializer.appendFormat("default: goto end;")
            serializer.newline()

    def serializeBranch(self, serializer, branch_on, branch_to, program):
        assert isinstance(serializer, programSerializer.ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        if branch_on == []:
            dest = branch_to.values()[0]
            serializer.emitIndent()
            name = program.getLabel(dest)
            serializer.appendFormat("goto {0};", name)
            serializer.newline()
        elif isinstance(branch_on, list):
            tmpvar = program.generateNewName("tmp")
            self.serializeSelect(tmpvar, serializer, branch_on, program)
            self.serializeCases(tmpvar, serializer, branch_to, program)
        else:
            raise CompilationException(
                True, "Unexpected branch_on {0}", branch_on)

    def serializeOperation(self, serializer, op, program):
        assert isinstance(serializer, programSerializer.ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        operation = op[0]
        if operation is parse_call.extract:
            self.serializeExtract(serializer, op[1], program)
        elif operation is parse_call.set:
            self.serializeMetadataSet(serializer, op[1], op[2], program)
        else:
            raise CompilationException(
                True, "Unexpected operation in parser {0}", op)

    def serializeFieldExtract(self, serializer, headerInstanceName,
                              index, field, alignment, program):
        assert isinstance(index, str)
        assert isinstance(headerInstanceName, str)
        assert isinstance(field, ebpfStructType.EbpfField)
        assert isinstance(serializer, programSerializer.ProgramSerializer)
        assert isinstance(alignment, int)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        fieldToExtractTo = headerInstanceName + index + "." + field.name

        serializer.emitIndent()
        width = field.widthInBits()
        if field.name == "valid":
            serializer.appendFormat(
                "{0}.{1} = 1;", program.headerStructName, fieldToExtractTo)
            serializer.newline()
            return

        serializer.appendFormat("if ({0}->len < BYTES({1} + {2})) ",
                                program.packetName,
                                program.offsetVariableName, width)
        serializer.blockStart()
        serializer.emitIndent()
        serializer.appendFormat("{0} = p4_pe_header_too_short;",
                                program.errorName)
        serializer.newline()
        serializer.emitIndent()
        serializer.appendLine("goto end;")
        # TODO: jump to correct exception handler
        serializer.blockEnd(True)

        if width <= 32:
            serializer.emitIndent()
            load = self.generatePacketLoad(0, width, alignment, program)

            serializer.appendFormat("{0}.{1} = {2};",
                                    program.headerStructName,
                                    fieldToExtractTo, load)
            serializer.newline()
        else:
            # Destination is bigger than 4 bytes and
            # represented as a byte array.
            if alignment == 0:
                shift = 0
            else:
                shift = 8 - alignment

            assert shift >= 0
            if shift == 0:
                method = "load_byte"
            else:
                method = "load_half"
            b = (width + 7) / 8
            for i in range(0, b):
                serializer.emitIndent()
                serializer.appendFormat("{0}.{1}[{2}] = ({3}8)",
                                        program.headerStructName,
                                        fieldToExtractTo, i,
                                        program.config.uprefix)
                serializer.appendFormat("(({0}({1}, ({2} / 8) + {3}) >> {4})",
                                        method, program.packetName,
                                        program.offsetVariableName, i, shift)
                if (i == b - 1) and (width % 8 != 0):
                    serializer.appendFormat(" & EBPF_MASK({0}8, {1})",
                                            program.config.uprefix, width % 8)
                serializer.append(")")
                serializer.endOfStatement(True)

        serializer.emitIndent()
        serializer.appendFormat("{0} += {1};",
                                program.offsetVariableName, width)
        serializer.newline()

    def serializeExtract(self, serializer, headerInstance, program):
        assert isinstance(serializer, programSerializer.ProgramSerializer)
        assert isinstance(headerInstance, p4_header_instance)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        if ebpfProgram.EbpfProgram.isArrayElementInstance(headerInstance):
            ebpfStack = program.getStackInstance(headerInstance.base_name)
            assert isinstance(ebpfStack, ebpfInstance.EbpfHeaderStack)

            # write bounds check
            serializer.emitIndent()
            serializer.appendFormat("if ({0} >= {1}) ",
                                    ebpfStack.indexVar, ebpfStack.arraySize)
            serializer.blockStart()
            serializer.emitIndent()
            serializer.appendFormat("{0} = p4_pe_index_out_of_bounds;",
                                    program.errorName)
            serializer.newline()
            serializer.emitIndent()
            serializer.appendLine("goto end;")
            serializer.blockEnd(True)

            if isinstance(headerInstance.index, int):
                index = "[" + str(headerInstance.index) + "]"
            elif headerInstance.index is P4_NEXT:
                index = "[" + ebpfStack.indexVar + "]"
            else:
                raise CompilationException(
                    True, "Unexpected index for array {0}",
                    headerInstance.index)
            basetype = ebpfStack.basetype
        else:
            ebpfHeader = program.getHeaderInstance(headerInstance.name)
            basetype = ebpfHeader.type
            index = ""

        # extract all fields
        alignment = 0
        for field in basetype.fields:
            assert isinstance(field, ebpfStructType.EbpfField)

            self.serializeFieldExtract(serializer, headerInstance.base_name,
                                       index, field, alignment, program)
            alignment += field.widthInBits()
            alignment = alignment % 8

        if ebpfProgram.EbpfProgram.isArrayElementInstance(headerInstance):
            # increment stack index
            ebpfStack = program.getStackInstance(headerInstance.base_name)
            assert isinstance(ebpfStack, ebpfInstance.EbpfHeaderStack)

            # write bounds check
            serializer.emitIndent()
            serializer.appendFormat("{0}++;", ebpfStack.indexVar)
            serializer.newline()

    def serializeMetadataSet(self, serializer, field, value, program):
        assert isinstance(serializer, programSerializer.ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)
        assert isinstance(field, p4_field)

        dest = program.getInstance(field.instance.name)
        assert isinstance(dest, ebpfInstance.SimpleInstance)
        destType = dest.type
        assert isinstance(destType, ebpfStructType.EbpfStructType)
        destField = destType.getField(field.name)

        if destField.widthInBits() > 32:
            useMemcpy = True
            bytesToCopy = destField.widthInBits() / 8
            if destField.widthInBits() % 8 != 0:
                raise CompilationException(
                    True,
                    "{0}: Not implemented: wide field w. sz not multiple of 8",
                    field)
        else:
            useMemcpy = False
            bytesToCopy = None # not needed, but compiler is confused

        serializer.emitIndent()
        destination = "{0}.{1}.{2}".format(
            program.metadataStructName, dest.name, destField.name)
        if isinstance(value, int):
            source = str(value)
            if useMemcpy:
                raise CompilationException(
                    True,
                    "{0}: Not implemented: copying from wide constant",
                    value)
        elif isinstance(value, tuple):
            source = self.currentReferenceAsString(value, program)
        elif isinstance(value, p4_field):
            source = program.getInstance(value.instance.name)
            if isinstance(source, ebpfInstance.EbpfMetadata):
                sourceStruct = program.metadataStructName
            else:
                sourceStruct = program.headerStructName
            source = "{0}.{1}.{2}".format(sourceStruct, source.name, value.name)
        else:
            raise CompilationException(
                True, "Unexpected type for parse_call.set {0}", value)

        if useMemcpy:
            serializer.appendFormat("memcpy(&{0}, &{1}, {2})",
                                    destination, source, bytesToCopy)
        else:
            serializer.appendFormat("{0} = {1}", destination, source)

        serializer.endOfStatement(True)
