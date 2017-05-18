# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from p4_hlir.hlir import p4_header_instance, p4_table, \
     p4_conditional_node, p4_action, p4_parse_state
from p4_hlir.main import HLIR
import typeFactory
import ebpfTable
import ebpfParser
import ebpfAction
import ebpfInstance
import ebpfConditional
import ebpfCounter
import ebpfDeparser
import programSerializer
import target
from compilationException import *


class EbpfProgram(object):
    def __init__(self, name, hlir, isRouter, config):
        """Representation of an EbpfProgram (in fact,
        a C program that is converted to EBPF)"""
        assert isinstance(hlir, HLIR)
        assert isinstance(isRouter, bool)
        assert isinstance(config, target.TargetConfig)

        self.hlir = hlir
        self.name = name
        self.uniqueNameCounter = 0
        self.config = config
        self.isRouter = isRouter
        self.reservedPrefix = "ebpf_"

        assert isinstance(config, target.TargetConfig)

        self.packetName = self.reservedPrefix + "packet"
        self.dropBit = self.reservedPrefix + "drop"
        self.license = "GPL"
        self.offsetVariableName = self.reservedPrefix + "packetOffsetInBits"
        self.zeroKeyName = self.reservedPrefix + "zero"
        self.arrayIndexType = self.config.uprefix + "32"
        # all array tables must be indexed with u32 values

        self.errorName = self.reservedPrefix + "error"
        self.functionName = self.reservedPrefix + "filter"
        self.egressPortName = "egress_port" # Hardwired in P4 definition

        self.typeFactory = typeFactory.EbpfTypeFactory(config)
        self.errorCodes = [
            "p4_pe_no_error",
            "p4_pe_index_out_of_bounds",
            "p4_pe_out_of_packet",
            "p4_pe_header_too_long",
            "p4_pe_header_too_short",
            "p4_pe_unhandled_select",
            "p4_pe_checksum"]

        self.actions = []
        self.conditionals = []
        self.tables = []
        self.headers = []   # header instances
        self.metadata = []  # metadata instances
        self.stacks = []    # header stack instances EbpfHeaderStack
        self.parsers = []   # all parsers
        self.deparser = None
        self.entryPoints = []  # control-flow entry points from parser
        self.counters = []
        self.entryPointLabels = {}  # maps p4_node from entryPoints
                                    # to labels in the C program
        self.egressEntry = None

        self.construct()

        self.headersStructTypeName = self.reservedPrefix + "headers_t"
        self.headerStructName = self.reservedPrefix + "headers"
        self.metadataStructTypeName = self.reservedPrefix + "metadata_t"
        self.metadataStructName = self.reservedPrefix + "metadata"

    def construct(self):
        if len(self.hlir.p4_field_list_calculations) > 0:
            raise NotSupportedException(
                "{0} calculated field",
                self.hlir.p4_field_list_calculations.values()[0].name)

        for h in self.hlir.p4_header_instances.values():
            if h.max_index is not None:
                assert isinstance(h, p4_header_instance)
                if h.index == 0:
                    # header stack; allocate only for zero-th index
                    indexVarName = self.generateNewName(h.base_name + "_index")
                    stack = ebpfInstance.EbpfHeaderStack(
                        h, indexVarName, self.typeFactory)
                    self.stacks.append(stack)
            elif h.metadata:
                metadata = ebpfInstance.EbpfMetadata(h, self.typeFactory)
                self.metadata.append(metadata)
            else:
                header = ebpfInstance.EbpfHeader(h, self.typeFactory)
                self.headers.append(header)

        for p in self.hlir.p4_parse_states.values():
            parser = ebpfParser.EbpfParser(p)
            self.parsers.append(parser)

        for a in self.hlir.p4_actions.values():
            if self.isInternalAction(a):
                continue
            action = ebpfAction.EbpfAction(a, self)
            self.actions.append(action)

        for c in self.hlir.p4_counters.values():
            counter = ebpfCounter.EbpfCounter(c, self)
            self.counters.append(counter)

        for t in self.hlir.p4_tables.values():
            table = ebpfTable.EbpfTable(t, self, self.config)
            self.tables.append(table)

        for n in self.hlir.p4_ingress_ptr.keys():
            self.entryPoints.append(n)

        for n in self.hlir.p4_conditional_nodes.values():
            conditional = ebpfConditional.EbpfConditional(n, self)
            self.conditionals.append(conditional)

        self.egressEntry = self.hlir.p4_egress_ptr
        self.deparser = ebpfDeparser.EbpfDeparser(self.hlir)

    def isInternalAction(self, action):
        # This is a heuristic really to guess which actions are built-in
        # Unfortunately there seems to be no other way to do this
        return action.lineno < 0

    @staticmethod
    def isArrayElementInstance(headerInstance):
        assert isinstance(headerInstance, p4_header_instance)
        return headerInstance.max_index is not None

    def emitWarning(self, formatString, *message):
        assert isinstance(formatString, str)
        print("WARNING: ", formatString.format(*message))

    def toC(self, serializer):
        assert isinstance(serializer, programSerializer.ProgramSerializer)

        self.generateIncludes(serializer)
        self.generatePreamble(serializer)
        self.generateTypes(serializer)
        self.generateTables(serializer)

        serializer.newline()
        serializer.emitIndent()
        self.config.serializeCodeSection(serializer)
        serializer.newline()
        serializer.emitIndent()
        serializer.appendFormat("int {0}(struct __sk_buff* {1}) ",
                                self.functionName, self.packetName)
        serializer.blockStart()

        self.generateHeaderInstance(serializer)
        serializer.append(" = ")
        self.generateInitializeHeaders(serializer)
        serializer.endOfStatement(True)

        self.generateMetadataInstance(serializer)
        serializer.append(" = ")
        self.generateInitializeMetadata(serializer)
        serializer.endOfStatement(True)

        self.createLocalVariables(serializer)
        serializer.newline()

        serializer.emitIndent()
        serializer.appendLine("goto start;")

        self.generateParser(serializer)
        self.generatePipeline(serializer)

        self.generateDeparser(serializer)

        serializer.emitIndent()
        serializer.appendLine("end:")
        serializer.emitIndent()

        if isinstance(self.config, target.KernelSamplesConfig):
            serializer.appendFormat("return {0};", self.dropBit)
            serializer.newline()
        elif isinstance(self.config, target.BccConfig):
            if self.isRouter:
                serializer.appendFormat("if (!{0})", self.dropBit)
                serializer.newline()
                serializer.increaseIndent()
                serializer.emitIndent()
                serializer.appendFormat(
                    "bpf_clone_redirect({0}, {1}.standard_metadata.{2}, 0);",
                    self.packetName, self.metadataStructName,
                    self.egressPortName)
                serializer.newline()
                serializer.decreaseIndent()

                serializer.emitIndent()
                serializer.appendLine(
                    "return TC_ACT_SHOT /* drop packet; clone is forwarded */;")
            else:
                serializer.appendFormat(
                    "return {1} ? TC_ACT_SHOT : TC_ACT_PIPE;",
                    self.dropBit)
                serializer.newline()
        else:
            raise CompilationException(
                True, "Unexpected target configuration {0}",
                self.config.targetName)
        serializer.blockEnd(True)

        self.generateLicense(serializer)

        serializer.append(self.config.postamble)

    def generateLicense(self, serializer):
        self.config.serializeLicense(serializer, self.license)

    # noinspection PyMethodMayBeStatic
    def generateIncludes(self, serializer):
        assert isinstance(serializer, programSerializer.ProgramSerializer)
        serializer.append(self.config.getIncludes())

    def getLabel(self, p4node):
        # C label that corresponds to this point in the control-flow
        if p4node is None:
            return "end"
        elif isinstance(p4node, p4_parse_state):
            label = p4node.name
            self.entryPointLabels[p4node.name] = label
        if p4node.name not in self.entryPointLabels:
            label = self.generateNewName(p4node.name)
            self.entryPointLabels[p4node.name] = label
        return self.entryPointLabels[p4node.name]

    # noinspection PyMethodMayBeStatic
    def generatePreamble(self, serializer):
        assert isinstance(serializer, programSerializer.ProgramSerializer)

        serializer.emitIndent()
        serializer.append("enum ErrorCode ")
        serializer.blockStart()
        for error in self.errorCodes:
            serializer.emitIndent()
            serializer.appendFormat("{0},", error)
            serializer.newline()
        serializer.blockEnd(False)
        serializer.endOfStatement(True)
        serializer.newline()

        serializer.appendLine(
            "#define EBPF_MASK(t, w) ((((t)(1)) << (w)) - (t)1)")
        serializer.appendLine("#define BYTES(w) ((w + 7) / 8)")

        self.config.generateDword(serializer)

    # noinspection PyMethodMayBeStatic
    def generateNewName(self, base):  # base is a string
        """Generates a fresh name based on the specified base name"""
        # TODO: this should be made "safer"
        assert isinstance(base, str)

        base += "_" + str(self.uniqueNameCounter)
        self.uniqueNameCounter += 1
        return base

    def generateTypes(self, serializer):
        assert isinstance(serializer, programSerializer.ProgramSerializer)

        for t in self.typeFactory.type_map.values():
            t.serialize(serializer)

        # generate a new struct type for the packet itself
        serializer.appendFormat("struct {0} ", self.headersStructTypeName)
        serializer.blockStart()
        for h in self.headers:
            serializer.emitIndent()
            h.declare(serializer)
            serializer.endOfStatement(True)

        for h in self.stacks:
            assert isinstance(h, ebpfInstance.EbpfHeaderStack)

            serializer.emitIndent()
            h.declare(serializer)
            serializer.endOfStatement(True)

        serializer.blockEnd(False)
        serializer.endOfStatement(True)

        # generate a new struct type for the metadata
        serializer.appendFormat("struct {0} ", self.metadataStructTypeName)
        serializer.blockStart()
        for h in self.metadata:
            assert isinstance(h, ebpfInstance.EbpfMetadata)

            serializer.emitIndent()
            h.declare(serializer)
            serializer.endOfStatement(True)
        serializer.blockEnd(False)
        serializer.endOfStatement(True)

    def generateTables(self, serializer):
        assert isinstance(serializer, programSerializer.ProgramSerializer)

        for t in self.tables:
            t.serialize(serializer, self)

        for c in self.counters:
            c.serialize(serializer, self)

    def generateHeaderInstance(self, serializer):
        assert isinstance(serializer, programSerializer.ProgramSerializer)

        serializer.emitIndent()
        serializer.appendFormat(
            "struct {0} {1}", self.headersStructTypeName, self.headerStructName)

    def generateInitializeHeaders(self, serializer):
        assert isinstance(serializer, programSerializer.ProgramSerializer)

        serializer.blockStart()
        for h in self.headers:
            serializer.emitIndent()
            serializer.appendFormat(".{0} = ", h.name)
            h.type.emitInitializer(serializer)
            serializer.appendLine(",")
        serializer.blockEnd(False)

    def generateMetadataInstance(self, serializer):
        assert isinstance(serializer, programSerializer.ProgramSerializer)

        serializer.emitIndent()
        serializer.appendFormat(
            "struct {0} {1}",
            self.metadataStructTypeName,
            self.metadataStructName)

    def generateDeparser(self, serializer):
        self.deparser.serialize(serializer, self)

    def generateInitializeMetadata(self, serializer):
        assert isinstance(serializer, programSerializer.ProgramSerializer)

        serializer.blockStart()
        for h in self.metadata:
            serializer.emitIndent()
            serializer.appendFormat(".{0} = ", h.name)
            h.emitInitializer(serializer)
            serializer.appendLine(",")
        serializer.blockEnd(False)

    def createLocalVariables(self, serializer):
        assert isinstance(serializer, programSerializer.ProgramSerializer)

        serializer.emitIndent()
        serializer.appendFormat("unsigned {0} = 0;", self.offsetVariableName)
        serializer.newline()

        serializer.emitIndent()
        serializer.appendFormat(
            "enum ErrorCode {0} = p4_pe_no_error;", self.errorName)
        serializer.newline()

        serializer.emitIndent()
        serializer.appendFormat(
            "{0}8 {1} = 0;", self.config.uprefix, self.dropBit)
        serializer.newline()

        serializer.emitIndent()
        serializer.appendFormat(
            "{0} {1} = 0;", self.arrayIndexType, self.zeroKeyName)
        serializer.newline()

        for h in self.stacks:
            serializer.emitIndent()
            serializer.appendFormat(
                "{0}8 {0} = 0;", self.config.uprefix, h.indexVar)
            serializer.newline()

    def getStackInstance(self, name):
        assert isinstance(name, str)

        for h in self.stacks:
            if h.name == name:
                assert isinstance(h, ebpfInstance.EbpfHeaderStack)
                return h
        raise CompilationException(
            True, "Could not locate header stack named {0}", name)

    def getHeaderInstance(self, name):
        assert isinstance(name, str)

        for h in self.headers:
            if h.name == name:
                assert isinstance(h, ebpfInstance.EbpfHeader)
                return h
        raise CompilationException(
            True, "Could not locate header instance named {0}", name)

    def getInstance(self, name):
        assert isinstance(name, str)

        for h in self.headers:
            if h.name == name:
                return h
        for h in self.metadata:
            if h.name == name:
                return h
        raise CompilationException(
            True, "Could not locate instance named {0}", name)

    def getAction(self, p4action):
        assert isinstance(p4action, p4_action)
        for a in self.actions:
            if a.name == p4action.name:
                return a

        newAction = ebpfAction.BuiltinAction(p4action)
        self.actions.append(newAction)
        return newAction

    def getTable(self, name):
        assert isinstance(name, str)
        for t in self.tables:
            if t.name == name:
                return t
        raise CompilationException(
            True, "Could not locate table named {0}", name)

    def getCounter(self, name):
        assert isinstance(name, str)
        for t in self.counters:
            if t.name == name:
                return t
        raise CompilationException(
            True, "Could not locate counters named {0}", name)

    def getConditional(self, name):
        assert isinstance(name, str)
        for c in self.conditionals:
            if c.name == name:
                return c
        raise CompilationException(
            True, "Could not locate conditional named {0}", name)

    def generateParser(self, serializer):
        assert isinstance(serializer, programSerializer.ProgramSerializer)
        for p in self.parsers:
            p.serialize(serializer, self)

    def generateIngressPipeline(self, serializer):
        assert isinstance(serializer, programSerializer.ProgramSerializer)
        for t in self.tables:
            assert isinstance(t, ebpfTable.EbpfTable)
            serializer.emitIndent()
            serializer.appendFormat("{0}:", t.name)
            serializer.newline()

    def generateControlFlowNode(self, serializer, node, nextEntryPoint):
        # nextEntryPoint is used as a target whenever the target is None
        # nextEntryPoint may also be None
        if isinstance(node, p4_table):
            table = self.getTable(node.name)
            assert isinstance(table, ebpfTable.EbpfTable)
            table.serializeCode(serializer, self, nextEntryPoint)
        elif isinstance(node, p4_conditional_node):
            conditional = self.getConditional(node.name)
            assert isinstance(conditional, ebpfConditional.EbpfConditional)
            conditional.generateCode(serializer, self, nextEntryPoint)
        else:
            raise CompilationException(
                True, "{0} Unexpected control flow node ", node)

    def generatePipelineInternal(self, serializer, nodestoadd, nextEntryPoint):
        assert isinstance(serializer, programSerializer.ProgramSerializer)
        assert isinstance(nodestoadd, set)

        done = set()
        while len(nodestoadd) > 0:
            todo = nodestoadd.pop()
            if todo in done:
                continue
            if todo is None:
                continue

            print("Generating ", todo.name)

            done.add(todo)
            self.generateControlFlowNode(serializer, todo, nextEntryPoint)

            for n in todo.next_.values():
                nodestoadd.add(n)

    def generatePipeline(self, serializer):
        todo = set()
        for e in self.entryPoints:
            todo.add(e)
        self.generatePipelineInternal(serializer, todo, self.egressEntry)
        todo = set()
        todo.add(self.egressEntry)
        self.generatePipelineInternal(serializer, todo, None)
