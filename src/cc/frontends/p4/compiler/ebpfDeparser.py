# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from collections import defaultdict, OrderedDict
from p4_hlir.hlir import parse_call, p4_field, p4_parse_value_set, \
    P4_DEFAULT, p4_parse_state, p4_table, \
    p4_conditional_node, p4_parser_exception, \
    p4_header_instance, P4_NEXT

import ebpfProgram
import ebpfInstance
import ebpfType
import ebpfStructType
from topoSorting import Graph
from programSerializer import ProgramSerializer

def produce_parser_topo_sorting(hlir):
    # This function is copied from the P4 behavioral model implementation
    header_graph = Graph()

    def walk_rec(hlir, parse_state, prev_hdr_node, tag_stacks_index):
        assert(isinstance(parse_state, p4_parse_state))
        for call in parse_state.call_sequence:
            call_type = call[0]
            if call_type == parse_call.extract:
                hdr = call[1]

                if hdr.virtual:
                    base_name = hdr.base_name
                    current_index = tag_stacks_index[base_name]
                    if current_index > hdr.max_index:
                        return
                    tag_stacks_index[base_name] += 1
                    name = base_name + "[%d]" % current_index
                    hdr = hlir.p4_header_instances[name]

                if hdr not in header_graph:
                    header_graph.add_node(hdr)
                hdr_node = header_graph.get_node(hdr)

                if prev_hdr_node:
                    prev_hdr_node.add_edge_to(hdr_node)
                else:
                    header_graph.root = hdr
                prev_hdr_node = hdr_node

        for branch_case, next_state in parse_state.branch_to.items():
            if not next_state:
                continue
            if not isinstance(next_state, p4_parse_state):
                continue
            walk_rec(hlir, next_state, prev_hdr_node, tag_stacks_index.copy())

    start_state = hlir.p4_parse_states["start"]
    walk_rec(hlir, start_state, None, defaultdict(int))

    header_topo_sorting = header_graph.produce_topo_sorting()

    return header_topo_sorting

class EbpfDeparser(object):
    def __init__(self, hlir):
        header_topo_sorting = produce_parser_topo_sorting(hlir)
        self.headerOrder = [hdr.name for hdr in header_topo_sorting]

    def serialize(self, serializer, program):
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        serializer.emitIndent()
        serializer.blockStart()
        serializer.emitIndent()
        serializer.appendLine("/* Deparser */")
        serializer.emitIndent()
        serializer.appendFormat("{0} = 0;", program.offsetVariableName)
        serializer.newline()
        for h in self.headerOrder:
            header = program.getHeaderInstance(h)
            self.serializeHeaderEmit(header, serializer, program)
        serializer.blockEnd(True)

    def serializeHeaderEmit(self, header, serializer, program):
        assert isinstance(header, ebpfInstance.EbpfHeader)
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)
        p4header = header.hlirInstance
        assert isinstance(p4header, p4_header_instance)

        serializer.emitIndent()
        serializer.appendFormat("if ({0}.{1}.valid) ",
                                program.headerStructName, header.name)
        serializer.blockStart()

        if ebpfProgram.EbpfProgram.isArrayElementInstance(p4header):
            ebpfStack = program.getStackInstance(p4header.base_name)
            assert isinstance(ebpfStack, ebpfInstance.EbpfHeaderStack)

            if isinstance(p4header.index, int):
                index = "[" + str(headerInstance.index) + "]"
            elif p4header.index is P4_NEXT:
                index = "[" + ebpfStack.indexVar + "]"
            else:
                raise CompilationException(
                    True, "Unexpected index for array {0}",
                    p4header.index)
            basetype = ebpfStack.basetype
        else:
            ebpfHeader = program.getHeaderInstance(p4header.name)
            basetype = ebpfHeader.type
            index = ""

        alignment = 0
        for field in basetype.fields:
            assert isinstance(field, ebpfStructType.EbpfField)

            self.serializeFieldEmit(serializer, p4header.base_name,
                                    index, field, alignment, program)
            alignment += field.widthInBits()
            alignment = alignment % 8
        serializer.blockEnd(True)

    def serializeFieldEmit(self, serializer, name, index,
                           field, alignment, program):
        assert isinstance(index, str)
        assert isinstance(name, str)
        assert isinstance(field, ebpfStructType.EbpfField)
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(alignment, int)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        if field.name == "valid":
            return

        fieldToEmit = (program.headerStructName + "." + name +
                       index + "." + field.name)
        width = field.widthInBits()
        if width <= 32:
            store = self.generatePacketStore(fieldToEmit, 0, alignment,
                                             width, program)
            serializer.emitIndent()
            serializer.appendLine(store)
        else:
            # Destination is bigger than 4 bytes and
            # represented as a byte array.
            b = (width + 7) / 8
            for i in range(0, b):
                serializer.emitIndent()
                store = self.generatePacketStore(fieldToEmit + "["+str(i)+"]",
                                                 i,
                                                 alignment,
                                                 8, program)
                serializer.appendLine(store)

        serializer.emitIndent()
        serializer.appendFormat("{0} += {1};",
                                program.offsetVariableName, width)
        serializer.newline()

    def generatePacketStore(self, value, offset, alignment, width, program):
        assert width > 0
        assert alignment < 8
        assert isinstance(width, int)
        assert isinstance(alignment, int)

        return "bpf_dins_pkt({0}, {1} / 8 + {2}, {3}, {4}, {5});".format(
            program.packetName,
            program.offsetVariableName,
            offset,
            alignment,
            width,
            value
        )
