# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from p4_hlir.hlir import p4_conditional_node, p4_expression
from p4_hlir.hlir import p4_header_instance, p4_field
from programSerializer import ProgramSerializer
from compilationException import CompilationException
import ebpfProgram
import ebpfInstance


class EbpfConditional(object):
    @staticmethod
    def translate(op):
        if op == "not":
            return "!"
        elif op == "or":
            return "||"
        elif op == "and":
            return "&&"
        return op

    def __init__(self, p4conditional, program):
        assert isinstance(p4conditional, p4_conditional_node)
        assert isinstance(program, ebpfProgram.EbpfProgram)
        self.hlirconditional = p4conditional
        self.name = p4conditional.name

    def emitNode(self, node, serializer, program):
        if isinstance(node, p4_expression):
            self.emitExpression(node, serializer, program, False)
        elif node is None:
            pass
        elif isinstance(node, int):
            serializer.append(node)
        elif isinstance(node, p4_header_instance):
            header = program.getInstance(node.name)
            assert isinstance(header, ebpfInstance.EbpfHeader)
            # TODO: stacks?
            serializer.appendFormat(
                "{0}.{1}", program.headerStructName, header.name)
        elif isinstance(node, p4_field):
            instance = node.instance
            einstance = program.getInstance(instance.name)
            if isinstance(einstance, ebpfInstance.EbpfHeader):
                base = program.headerStructName
            else:
                base = program.metadataStructName
            serializer.appendFormat(
                "{0}.{1}.{2}", base, einstance.name, node.name)
        else:
            raise CompilationException(True, "{0} Unexpected expression ", node)

    def emitExpression(self, expression, serializer, program, toplevel):
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)
        assert isinstance(expression, p4_expression)
        assert isinstance(toplevel, bool)
        left = expression.left
        op = expression.op
        right = expression.right

        assert isinstance(op, str)

        if op == "valid":
            self.emitNode(right, serializer, program)
            serializer.append(".valid")
            return

        if not toplevel:
            serializer.append("(")
        self.emitNode(left, serializer, program)
        op = EbpfConditional.translate(op)
        serializer.append(op)
        self.emitNode(right, serializer, program)
        if not toplevel:
            serializer.append(")")

    def generateCode(self, serializer, program, nextNode):
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)
        serializer.emitIndent()
        serializer.blockStart()

        trueBranch = self.hlirconditional.next_[True]
        if trueBranch is None:
            trueBranch = nextNode
        falseBranch = self.hlirconditional.next_[False]
        if falseBranch is None:
            falseBranch = nextNode

        serializer.emitIndent()
        serializer.appendFormat("{0}:", program.getLabel(self.hlirconditional))
        serializer.newline()

        serializer.emitIndent()
        serializer.append("if (")
        self.emitExpression(
            self.hlirconditional.condition, serializer, program, True)
        serializer.appendLine(")")

        serializer.increaseIndent()
        label = program.getLabel(trueBranch)
        serializer.emitIndent()
        serializer.appendFormat("goto {0};", label)
        serializer.newline()
        serializer.decreaseIndent()

        serializer.emitIndent()
        serializer.appendLine("else")
        serializer.increaseIndent()
        label = program.getLabel(falseBranch)
        serializer.emitIndent()
        serializer.appendFormat("goto {0};", label)
        serializer.newline()
        serializer.decreaseIndent()

        serializer.blockEnd(True)
