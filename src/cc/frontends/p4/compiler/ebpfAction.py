# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from p4_hlir.hlir import p4_action, p4_field
from p4_hlir.hlir import p4_signature_ref, p4_header_instance
import ebpfProgram
from programSerializer import ProgramSerializer
from compilationException import *
import ebpfScalarType
import ebpfCounter
import ebpfType
import ebpfInstance


class EbpfActionData(object):
    def __init__(self, name, argtype):
        self.name = name
        self.argtype = argtype


class EbpfActionBase(object):
    def __init__(self, p4action):
        self.name = p4action.name
        self.hliraction = p4action
        self.builtin = False
        self.arguments = []

    def serializeArgumentsAsStruct(self, serializer):
        serializer.emitIndent()
        serializer.appendFormat("/* no arguments for {0} */", self.name)
        serializer.newline()

    def serializeBody(self, serializer, valueName, program):
        serializer.emitIndent()
        serializer.appendFormat("/* no body for {0} */", self.name)
        serializer.newline()

    def __str__(self):
        return "EbpfAction({0})".format(self.name)


class EbpfAction(EbpfActionBase):
    unsupported = [
        # The following cannot be done in EBPF
        "add_header", "remove_header", "execute_meter",
        "clone_ingress_pkt_to_egress",
        "clone_egress_pkt_to_egress", "generate_digest", "resubmit",
        "modify_field_with_hash_based_offset", "truncate", "push", "pop",
        # The following could be done, but are not yet implemented
        # The situation with copy_header is complicated,
        # because we don't do checksums
        "copy_header", "count",
        "register_read", "register_write"]

    # noinspection PyUnresolvedReferences
    def __init__(self, p4action, program):
        super(EbpfAction, self).__init__(p4action)
        assert isinstance(p4action, p4_action)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        self.builtin = False
        self.invalid = False  # a leaf action which is never
                              # called from a table can be invalid.

        for i in range(0, len(p4action.signature)):
            param = p4action.signature[i]
            width = p4action.signature_widths[i]
            if width is None:
                self.invalid = True
                return
            argtype = ebpfScalarType.EbpfScalarType(p4action, width,
                                                    False, program.config)
            actionData = EbpfActionData(param, argtype)
            self.arguments.append(actionData)

    def serializeArgumentsAsStruct(self, serializer):
        if self.invalid:
            raise CompilationException(True,
                "{0} Attempting to generate code for an invalid action",
                                       self.hliraction)

        # Build a struct containing all action arguments.
        serializer.emitIndent()
        serializer.append("struct ")
        serializer.blockStart()
        assert isinstance(serializer, ProgramSerializer)
        for arg in self.arguments:
            assert isinstance(arg, EbpfActionData)
            serializer.emitIndent()
            argtype = arg.argtype
            assert isinstance(argtype, ebpfType.EbpfType)
            argtype.declare(serializer, arg.name, False)
            serializer.endOfStatement(True)
        serializer.blockEnd(False)
        serializer.space()
        serializer.append(self.name)
        serializer.endOfStatement(True)

    def serializeBody(self, serializer, dataContainer, program):
        if self.invalid:
            raise CompilationException(True,
                "{0} Attempting to generate code for an invalid action",
                                       self.hliraction)

        # TODO: generate PARALLEL implementation
        # dataContainer is a string containing the variable name
        # containing the action data
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)
        assert isinstance(dataContainer, str)
        callee_list = self.hliraction.flat_call_sequence
        for e in callee_list:
            action = e[0]
            assert isinstance(action, p4_action)
            arguments = e[1]
            assert isinstance(arguments, list)
            self.serializeCallee(self, action, arguments, serializer,
                                 dataContainer, program)

    def checkSize(self, call, args, program):
        size = None
        for a in args:
            if a is None:
                continue
            if size is None:
                size = a
            elif a != size:
                program.emitWarning(
                    "{0}: Arguments do not have the same size {1} and {2}",
                    call, size, a)
        return size

    @staticmethod
    def translateActionToOperator(actionName):
        if actionName == "add" or actionName == "add_to_field":
            return "+"
        elif actionName == "bit_and":
            return "&"
        elif actionName == "bit_or":
            return "|"
        elif actionName == "bit_xor":
            return "^"
        elif actionName == "subtract" or actionName == "subtract_from_field":
            return "-"
        else:
            raise CompilationException(True,
                                       "Unexpected primitive action {0}",
                                       actionName)

    def serializeCount(self, caller, arguments, serializer,
                       dataContainer, program):
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)
        assert isinstance(arguments, list)
        assert len(arguments) == 2

        counter = arguments[0]
        index = ArgInfo(arguments[1], caller, dataContainer, program)
        ctr = program.getCounter(counter.name)
        assert isinstance(ctr, ebpfCounter.EbpfCounter)
        serializer.emitIndent()
        serializer.blockStart()

        # This is actually incorrect, since the key is not always an u32.
        # This code is currently disabled
        key = program.reservedPrefix + "index"
        serializer.emitIndent()
        serializer.appendFormat("u32 {0} = {1};", key, index.asString)
        serializer.newline()

        ctr.serializeCode(key, serializer, program)

        serializer.blockEnd(True)

    def serializeCallee(self, caller, callee, arguments,
                        serializer, dataContainer, program):
        if self.invalid:
            raise CompilationException(
                True,
                "{0} Attempting to generate code for an invalid action",
                self.hliraction)

        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)
        assert isinstance(callee, p4_action)
        assert isinstance(arguments, list)

        if callee.name in EbpfAction.unsupported:
            raise NotSupportedException("{0}", callee)

        # This is not yet ready
        #if callee.name == "count":
        #    self.serializeCount(caller, arguments,
        #                        serializer, dataContainer, program)
        #    return

        serializer.emitIndent()
        args = self.transformArguments(arguments, caller,
                                       dataContainer, program)
        if callee.name == "modify_field":
            dst = args[0]
            src = args[1]

            size = self.checkSize(callee,
                                  [a.widthInBits() for a in args],
                                  program)
            if size is None:
                raise CompilationException(
                    True, "Cannot infer width for arguments {0}",
                    callee)
            elif size <= 32:
                serializer.appendFormat("{0} = {1};",
                                        dst.asString,
                                        src.asString)
            else:
                if not dst.isLvalue:
                    raise NotSupportedException(
                        "Constants wider than 32-bit: {0}({1})",
                        dst.caller, dst.asString)
                if not src.isLvalue:
                    raise NotSupportedException(
                        "Constants wider than 32-bit: {0}({1})",
                        src.caller, src.asString)
                serializer.appendFormat("memcpy(&{0}, &{1}, {2});",
                                        dst.asString,
                                        src.asString,
                                        size / 8)
        elif (callee.name == "add" or
             callee.name == "bit_and" or
             callee.name == "bit_or" or
             callee.name == "bit_xor" or
             callee.name == "subtract"):
            size = self.checkSize(callee,
                                  [a.widthInBits() for a in args],
                                  program)
            if size is None:
                raise CompilationException(
                    True,
                    "Cannot infer width for arguments {0}",
                    callee)
            if size > 32:
                raise NotSupportedException("{0}: Arithmetic on {1}-bits",
                                            callee, size)
            op = EbpfAction.translateActionToOperator(callee.name)
            serializer.appendFormat("{0} = {1} {2} {3};",
                                    args[0].asString,
                                    args[1].asString,
                                    op,
                                    args[2].asString)
        elif (callee.name == "add_to_field" or
              callee.name == "subtract_from_field"):
            size = self.checkSize(callee,
                                  [a.widthInBits() for a in args],
                                  program)
            if size is None:
                raise CompilationException(
                    True, "Cannot infer width for arguments {0}", callee)
            if size > 32:
                raise NotSupportedException(
                    "{0}: Arithmetic on {1}-bits", callee, size)

            op = EbpfAction.translateActionToOperator(callee.name)
            serializer.appendFormat("{0} = {0} {1} {2};",
                                    args[0].asString,
                                    op,
                                    args[1].asString)
        elif callee.name == "no_op":
            serializer.append("/* noop */")
        elif callee.name == "drop":
            serializer.appendFormat("{0} = 1;", program.dropBit)
        elif callee.name == "push" or callee.name == "pop":
            raise CompilationException(
                True, "{0} push/pop not yet implemented", callee)
        else:
            raise CompilationException(
                True, "Unexpected primitive action {0}", callee)
        serializer.newline()

    def transformArguments(self, arguments, caller, dataContainer, program):
        result = []
        for a in arguments:
            t = ArgInfo(a, caller, dataContainer, program)
            result.append(t)
        return result


class BuiltinAction(EbpfActionBase):
    def __init__(self, p4action):
        super(BuiltinAction, self).__init__(p4action)
        self.builtin = True

    def serializeBody(self, serializer, valueName, program):
        # This is ugly; there should be a better way
        if self.name == "drop":
            serializer.emitIndent()
            serializer.appendFormat("{0} = 1;", program.dropBit)
            serializer.newline()
        else:
            serializer.emitIndent()
            serializer.appendFormat("/* no body for {0} */", self.name)
            serializer.newline()


class ArgInfo(object):
    # noinspection PyUnresolvedReferences
    # Represents an argument passed to an action
    def __init__(self, argument, caller, dataContainer, program):
        self.width = None
        self.asString = None
        self.isLvalue = True
        self.caller = caller

        assert isinstance(program, ebpfProgram.EbpfProgram)
        assert isinstance(caller, EbpfAction)

        if isinstance(argument, int):
            self.asString = str(argument)
            self.isLvalue = False
            # size is unknown
        elif isinstance(argument, p4_field):
            if ebpfProgram.EbpfProgram.isArrayElementInstance(
                    argument.instance):
                if isinstance(argument.instance.index, int):
                    index = "[" + str(argument.instance.index) + "]"
                else:
                    raise CompilationException(
                        True,
                        "Unexpected index for array {0}",
                        argument.instance.index)
                stackInstance = program.getStackInstance(
                    argument.instance.base_name)
                assert isinstance(stackInstance, ebpfInstance.EbpfHeaderStack)
                fieldtype = stackInstance.basetype.getField(argument.name)
                self.width = fieldtype.widthInBits()
                self.asString = "{0}.{1}{3}.{2}".format(
                    program.headerStructName,
                    stackInstance.name, argument.name, index)
            else:
                instance = program.getInstance(argument.instance.base_name)
                if isinstance(instance, ebpfInstance.EbpfHeader):
                    parent = program.headerStructName
                else:
                    parent = program.metadataStructName
                fieldtype = instance.type.getField(argument.name)
                self.width = fieldtype.widthInBits()
                self.asString = "{0}.{1}.{2}".format(
                    parent, instance.name, argument.name)
        elif isinstance(argument, p4_signature_ref):
            refarg = caller.arguments[argument.idx]
            self.asString = "{0}->u.{1}.{2}".format(
                dataContainer, caller.name, refarg.name)
            self.width = caller.arguments[argument.idx].argtype.widthInBits()
        elif isinstance(argument, p4_header_instance):
            # This could be a header array element
            # Unfortunately for push and pop, the user mean the whole array,
            # but the representation contains just the first element here.
            # This looks like a bug in the HLIR.
            if ebpfProgram.EbpfProgram.isArrayElementInstance(argument):
                if isinstance(argument.index, int):
                    index = "[" + str(argument.index) + "]"
                else:
                    raise CompilationException(
                        True,
                        "Unexpected index for array {0}", argument.index)
                stackInstance = program.getStackInstance(argument.base_name)
                assert isinstance(stackInstance, ebpfInstance.EbpfHeaderStack)
                fieldtype = stackInstance.basetype
                self.width = fieldtype.widthInBits()
                self.asString = "{0}.{1}{2}".format(
                    program.headerStructName, stackInstance.name, index)
            else:
                instance = program.getInstance(argument.name)
                instancetype = instance.type
                self.width = instancetype.widthInBits()
                self.asString = "{0}.{1}".format(
                    program.headerStructName, argument.name)
        else:
            raise CompilationException(
                True, "Unexpected action argument {0}", argument)

    def widthInBits(self):
        return self.width
