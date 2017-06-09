# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from p4_hlir.hlir import p4_match_type, p4_field, p4_table, p4_header_instance
from programSerializer import ProgramSerializer
from compilationException import *
import ebpfProgram
import ebpfInstance
import ebpfCounter
import ebpfStructType
import ebpfAction


class EbpfTableKeyField(object):
    def __init__(self, fieldname, instance, field, mask):
        assert isinstance(instance, ebpfInstance.EbpfInstanceBase)
        assert isinstance(field, ebpfStructType.EbpfField)

        self.keyFieldName = fieldname
        self.instance = instance
        self.field = field
        self.mask = mask

    def serializeType(self, serializer):
        assert isinstance(serializer, ProgramSerializer)
        ftype = self.field.type
        serializer.emitIndent()
        ftype.declare(serializer, self.keyFieldName, False)
        serializer.endOfStatement(True)

    def serializeConstruction(self, keyName, serializer, program):
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(keyName, str)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        if self.mask is not None:
            maskExpression = " & {0}".format(self.mask)
        else:
            maskExpression = ""

        if isinstance(self.instance, ebpfInstance.EbpfMetadata):
            base = program.metadataStructName
        else:
            base = program.headerStructName

        if isinstance(self.instance, ebpfInstance.SimpleInstance):
            source = "{0}.{1}.{2}".format(
                base, self.instance.name, self.field.name)
        else:
            assert isinstance(self.instance, ebpfInstance.EbpfHeaderStack)
            source = "{0}.{1}[{2}].{3}".format(
                base, self.instance.name,
                self.instance.hlirInstance.index, self.field.name)
        destination = "{0}.{1}".format(keyName, self.keyFieldName)
        size = self.field.widthInBits()

        serializer.emitIndent()
        if size <= 32:
            serializer.appendFormat("{0} = ({1}){2};",
                                    destination, source, maskExpression)
        else:
            if maskExpression != "":
                raise NotSupportedException(
                    "{0} Mask wider than 32 bits", self.field.hlirType)
            serializer.appendFormat(
                "memcpy(&{0}, &{1}, {2});", destination, source, size / 8)

        serializer.newline()


class EbpfTableKey(object):
    def __init__(self, match_fields, program):
        assert isinstance(program, ebpfProgram.EbpfProgram)

        self.expressions = []
        self.fields = []
        self.masks = []
        self.fieldNamePrefix = "key_field_"
        self.program = program

        fieldNumber = 0
        for f in match_fields:
            field = f[0]
            matchType = f[1]
            mask = f[2]

            if ((matchType is p4_match_type.P4_MATCH_TERNARY) or
                (matchType is p4_match_type.P4_MATCH_LPM) or
                (matchType is p4_match_type.P4_MATCH_RANGE)):
                raise NotSupportedException(
                    False, "Match type {0}", matchType)

            if matchType is p4_match_type.P4_MATCH_VALID:
                # we should be really checking the valid field;
                # p4_field is a header instance
                assert isinstance(field, p4_header_instance)
                instance = field
                fieldname = "valid"
            else:
                assert isinstance(field, p4_field)
                instance = field.instance
                fieldname = field.name

            if ebpfProgram.EbpfProgram.isArrayElementInstance(instance):
                ebpfStack = program.getStackInstance(instance.base_name)
                assert isinstance(ebpfStack, ebpfInstance.EbpfHeaderStack)
                basetype = ebpfStack.basetype
                eInstance = program.getStackInstance(instance.base_name)
            else:
                ebpfHeader = program.getInstance(instance.name)
                assert isinstance(ebpfHeader, ebpfInstance.SimpleInstance)
                basetype = ebpfHeader.type
                eInstance = program.getInstance(instance.base_name)

            ebpfField = basetype.getField(fieldname)
            assert isinstance(ebpfField, ebpfStructType.EbpfField)

            fieldName = self.fieldNamePrefix + str(fieldNumber)
            fieldNumber += 1
            keyField = EbpfTableKeyField(fieldName, eInstance, ebpfField, mask)

            self.fields.append(keyField)
            self.masks.append(mask)

    @staticmethod
    def fieldRank(field):
        assert isinstance(field, EbpfTableKeyField)
        return field.field.type.alignment()

    def serializeType(self, serializer, keyTypeName):
        assert isinstance(serializer, ProgramSerializer)
        serializer.emitIndent()
        serializer.appendFormat("struct {0} ", keyTypeName)
        serializer.blockStart()

        # Sort fields in decreasing size; this will ensure that
        # there is no padding.
        # Padding may cause the ebpf verification to fail,
        # since padding fields are not initalized
        fieldOrder = sorted(
            self.fields, key=EbpfTableKey.fieldRank, reverse=True)
        for f in fieldOrder:
            assert isinstance(f, EbpfTableKeyField)
            f.serializeType(serializer)

        serializer.blockEnd(False)
        serializer.endOfStatement(True)

    def serializeConstruction(self, serializer, keyName, program):
        serializer.emitIndent()
        serializer.appendLine("/* construct key */")

        for f in self.fields:
            f.serializeConstruction(keyName, serializer, program)


class EbpfTable(object):
    # noinspection PyUnresolvedReferences
    def __init__(self, hlirtable, program, config):
        assert isinstance(hlirtable, p4_table)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        self.name = hlirtable.name
        self.hlirtable = hlirtable
        self.config = config

        self.defaultActionMapName = (program.reservedPrefix +
                                     self.name + "_miss")
        self.key = EbpfTableKey(hlirtable.match_fields, program)
        self.size = hlirtable.max_size
        if self.size is None:
            program.emitWarning(
                "{0} does not specify a max_size; using 1024", hlirtable)
            self.size = 1024
        self.isHash = True  # TODO: try to guess arrays when possible
        self.dataMapName = self.name
        self.actionEnumName = program.generateNewName(self.name + "_actions")
        self.keyTypeName = program.generateNewName(self.name + "_key")
        self.valueTypeName = program.generateNewName(self.name + "_value")
        self.actions = []

        if hlirtable.action_profile is not None:
            raise NotSupportedException("{0}: action_profile tables",
                                        hlirtable)
        if hlirtable.support_timeout:
            program.emitWarning("{0}: table timeout {1}; ignoring",
                                hlirtable, NotSupportedException.archError)

        self.counters = []
        if (hlirtable.attached_counters is not None):
            for c in hlirtable.attached_counters:
                ctr = program.getCounter(c.name)
                assert isinstance(ctr, ebpfCounter.EbpfCounter)
                self.counters.append(ctr)

        if (len(hlirtable.attached_meters) > 0 or
            len(hlirtable.attached_registers) > 0):
            program.emitWarning("{0}: meters/registers {1}; ignored",
                                hlirtable, NotSupportedException.archError)

        for a in hlirtable.actions:
            action = program.getAction(a)
            self.actions.append(action)

    def serializeKeyType(self, serializer):
        assert isinstance(serializer, ProgramSerializer)
        self.key.serializeType(serializer, self.keyTypeName)

    def serializeActionArguments(self, serializer, action):
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(action, ebpfAction.EbpfActionBase)
        action.serializeArgumentsAsStruct(serializer)

    def serializeValueType(self, serializer):
        assert isinstance(serializer, ProgramSerializer)
        #  create an enum with tags for all actions
        serializer.emitIndent()
        serializer.appendFormat("enum {0} ", self.actionEnumName)
        serializer.blockStart()

        for a in self.actions:
            name = a.name
            serializer.emitIndent()
            serializer.appendFormat("{0}_{1},", self.name, name)
            serializer.newline()

        serializer.blockEnd(False)
        serializer.endOfStatement(True)

        # a type-safe union: a struct with a tag and an union
        serializer.emitIndent()
        serializer.appendFormat("struct {0} ", self.valueTypeName)
        serializer.blockStart()

        serializer.emitIndent()
        #serializer.appendFormat("enum {0} action;", self.actionEnumName)
        # teporary workaround bcc bug
        serializer.appendFormat("{0}32 action;",
                                self.config.uprefix)
        serializer.newline()

        serializer.emitIndent()
        serializer.append("union ")
        serializer.blockStart()

        for a in self.actions:
            self.serializeActionArguments(serializer, a)

        serializer.blockEnd(False)
        serializer.space()
        serializer.appendLine("u;")
        serializer.blockEnd(False)
        serializer.endOfStatement(True)

    def serialize(self, serializer, program):
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        self.serializeKeyType(serializer)
        self.serializeValueType(serializer)

        self.config.serializeTableDeclaration(
            serializer, self.dataMapName, self.isHash,
            "struct " + self.keyTypeName,
            "struct " + self.valueTypeName, self.size)
        self.config.serializeTableDeclaration(
            serializer, self.defaultActionMapName, False,
            program.arrayIndexType, "struct " + self.valueTypeName, 1)

    def serializeCode(self, serializer, program, nextNode):
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(program, ebpfProgram.EbpfProgram)

        hitVarName = program.reservedPrefix + "hit"
        keyname = "key"
        valueName = "value"

        serializer.newline()
        serializer.emitIndent()
        serializer.appendFormat("{0}:", program.getLabel(self))
        serializer.newline()

        serializer.emitIndent()
        serializer.blockStart()

        serializer.emitIndent()
        serializer.appendFormat("{0}8 {1};", program.config.uprefix, hitVarName)
        serializer.newline()

        serializer.emitIndent()
        serializer.appendFormat("struct {0} {1} = {{}};", self.keyTypeName, keyname)
        serializer.newline()

        serializer.emitIndent()
        serializer.appendFormat(
            "struct {0} *{1};", self.valueTypeName, valueName)
        serializer.newline()

        self.key.serializeConstruction(serializer, keyname, program)

        serializer.emitIndent()
        serializer.appendFormat("{0} = 1;", hitVarName)
        serializer.newline()

        serializer.emitIndent()
        serializer.appendLine("/* perform lookup */")
        serializer.emitIndent()
        program.config.serializeLookup(
            serializer, self.dataMapName, keyname, valueName)
        serializer.newline()

        serializer.emitIndent()
        serializer.appendFormat("if ({0} == NULL) ", valueName)
        serializer.blockStart()

        serializer.emitIndent()
        serializer.appendFormat("{0} = 0;", hitVarName)
        serializer.newline()

        serializer.emitIndent()
        serializer.appendLine("/* miss; find default action */")
        serializer.emitIndent()
        program.config.serializeLookup(
            serializer, self.defaultActionMapName,
            program.zeroKeyName, valueName)
        serializer.newline()
        serializer.blockEnd(True)

        if len(self.counters) > 0:
            serializer.emitIndent()
            serializer.append("else ")
            serializer.blockStart()
            for c in self.counters:
                assert isinstance(c, ebpfCounter.EbpfCounter)
                if c.autoIncrement:
                    serializer.emitIndent()
                    serializer.blockStart()
                    c.serializeCode(keyname, serializer, program)
                    serializer.blockEnd(True)
            serializer.blockEnd(True)

        serializer.emitIndent()
        serializer.appendFormat("if ({0} != NULL) ", valueName)
        serializer.blockStart()
        serializer.emitIndent()
        serializer.appendLine("/* run action */")
        self.runAction(serializer, self.name, valueName, program, nextNode)

        nextNode = self.hlirtable.next_
        if "hit" in nextNode:
            node = nextNode["hit"]
            if node is None:
                node = nextNode
            label = program.getLabel(node)
            serializer.emitIndent()
            serializer.appendFormat("if (hit) goto {0};", label)
            serializer.newline()

            node = nextNode["miss"]
            if node is None:
                node = nextNode
            label = program.getLabel(node)
            serializer.emitIndent()
            serializer.appendFormat("else goto {0};", label)
            serializer.newline()

        serializer.blockEnd(True)
        if not "hit" in nextNode:
            # Catch-all
            serializer.emitIndent()
            serializer.appendFormat("goto end;")
            serializer.newline()

        serializer.blockEnd(True)

    def runAction(self, serializer, tableName, valueName, program, nextNode):
        serializer.emitIndent()
        serializer.appendFormat("switch ({0}->action) ", valueName)
        serializer.blockStart()

        for a in self.actions:
            assert isinstance(a, ebpfAction.EbpfActionBase)

            serializer.emitIndent()
            serializer.appendFormat("case {0}_{1}: ", tableName, a.name)
            serializer.newline()
            serializer.emitIndent()
            serializer.blockStart()
            a.serializeBody(serializer, valueName, program)
            serializer.blockEnd(True)
            serializer.emitIndent()

            nextNodes = self.hlirtable.next_
            if a.hliraction in nextNodes:
                node = nextNodes[a.hliraction]
                if node is None:
                    node = nextNode
                label = program.getLabel(node)
                serializer.appendFormat("goto {0};", label)
            else:
                serializer.appendFormat("break;")
            serializer.newline()

        serializer.blockEnd(True)
