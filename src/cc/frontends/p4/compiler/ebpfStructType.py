# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from p4_hlir.hlir import P4_SIGNED, P4_SATURATING
from ebpfScalarType import *


class EbpfField(object):
    __doc__ = "represents a field in a struct type, not in an instance"

    def __init__(self, hlirParentType, name, widthInBits, attributes, config):
        self.name = name
        self.width = widthInBits
        self.hlirType = hlirParentType
        signed = False
        if P4_SIGNED in attributes:
            signed = True
        if P4_SATURATING in attributes:
            raise NotSupportedException(
                "{0}.{1}: Saturated types", self.hlirType, self.name)

        try:
            self.type = EbpfScalarType(
                self.hlirType, widthInBits, signed, config)
        except CompilationException, e:
            raise CompilationException(
                e.isBug, "{0}.{1}: {2}", hlirParentType, self.name, e.show())

    def widthInBits(self):
        return self.width


class EbpfStructType(EbpfType):
    # Abstract base class for HeaderType and MetadataType.
    # They are both represented by a p4 header_type
    def __init__(self, hlirHeader, config):
        super(EbpfStructType, self).__init__(hlirHeader)
        self.name = hlirHeader.name
        self.fields = []

        for (fieldName, fieldSize) in self.hlirType.layout.items():
            attributes = self.hlirType.attributes[fieldName]
            field = EbpfField(
                hlirHeader, fieldName, fieldSize, attributes, config)
            self.fields.append(field)

    def serialize(self, serializer):
        assert isinstance(serializer, ProgramSerializer)

        serializer.emitIndent()
        serializer.appendFormat("struct {0} ", self.name)
        serializer.blockStart()

        for field in self.fields:
            serializer.emitIndent()
            field.type.declare(serializer, field.name, False)
            serializer.appendFormat("; /* {0} bits */", field.widthInBits())
            serializer.newline()

        serializer.blockEnd(False)
        serializer.endOfStatement(True)

    def declare(self, serializer, identifier, asPointer):
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(identifier, str)
        assert isinstance(asPointer, bool)

        serializer.appendFormat("struct {0} ", self.name)
        if asPointer:
            serializer.append("*")
        serializer.append(identifier)

    def widthInBits(self):
        return self.hlirType.length * 8

    def getField(self, name):
        assert isinstance(name, str)

        for f in self.fields:
            assert isinstance(f, EbpfField)
            if f.name == name:
                return f
        raise CompilationException(
            True, "Could not locate field {0}.{1}", self, name)


class EbpfHeaderType(EbpfStructType):
    def __init__(self, hlirHeader, config):
        super(EbpfHeaderType, self).__init__(hlirHeader, config)
        validField = EbpfField(hlirHeader, "valid", 1, set(), config)
        # check that no "valid" field exists already
        for f in self.fields:
            if f.name == "valid":
                raise CompilationException(
                    True,
                    "Header type contains a field named `valid': {0}",
                    f)
        self.fields.append(validField)

    def emitInitializer(self, serializer):
        assert isinstance(serializer, ProgramSerializer)
        serializer.blockStart()
        serializer.emitIndent()
        serializer.appendLine(".valid = 0")
        serializer.blockEnd(False)

    def declareArray(self, serializer, identifier, size):
        assert isinstance(serializer, ProgramSerializer)
        serializer.appendFormat(
            "struct {0} {1}[{2}]", self.name, identifier, size)


class EbpfMetadataType(EbpfStructType):
    def __init__(self, hlirHeader, config):
        super(EbpfMetadataType, self).__init__(hlirHeader, config)

    def emitInitializer(self, serializer):
        assert isinstance(serializer, ProgramSerializer)

        serializer.blockStart()
        for field in self.fields:
            serializer.emitIndent()
            serializer.appendFormat(".{0} = ", field.name)

            field.type.emitInitializer(serializer)
            serializer.append(",")
            serializer.newline()
        serializer.blockEnd(False)
