# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from p4_hlir.hlir import P4_AUTO_WIDTH
from ebpfType import *
from compilationException import *
from programSerializer import ProgramSerializer


class EbpfScalarType(EbpfType):
    __doc__ = "Represents a scalar type"
    def __init__(self, parent, widthInBits, isSigned, config):
        super(EbpfScalarType, self).__init__(None)
        assert isinstance(widthInBits, int)
        assert isinstance(isSigned, bool)
        self.width = widthInBits
        self.isSigned = isSigned
        self.config = config
        if widthInBits is P4_AUTO_WIDTH:
            raise NotSupportedException("{0} Variable-width field", parent)

    def widthInBits(self):
        return self.width

    @staticmethod
    def bytesRequired(width):
        return (width + 7) / 8

    def asString(self):
        if self.isSigned:
            prefix = self.config.iprefix
        else:
            prefix = self.config.uprefix

        if self.width <= 8:
            name = prefix + "8"
        elif self.width <= 16:
            name = prefix + "16"
        elif self.width <= 32:
            name = prefix + "32"
        else:
            name = "char*"
        return name

    def alignment(self):
        if self.width <= 8:
            return 1
        elif self.width <= 16:
            return 2
        elif self.width <= 32:
            return 4
        else:
            return 1  # Char array

    def serialize(self, serializer):
        assert isinstance(serializer, ProgramSerializer)
        serializer.append(self.asString())

    def declareArray(self, serializer, identifier, size):
        raise CompilationException(
            True, "Arrays of base type not expected in P4")

    def declare(self, serializer, identifier, asPointer):
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(asPointer, bool)
        assert isinstance(identifier, str)

        if self.width <= 32:
            self.serialize(serializer)
            if asPointer:
                serializer.append("*")
            serializer.space()
            serializer.append(identifier)
        else:
            if asPointer:
                serializer.append("char*")
            else:
                serializer.appendFormat(
                    "char {0}[{1}]", identifier,
                    EbpfScalarType.bytesRequired(self.width))

    def emitInitializer(self, serializer):
        assert isinstance(serializer, ProgramSerializer)
        serializer.append("0")
