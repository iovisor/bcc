# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from compilationException import CompilationException

class EbpfType(object):
    __doc__ = "Base class for representing a P4 type"

    def __init__(self, hlirType):
        self.hlirType = hlirType

    # Methods to override

    def serialize(self, serializer):
        # the type itself
        raise CompilationException(True, "Method must be overridden")

    def declare(self, serializer, identifier, asPointer):
        # declaration of an identifier with this type
        # asPointer is a boolean;
        # if true, the identifier is declared as a pointer
        raise CompilationException(True, "Method must be overridden")

    def emitInitializer(self, serializer):
        # A default initializer suitable for this type
        raise CompilationException(True, "Method must be overridden")

    def declareArray(self, serializer, identifier, size):
        # Declare an identifier with an array type with the specified size
        raise CompilationException(True, "Method must be overridden")
