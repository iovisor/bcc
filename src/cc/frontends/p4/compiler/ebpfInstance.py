# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from p4_hlir.hlir import p4_header_instance
from ebpfType import EbpfType
from compilationException import CompilationException
from programSerializer import ProgramSerializer
import typeFactory


class EbpfInstanceBase(object):
    def __init__(self):
        pass


class SimpleInstance(EbpfInstanceBase):
    # A header or a metadata instance (but not array elements)
    def __init__(self, hlirInstance, factory, isMetadata):
        super(SimpleInstance, self).__init__()
        self.hlirInstance = hlirInstance
        self.name = hlirInstance.base_name
        self.type = factory.build(hlirInstance.header_type, isMetadata)

    def declare(self, serializer):
        assert isinstance(serializer, ProgramSerializer)
        self.type.declare(serializer, self.name, False)


class EbpfHeader(SimpleInstance):
    """ Represents a header instance from a P4 program """
    def __init__(self, hlirHeaderInstance, factory):
        super(EbpfHeader, self).__init__(hlirHeaderInstance, factory, False)
        if hlirHeaderInstance.metadata:
            raise CompilationException(True, "Metadata passed to EpbfHeader")
        if hlirHeaderInstance.index is not None:
            self.name += "_" + str(hlirHeaderInstance.index)


class EbpfMetadata(SimpleInstance):
    """Represents a metadata instance from a P4 program"""
    def __init__(self, hlirMetadataInstance, factory):
        super(EbpfMetadata, self).__init__(hlirMetadataInstance, factory, True)
        if not hlirMetadataInstance.metadata:
            raise CompilationException(
                True, "Header instance passed to EpbfMetadata {0}",
                hlirMetadataInstance)
        if hlirMetadataInstance.index is not None:
            raise CompilationException(
                True, "Unexpected metadata array {0}", self.hlirInstance)
        if hasattr(hlirMetadataInstance, "initializer"):
            self.initializer = hlirMetadataInstance.initializer
        else:
            self.initializer = None

    def emitInitializer(self, serializer):
        assert isinstance(serializer, ProgramSerializer)
        if self.initializer is None:
            self.type.emitInitializer(serializer)
        else:
            for key in self.initializer.keys():
                serializer.appendFormat(
                    ".{0} = {1},", key, self.initializer[key])


class EbpfHeaderStack(EbpfInstanceBase):
    """Represents a header stack instance; there is one instance of
    this class for each STACK, and not for each
    element of the stack, as in the HLIR"""
    def __init__(self, hlirInstance, indexVar, factory):
        super(EbpfHeaderStack, self).__init__()

        # indexVar: name of the ebpf variable that
        # holds the current index for this stack
        assert isinstance(indexVar, str)
        assert isinstance(factory, typeFactory.EbpfTypeFactory)
        assert isinstance(hlirInstance, p4_header_instance)

        self.indexVar = indexVar
        self.name = hlirInstance.base_name
        self.basetype = factory.build(hlirInstance.header_type, False)
        assert isinstance(self.basetype, EbpfType)
        self.arraySize = hlirInstance.max_index + 1
        self.hlirInstance = hlirInstance

    def declare(self, serializer):
        assert isinstance(serializer, ProgramSerializer)
        self.basetype.declareArray(serializer, self.name, self.arraySize)
