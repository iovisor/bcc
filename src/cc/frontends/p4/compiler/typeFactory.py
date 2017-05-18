# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from p4_hlir.hlir import p4_header
from ebpfStructType import *

class EbpfTypeFactory(object):
    def __init__(self, config):
        self.type_map = {}
        self.config = config

    def build(self, hlirType, asMetadata):
        name = hlirType.name
        if hlirType.name in self.type_map:
            retval = self.type_map[name]
            if ((not asMetadata and isinstance(retval, EbpfMetadataType)) or
                (asMetadata and isinstance(retval, EbpfHeaderType))):
                raise CompilationException(
                    True, "Same type used both as a header and metadata {0}",
                    hlirType)

        if isinstance(hlirType, p4_header):
            if asMetadata:
                type = EbpfMetadataType(hlirType, self.config)
            else:
                type = EbpfHeaderType(hlirType, self.config)
        else:
            raise CompilationException(True, "Unexpected type {0}", hlirType)
        self.registerType(name, type)
        return type

    def registerType(self, name, ebpfType):
        self.type_map[name] = ebpfType
