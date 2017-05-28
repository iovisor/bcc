# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from programSerializer import ProgramSerializer

# abstraction for isolating target-specific features

# Base class for representing target-specific configuration
class TargetConfig(object):
    def __init__(self, target):
        self.targetName = target

    def getIncludes(self):
        return ""

    def serializeLookup(self, serializer, tableName, key, value):
        serializer.appendFormat("{0} = bpf_map_lookup_elem(&{1}, &{2});",
                                value, tableName, key)

    def serializeUpdate(self, serializer, tableName, key, value):
        serializer.appendFormat(
            "bpf_map_update_elem(&{0}, &{1}, &{2}, BPF_ANY);",
            tableName, key, value)

    def serializeLicense(self, serializer, licenseString):
        assert isinstance(serializer, ProgramSerializer)
        serializer.emitIndent()
        serializer.appendFormat(
            "char _license[] {0}(\"license\") = \"{1}\";",
            self.config.section, licenseString)
        serializer.newline()

    def serializeCodeSection(self, serializer):
        assert isinstance(serializer, ProgramSerializer)
        serializer.appendFormat("{0}(\"{1}\")", self.section, self.entrySection)

    def serializeTableDeclaration(self, serializer, tableName,
                                  isHash, keyType, valueType, size):
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(tableName, str)
        assert isinstance(isHash, bool)
        assert isinstance(keyType, str)
        assert isinstance(valueType, str)
        assert isinstance(size, int)

        serializer.emitIndent()
        serializer.appendFormat("struct {0} {1}(\"maps\") {2} = ",
                                self.tableName, self.section, tableName)
        serializer.blockStart()

        serializer.emitIndent()
        serializer.append(".type = ")
        if isHash:
            serializer.appendLine("BPF_MAP_TYPE_HASH,")
        else:
            serializer.appendLine("BPF_MAP_TYPE_ARRAY,")

        serializer.emitIndent()
        serializer.appendFormat(".{0} = sizeof(struct {1}), ",
                                self.tableKeyAttribute, keyType)
        serializer.newline()

        serializer.emitIndent()
        serializer.appendFormat(".{0} = sizeof(struct {1}), ",
                                self.tableValueAttribute, valueType)
        serializer.newline()

        serializer.emitIndent()
        serializer.appendFormat(".{0} = {1}, ", self.tableSizeAttribute, size)
        serializer.newline()

        serializer.blockEnd(False)
        serializer.endOfStatement(True)

    def generateDword(self, serializer):
        serializer.appendFormat(
            "static inline {0}64 load_dword(void *skb, {0}64 off)",
            self.uprefix)
        serializer.newline()
        serializer.blockStart()
        serializer.emitIndent()
        serializer.appendFormat(
            ("return (({0}64)load_word(skb, off) << 32) | " +
             "load_word(skb, off + 4);"),
            self.uprefix)
        serializer.newline()
        serializer.blockEnd(True)


# Represents a target that is compiled within the kernel
# source tree samples folder and which attaches to a socket
class KernelSamplesConfig(TargetConfig):
    def __init__(self):
        super(SocketConfig, self).__init__("Socket")
        self.entrySection = "socket1"
        self.section = "SEC"
        self.uprefix = "u"
        self.iprefix = "i"
        self.tableKeyAttribute = "key_size"
        self.tableValueAttribute = "value_size"
        self.tableSizeAttribute = "max_entries"
        self.tableName = "bpf_map_def"
        self.postamble = ""

    def getIncludes(self):
        return """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include "bpf_helpers.h"
"""


# Represents a target compiled by bcc that uses the TC
class BccConfig(TargetConfig):
    def __init__(self):
        super(BccConfig, self).__init__("BCC")
        self.uprefix = "u"
        self.iprefix = "i"
        self.postamble = ""

    def serializeTableDeclaration(self, serializer, tableName,
                                  isHash, keyType, valueType, size):
        assert isinstance(serializer, ProgramSerializer)
        assert isinstance(tableName, str)
        assert isinstance(isHash, bool)
        assert isinstance(keyType, str)
        assert isinstance(valueType, str)
        assert isinstance(size, int)

        serializer.emitIndent()
        if isHash:
            kind = "hash"
        else:
            kind = "array"
        serializer.appendFormat(
            "BPF_TABLE(\"{0}\", {1}, {2}, {3}, {4});",
            kind, keyType, valueType, tableName, size)
        serializer.newline()

    def serializeLookup(self, serializer, tableName, key, value):
        serializer.appendFormat("{0} = {1}.lookup(&{2});",
                                value, tableName, key)

    def serializeUpdate(self, serializer, tableName, key, value):
        serializer.appendFormat("{0}.update(&{1}, &{2});",
                                tableName, key, value)

    def generateDword(self, serializer):
        pass

    def serializeCodeSection(self, serializer):
        pass

    def getIncludes(self):
        return """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/pkt_cls.h>
"""

    def serializeLicense(self, serializer, licenseString):
        assert isinstance(serializer, ProgramSerializer)
        pass
