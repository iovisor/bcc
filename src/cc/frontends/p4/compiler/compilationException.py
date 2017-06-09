# Copyright (c) Barefoot Networks, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

class CompilationException(Exception):
    """Signals an error during compilation"""
    def __init__(self, isBug, format, *message):
        # isBug: indicates that this is a compiler bug
        super(CompilationException, self).__init__()

        assert isinstance(format, str)
        assert isinstance(isBug, bool)
        self.message = message
        self.format = format
        self.isBug = isBug

    def show(self):
        # TODO: format this message nicely
        return self.format.format(*self.message)


class NotSupportedException(Exception):
    archError = " not supported by EBPF"

    def __init__(self, format, *message):
        super(NotSupportedException, self).__init__()

        assert isinstance(format, str)
        self.message = message
        self.format = format

    def show(self):
        # TODO: format this message nicely
        return (self.format + NotSupportedException.archError).format(
            *self.message)
