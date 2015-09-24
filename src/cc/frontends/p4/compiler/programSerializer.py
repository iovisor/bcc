#!/usr/bin/env python

# helper for building C program source text

from compilationException import *


class ProgramSerializer(object):
    def __init__(self):
        self.program = ""
        self.eol = "\n"
        self.currentIndent = 0
        self.INDENT_AMOUNT = 4  # default indent amount

    def __str__(self):
        return self.program

    def increaseIndent(self):
        self.currentIndent += self.INDENT_AMOUNT

    def decreaseIndent(self):
        self.currentIndent -= self.INDENT_AMOUNT
        if self.currentIndent < 0:
            raise CompilationException(True, "Negative indentation level")

    def toString(self):
        return self.program

    def space(self):
        self.append(" ")

    def newline(self):
        self.program += self.eol

    def endOfStatement(self, addNewline):
        self.append(";")
        if addNewline:
            self.newline()

    def append(self, string):
        self.program += str(string)

    def appendFormat(self, format, *args):
        string = format.format(*args)
        self.append(string)

    def appendLine(self, string):
        self.append(string)
        self.newline()

    def emitIndent(self):
        self.program += " " * self.currentIndent

    def blockStart(self):
        self.append("{")
        self.newline()
        self.increaseIndent()

    def blockEnd(self, addNewline):
        self.decreaseIndent()
        self.emitIndent()
        self.append("}")
        if addNewline:
            self.newline()
