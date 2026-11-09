# Licensed under the Apache License, Version 2.0 (the "License")

import os
from unittest import TextTestRunner


class _LogStream:
    def __init__(self, stream, logfile):
        self.stream = stream
        self.logfile = logfile

    def write(self, text):
        self.stream.write(text)
        self.logfile.write(text)

    def flush(self):
        self.stream.flush()
        self.logfile.flush()

    def writeln(self, text=""):
        self.write(text + "\n")
        self.flush()


class LoggingTestRunner(TextTestRunner):
    """Keep normal unittest output and optionally append it to a log file."""

    def run(self, test):
        path = os.environ.get("LIBBPF_TOOLS_TEST_LOGFILE")
        if path is None:
            return super().run(test)

        with open(path, "a", encoding="utf-8") as logfile:
            stream = self.stream
            self.stream = _LogStream(stream, logfile)
            try:
                return super().run(test)
            finally:
                self.stream = stream
