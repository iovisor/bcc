from pyroute2 import NSPopen
from distutils.spawn import find_executable

def has_executable(name):
    path = find_executable(name)
    if path is None:
        raise Exception(name + ": command not found")
    return path

class NSPopenWithCheck(NSPopen):
    """
    A wrapper for NSPopen that additionally checks if the program
    to be executed is available from the system path or not.
    If found, it proceeds with the usual NSPopen() call.
    Otherwise, it raises an exception.
    """

    def __init__(self, nsname, *argv, **kwarg):
        name = list(argv)[0][0]
        has_executable(name)
        super(NSPopenWithCheck, self).__init__(nsname, *argv, **kwarg)
