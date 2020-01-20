from pyroute2 import NSPopen
from distutils.spawn import find_executable
import traceback

import logging, os, sys

if 'PYTHON_TEST_LOGFILE' in os.environ:
    logfile=os.environ['PYTHON_TEST_LOGFILE']
    logging.basicConfig(level=logging.ERROR, filename=logfile, filemode='a')
else:
    logging.basicConfig(level=logging.ERROR, stream=sys.stderr)

logger = logging.getLogger()

def has_executable(name):
    path = find_executable(name)
    if path is None:
        raise Exception(name + ": command not found")
    return path

# This is a decorator that will allow for logging tests, but flagging them as
# "known to fail". These tests legitimately fail and represent actual bugs, but
# as these are already documented the test status can be "green" without these
# tests, similar to catch2's [!mayfail] tag.
# This is done using the existing python unittest concept of an "expected failure",
# but it is only done after the fact, if the test fails or raises an exception.
# It gives all tests a chance to succeed, but if they fail it logs them and
# continues.
def mayFail(message):
    def decorator(func):
        def wrapper(*args, **kwargs):
            res = None
            err = None
            try:
                res = func(*args, **kwargs)
            except BaseException as e:
                logger.critical("WARNING! Test %s failed, but marked as passed because it is decorated with @mayFail." %
                       args[0])
                logger.critical("\tThe reason why this mayFail was: %s" % message)
                logger.critical("\tThe failure was: \"%s\"" % e)
                logger.critical("\tStacktrace: \"%s\"" % traceback.format_exc())
                testcase=args[0]
                testcase.TestResult().addExpectedFailure(testcase, e)
                err = e
            finally:
                if err != None:
                    raise err
                else:
                    return res
        return wrapper
    return decorator

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
