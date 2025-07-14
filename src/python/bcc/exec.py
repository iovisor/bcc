# Copyright 2025 Rocky Xing
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import signal
import sys

child_exit = 0

pipe_read, pipe_write = os.pipe()

def _child_signal_handler(signum, frame):
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                break
        except OSError:
            break

    global child_exit
    child_exit = 1

def run_cmd(args) -> int:
    pid = os.fork()
    if pid < 0:
        print("failed to fork", file=sys.stderr)
        sys.exit(1)
    elif pid == 0:
        try:
            os.close(pipe_write)
            os.read(pipe_read, 1)
            os.execvp(args[0], args)
        except OSError as e:
            print("failed to exec command: %s: %s" % (' '.join(args), e), file=sys.stderr)
            sys.exit(1)
        finally:
            os.close(pipe_read)
            sys.exit(0)
    else:
        signal.signal(signal.SIGCHLD, _child_signal_handler)
        return pid

def cmd_ready():
    try:
        os.close(pipe_read)
        os.write(pipe_write, b'x')
    except OSError as e:
        sys.exit(1)
    finally:
        os.close(pipe_write)

def cmd_exited():
    return child_exit

