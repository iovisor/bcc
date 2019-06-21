# Copyright 2017 Joel Fernandes <joelaf@google.com>
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

import pexpect as pe
import time
import os

from .shell import ShellRemote

class AdbRemote(ShellRemote):
    def __init__(self, cmd=None):
        """
        Create a connection by spawning bpfd and communicating
        with it using the spawned bpfd process's stdin and stdout.

        :param cmd: Command to execute for bpfd. If not specified,
                    then we default to search for bpfd in the path.
        :type cmd: str
        """

        # adb server is expected to be connected, either
        # through USB or the network
        self.client = pe.spawn("adb shell")
        time.sleep(2)

        if cmd == None:
            cmd = '/data/bpfd'

        self.client.sendline("su")
        self.client.readline()

        self.client.sendline(cmd)
        self.client.expect('STARTED_BPFD')
