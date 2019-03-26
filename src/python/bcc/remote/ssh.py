# Copyright 2019 Adrian Ratiu <adrian.ratiu@collabora.com>
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

import os, time, sys
import pexpect as pe

from .shell import ShellRemote

class SshRemote(ShellRemote):
    def __init__(self, cmd=None):
        """
        Spawn bpfd on a remote machine via ssh and communicate with its
        stdin/stdout bound to the ssh socket.

        We deliberately do NOT handle ssh authentication and authorization:
        make sure your ssh machines are properly set up from a security POV
        with passwords securely stored in places like ssh/gpg-agents before
        running this code, especially on open networks.

        Also make sure the remote user is capable of accessing the bpf syscall.
        The local user running BCC doesn't need special privileges.

        :param cmd: Command to execute for bpfd. If not specified,
                    then we default to search for bpfd in the path.
        :type cmd: str
        """

        if cmd == None:
            cmd = 'bpfd'

        cmd_env = os.environ.get('BCC_REMOTE_SSH_CMD')
        if cmd_env:
            cmd = cmd_env

        user = os.environ.get('BCC_REMOTE_SSH_USER')
        if user == None:
            print('SSH backend requires BCC_REMOTE_SSH_USER environment variable definition')
            sys.exit(1)

        addr = os.environ.get('BCC_REMOTE_SSH_ADDR')
        if addr == None:
            print('SSH backend requires BCC_REMOTE_SSH_ADDR environment variable definition')
            sys.exit(1)

        port = os.environ.get('BCC_REMOTE_SSH_PORT')
        if port == None:
            port = "22"

        self.client = pe.spawn("ssh -p {} {}@{} {}".format(port, user, addr, cmd))
        self.client.expect('STARTED_BPFD')
