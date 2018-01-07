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

class BccRemote(object):
    """
    Abstract Class for BccRemote connection classes
    This defines the API implementation for remotes such
    as networking or shell based remote bcc connections
    """

    def __init__(self, arg):
        """
        Initialize of remote connection

        A remote class should override this and provide an __init__
        function that establishes a connection to a remote, or
        raises an error.

        :param arg: An argument string specific to the remote
        :type arg: str
        """
        pass

    def send_command(self, cmd):
        """
        Abstract function to send a command to a remote

        :param cmd: Command to send.
        :type cmd: str

        :return: Output of the command.
        :rtype: List of strings, one for each line of command output.
        """
        raise NotImplementedError('subclasses must override class!')

    def close_connection(self):
        """
        Abstraction function to close a remote connection.

        Remote classes should override this function and tear down
        an initialized remote connection
        """
        raise NotImplementedError('subclasses must override class!')

