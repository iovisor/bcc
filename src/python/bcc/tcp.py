# Copyright 2018 Netflix, Inc.
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

# from include/net/tcp_states.h:
tcpstate = {}
tcpstate[1] = 'ESTABLISHED'
tcpstate[2] = 'SYN_SENT'
tcpstate[3] = 'SYN_RECV'
tcpstate[4] = 'FIN_WAIT1'
tcpstate[5] = 'FIN_WAIT2'
tcpstate[6] = 'TIME_WAIT'
tcpstate[7] = 'CLOSE'
tcpstate[8] = 'CLOSE_WAIT'
tcpstate[9] = 'LAST_ACK'
tcpstate[10] = 'LISTEN'
tcpstate[11] = 'CLOSING'
tcpstate[12] = 'NEW_SYN_RECV'

# from include/net/tcp.h:
TCPHDR_FIN = 0x01
TCPHDR_SYN = 0x02
TCPHDR_RST = 0x04
TCPHDR_PSH = 0x08
TCPHDR_ACK = 0x10
TCPHDR_URG = 0x20
TCPHDR_ECE = 0x40
TCPHDR_CWR = 0x80

def flags2str(flags):
    arr = []
    if flags & TCPHDR_FIN:
        arr.append("FIN")
    if flags & TCPHDR_SYN:
        arr.append("SYN")
    if flags & TCPHDR_RST:
        arr.append("RST")
    if flags & TCPHDR_PSH:
        arr.append("PSH")
    if flags & TCPHDR_ACK:
        arr.append("ACK")
    if flags & TCPHDR_URG:
        arr.append("URG")
    if flags & TCPHDR_ECE:
        arr.append("ECE")
    if flags & TCPHDR_CWR:
        arr.append("CWR")
    return "|".join(arr)
