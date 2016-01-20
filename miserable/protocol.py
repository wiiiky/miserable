# encoding=utf8
#
# Copyright 2015 Wiky L
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import socket
import struct

from miserable.utils import *
from miserable.exception import *


"""
https://www.ietf.org/rfc/rfc1928.txt
"""


# SOCKS command definition
class SOCKS5Command(object):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3

ADDRTYPE_IPV4 = 1
ADDRTYPE_IPV6 = 4
ADDRTYPE_DOMAIN = 3


def parse_tcp_request(data):
    """parse SOCKS5 request"""
    vsn = data[0]
    cmd = data[1]
    if vsn != 5:
        raise InvalidSockVersionException(vsn)
    elif cmd not in (SOCKS5Command.CONNECT, SOCKS5Command.BIND,
                     SOCKS5Command.UDP_ASSOCIATE):
        raise InvalidRequestException('invalid request command')

    data = data[3:]     # skip vsn,cmd,rsv
    atype = data[0]
    if atype == ADDRTYPE_IPV4:
        dest_addr = socket.inet_ntop(socket.AF_INET, data[1:5])
        dest_port = struct.unpack('!H', data[5:7])[0]
    elif atype == ADDRTYPE_IPV6:
        dest_addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
        dest_port = struct.unpack('!H', data[17:19])[0]
    elif atype == ADDRTYPE_DOMAIN:
        dlen = data[1]
        dest_addr = data[2:2 + dlen]
        dest_port = struct.unpack('!H', data[2 + dlen:4 + dlen])[0]
    else:
        raise InvalidRequestException('unknown address type')
    return vsn, cmd, atype, dest_addr, dest_port


def build_tcp_reply(vsn, rep, rsv, addr, port):
    """build a SOCKS5 reply"""
    atype = 1 if addr.family == socket.AF_INET else 4
    data = struct.pack('!BBBB', vsn, rep, rsv, atype) + addr.packed\
        + struct.pack('!H', port)
    return data
