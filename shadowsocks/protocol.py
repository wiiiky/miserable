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

import socket
import struct
import logging

from shadowsocks.utils import *
from shadowsocks.exception import InvalidHeaderException


ADDRTYPE_IPV4 = 1
ADDRTYPE_IPV6 = 4
ADDRTYPE_HOST = 3


def parse_header(data):
    addrtype = data[0]
    dest_addr = None
    dest_port = None
    header_length = 0
    if addrtype == ADDRTYPE_IPV4:
        if len(data) < 7:
            raise InvalidHeaderException('IPv4 header is too short')
        dest_addr = socket.inet_ntoa(data[1:5])
        dest_port = struct.unpack('!H', data[5:7])[0]
        header_length = 7
    elif addrtype == ADDRTYPE_HOST:
        if len(data) <= 2:
            raise InvalidHeaderException('Host header is too short')
        addrlen = data[1]
        if len(data) < 2 + addrlen:
            raise InvalidHeaderException('Host header is too short')

        dest_addr = data[2:2 + addrlen]
        dest_port = struct.unpack('!H', data[2 + addrlen:4 + addrlen])[0]
        header_length = 4 + addrlen
    elif addrtype == ADDRTYPE_IPV6:
        if len(data) < 19:
            raise InvalidHeaderException('IPv6 header is too short')
        dest_addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
        dest_port = struct.unpack('!H', data[17:19])[0]
        header_length = 19
    else:
        raise InvalidHeaderException('unknown header type %s' % addrtype)
    return addrtype, tobytes(dest_addr), dest_port, header_length
