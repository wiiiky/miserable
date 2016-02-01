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
from miserable.eventloop import *
from miserable.exception import *
from miserable.utils import Address
from miserable.encrypt import Encryptor
from miserable.protocol import parse_udp_request
from miserable.config import LocalConfigManager
from miserable.udp.transfer import LocalTransfer


class UDPProxy(object):

    def __init__(self, dns_resolver):
        cfg = LocalConfigManager.get_config()
        laddr = cfg['local_address']

        sock = socket.socket(laddr.family, socket.SOCK_DGRAM, socket.SOL_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((laddr.compressed, laddr.port))
        sock.setblocking(False)

        self._loop = None
        self._closed = False
        self._laddr = laddr
        self._dns_resolver = dns_resolver
        self._socket = sock
        self._transfers = set()

    def _find_transfer(self, caddr, saddr):
        for f in self._transfers:
            if f.caddr == caddr and f.saddr == saddr:
                return f
        f = LocalTransfer(self._loop, caddr, saddr, self._dns_resolver)
        f.start()
        self._transfers.add(f)
        return f

    def add_to_loop(self, loop):
        if self._loop or self._closed:
            raise ProgrammingError('illegal status of UDPProxy')
        self._loop = loop
        self._loop.add(self._socket, POLL_IN | POLL_ERR, self)

    def handle_event(self, sock, fd, event):
        data, addr = sock.recvfrom(1 << 16)
        frag, atype, server_addr, server_port, payload = parse_udp_request(
            data)
        transfer = self._find_transfer(
            Address(addr[0], addr[1]), Address(server_addr, server_port))
        transfer.write(data[3:])
