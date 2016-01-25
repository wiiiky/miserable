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
from miserable.utils import Address
from miserable.config import LocalConfigManager
from miserable.eventloop import *
from miserable.log import *


class LocalTransfer(object):

    def __init__(self, loop, caddr, saddr, dns_resolver):
        cfg = LocalConfigManager.get_config()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.SOL_UDP)
        sock.setblocking(False)
        self._socket = sock
        self._loop = loop
        self._caddr = caddr
        self._saddr = saddr
        self._dns_resolver = dns_resolver
        self._raddr = cfg['_remote_address']
        self._encryptor = Encryptor(cfg['password'], cfg['method'])
        self._pending = []

    @property
    def caddr(self):
        return self._caddr

    @property
    def saddr(self):
        return self._saddr

    def start(self, events=POLL_IN):
        self._loop.add(self._socket, events, this)
        self._events = events

    def handle_event(self, sock, fd, event):
        if event & POLL_ERR:
            self.stop(warning='udp %s error' % self.display_name)
            return
        data, addr = self._socket.recvfrom(1 << 16)
        data = self._encryptor.decrypt(data)
        if not data:
            self.stop(warning='udp %s invalid data' % self.display_name)
            return
        self._socket.sendto(data, (self._caddr.compressed, self._caddr.port))

    def write(self, data):
        data = self._encryptor.encrypt(data)
        if self._raddr.ipaddr:
            self._send(data)
        else:
            self._dns_resolver.resolve(self._raddr.hostname,
                                       self._dns_resolved)
            self._pending.append(data)

    def _send(self, data):
        self._socket.sendto(data, (self._raddr.compressed, self._raddr.port))

    def _dns_resolved(self, result, error):
        """remote ip address is resolved"""
        if self._socket is None:
            # ignore DNS resolve callback if transfer already closed
            return
        elif error:
            self.stop(warning=error)
            return
        self._raddr.ipaddr = result[1]
        for data in self._pending:
            self._send(data)
        self._pending = []

    @property
    def display_name(self):
        client = '%s:%s' % (self._caddr.ipaddr, self._caddr.port)
        server = '%s:%s' % (self._saddr.hostname, self._saddr.port)
        return '%s <==> %s' % (client, server)

    def stop(self, info=None, warning=None):
        """stop transfer"""
        if self._socket is None:
            return
        if info:
            INFO(info)
        elif warning:
            WARN(warning)
        self._loop.remove(self._socket)
        self._socket.close()
        self._socket = None
