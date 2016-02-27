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
import time
from miserable.utils import Address
from miserable.config import LocalConfigManager
from miserable.loop import MainLoop
from miserable.encrypt import *
from miserable.log import *


class LocalTransfer(object):

    def __init__(self, loop, caddr, saddr, dns_resolver):
        cfg = LocalConfigManager.get_config()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.SOL_UDP)
        self._socket = sock
        self._loop = loop
        self._caddr = caddr
        self._saddr = saddr
        self._dns_resolver = dns_resolver
        self._last_active = time.time()
        self._raddr = cfg['remote_address']
        self._password = cfg['password']
        self._method = cfg['method']
        self._pending = []

    @property
    def closed(self):
        return self._socket is None

    @property
    def last_active(self):
        return self._last_active

    @property
    def caddr(self):
        return self._caddr

    @property
    def saddr(self):
        return self._saddr

    def start(self, events=MainLoop.EVENT_READ):
        self._loop.register(self._socket, events, self.handle_event)

    def handle_event(self, sock, event):
        """receive package from remote, transfer to client"""
        if event & MainLoop.EVENT_ERROR:
            self.stop(warning='udp %s error' % self.display_name)
            return
        self._last_active = time.time()
        data, addr = self._socket.recvfrom(1 << 16)
        data = encrypt_all(self._password, self._method, 0, data)
        if not data:
            self.stop(warning='udp %s invalid data' % self.display_name)
            return
        DEBUG('UDP forward from %s to %s' %
              (self._saddr.display, self._caddr.display))
        self._socket.sendto(b'\x00\x00\x00' + data,
                            (self._caddr.compressed, self._caddr.port))

    def write(self, data):
        self._last_active = time.time()
        data = encrypt_all(self._password, self._method, 1, data)
        if self._raddr.ipaddr:
            self._send(data)
        else:
            self._pending.append(data)
            self._dns_resolver.resolve(
                self._raddr.hostname, self._dns_resolved)

    def _send(self, data):
        DEBUG('UDP forward from %s to %s' %
              (self._caddr.display, self._saddr.display))
        self._socket.sendto(data, (self._raddr.compressed, self._raddr.port))

    def _dns_resolved(self, result, error):
        """remote ip address is resolved"""
        if self._socket is None:
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
        self._loop.unregister(self._socket)
        self._socket.close()
        self._socket = None
