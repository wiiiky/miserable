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


import time
import socket
from miserable.log import *
from miserable.utils import *
from miserable.exception import *
from miserable.loop import MainLoop

from miserable.tcp.transfer import LocalTransfer
from miserable.config import LocalConfigManager


class TCPProxy(object):
    """Shadowsocks TCP proxy"""

    def __init__(self, dns_resolver, loop):
        cfg = LocalConfigManager.get_config()
        laddr = cfg['local_address']

        sock = socket.socket(laddr.family, socket.SOCK_STREAM, socket.SOL_TCP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((laddr.compressed, laddr.port))
        sock.setblocking(False)

        if cfg['fast_open']:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.TCP_FASTOPEN, 5)
            except (OSError, AttributeError) as e:
                raise UnsupportFeatureException('TCP Fast Open')
            VERBOSE('fast open enabled!')
        sock.listen(1024)

        self._dns_resolver = dns_resolver
        self._laddr = laddr
        self._socket = sock
        self._loop = loop
        self._timeout = cfg['timeout']
        self._transfers = []

        self._register_to_loop()

    def _register_to_loop(self):
        self._loop.register(self._socket, MainLoop.EVENT_READ,
                            self.handle_event)
        self._loop.add_timeout(self._handle_timeout, 5)

    def handle_event(self, sock, event):
        # handle events and dispatch to handlers
        if event & MainLoop.EVENT_ERROR:
            raise UnexpectedEventError('local server error!!!')
        self._accept()

    @return_val_if_wouldblock(None)
    def _accept(self):
        client, addr = self._socket.accept()
        addr = Address(addr[0], addr[1])
        DEBUG('accept %s:%s' % (addr.ipaddr, addr.port))
        transfer = LocalTransfer(self._loop, client, addr, self._dns_resolver)
        transfer.start()
        self._transfers.append(transfer)

    def _handle_timeout(self):
        if self.closed:
            return
        self._check_timeout()

    def _check_timeout(self):
        """
        check timeout connections and close them
        """
        now = time.time()
        transfers = []
        for t in self._transfers:
            if t.closed:    # skip closed transfer
                continue
            if now - t.last_active > self._timeout:
                t.stop(info='%s is timeout' % t.display_name)
            else:
                transfers.append(t)
        self._transfers = transfers

    @property
    def closed(self):
        return self._socket is None

    def close(self):
        if self.closed:
            return
        INFO('close TCP %s' % self._laddr.display)
        self._loop.remove_timeout(self._handle_timeout)
        self._loop.unregister(self._socket)
        self._socket.close()
        self._socket = None
