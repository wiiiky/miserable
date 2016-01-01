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
from miserable.exception import *
from miserable.eventloop import *

from miserable.tcp.peer import return_val_if_wouldblock
from miserable.tcp.transfer import LocalTransfer
from miserable.config import LocalConfig


class TCPProxy(object):
    """Shadowsocks TCP proxy"""

    def __init__(self, dns_resolver):
        cfg = LocalConfig.get_config()
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
        self._local_address = laddr
        self._socket = sock
        self._loop = None
        self._closed = False
        self._timeout = cfg['timeout']
        self._transfers = []

    def add_to_loop(self, loop):
        if self._loop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._loop = loop
        self._loop.add(self._socket, POLL_IN | POLL_ERR, self)
        self._loop.add_periodic(self.handle_periodic)

    def handle_event(self, sock, fd, event):
        # handle events and dispatch to handlers
        if event & POLL_ERR:
            raise UnexpectedEventError('local server error!!!')
        self._accept()

    @return_val_if_wouldblock(None)
    def _accept(self):
        client, addr = self._socket.accept()
        DEBUG('accept %s:%s' % addr)
        transfer = LocalTransfer(self._loop, client, addr, self._dns_resolver)
        transfer.start()
        self._transfers.append(transfer)

    def handle_periodic(self):
        if self._closed:
            self._close()
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

    def close(self, next_tick=False):
        self._closed = True
        if not next_tick:
            self._close()

    def _close(self):
        if self._socket is None:
            return
        INFO('close TCP %s:%s' %
             (self._local_address, self._local_address.port))
        self._loop.remove(self._socket)
        self._socket.close()
        self._socket = None
        self._loop.stop()
