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
import logging
from shadowsocks.exception import *
from shadowsocks.decorator import *
from shadowsocks.eventloop import *

from .transfer import LocalTransfer


class Proxy(object):
    """Shadowsocks TCP proxy"""

    def __init__(self, config, dns_resolver):
        addr = config['local_address']
        port = config['local_port']

        address = socket.getaddrinfo(addr, port, 0, socket.SOCK_STREAM,
                                     socket.SOL_TCP)
        if not address:
            raise InvalidAddressException(addr, port)

        af, socktype, proto, canonname, sa = address[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(sa)
        server_socket.setblocking(False)

        if config['fast_open']:
            if not hasattr(socket, 'TCP_FASTOPEN'):
                raise UnsupportFeatureException('TCP Fast Open')
            server_socket.setsockopt(socket.SOL_SOCKET, socket.TCP_FASTOPEN, 5)
        server_socket.listen(1024)

        self._config = config
        self._dns_resolver = dns_resolver
        self._address = (addr, port)
        self._server_socket = server_socket
        self._loop = None
        self._closed = False

    def add_to_loop(self, loop):
        if self._loop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._loop = loop
        self._loop.add(self._server_socket, POLL_IN | POLL_ERR, self)
        self._loop.add_periodic(self.handle_periodic)

    def handle_event(self, sock, fd, event):
        # handle events and dispatch to handlers
        if event & POLL_ERR:
            # TODO
            raise Exception('server_socket error')
        self._accept()

    @return_val_if_wouldblock(None)
    def _accept(self):
        client, addr = self._server_socket.accept()
        logging.debug('accept %s' % str(addr))
        transfer = LocalTransfer(self._config, self._loop, client, addr,
                                 self._dns_resolver)
        transfer.start()

    def handle_periodic(self):
        if self._closed:
            if self._server_socket:
                self._loop.remove(self._server_socket)
                self._server_socket.close()
                self._server_socket = None
                logging.info('closed TCP %s:%s' % self._address)
            self._loop.stop()
        self._sweep_timeout()

    def _sweep_timeout(self):
        """TODO"""
        pass

    def close(self, next_tick=False):
        logging.debug('TCP close')
        self._closed = True
        if not next_tick:
            if self._loop:
                self._loop.remove_periodic(self.handle_periodic)
                self._loop.remove(self._server_socket)
            self._server_socket.close()
