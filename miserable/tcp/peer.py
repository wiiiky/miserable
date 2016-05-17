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
from miserable.loop import MainLoop
from miserable.utils import return_val_if_wouldblock


class Peer(object):
    """
    The base class that manages connection to specific peer.
    """

    def __init__(self, sock, addr, loop, encryptor=None, bufsize=4096):
        """
        @sock the socket connected to the peer
        @addr (address, port) tuple
        @loop eventloop
        @encryptor
        """
        self._socket = sock
        self._addr = addr
        self._encryptor = encryptor
        self._bufsize = bufsize
        self._wbuf = b''
        self._loop = loop
        self._events = 0

        if self._socket:
            self._socket.setblocking(False)
            self._socket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

    def encrypt(self, data):
        """shortcut for encrypt """
        return self._encryptor.encrypt(data)

    def decrypt(self, data):
        """shortcut for decrypt"""
        return self._encryptor.decrypt(data)

    def start(self, events, func):
        self._loop.register(self._socket, events, func)
        self._events = events

    @property
    def connected(self):
        return self._socket is not None

    @property
    def socket(self):
        return self._socket

    @socket.setter
    def socket(self, sock):
        self._socket = sock
        self._socket.setblocking(False)
        self._socket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

    @property
    def address(self):
        return self._addr

    @property
    def ipaddr(self):
        return self._addr.ipaddr

    @property
    def port(self):
        return self._addr.port

    @return_val_if_wouldblock(None)
    def read(self):
        """
        returns None if recv would block
        returns b'' if closed
        returns data that recv
        """
        if not self.connected:
            return None
        return self._socket.recv(self._bufsize)

    def write(self, data=b''):
        """write data if connected or buffer data"""
        data = data or b''
        self._wbuf += data
        if not self.connected:
            return 0
        self._write()

        if self._wbuf and not (self._events & MainLoop.EVENT_WRITE):
            """
            not all data sent,
            monitor the EVENT_WRITE event so we can send them next time
            """
            self._events |= MainLoop.EVENT_WRITE
            self._loop.modify(self._socket, self._events)
        elif not self._wbuf and (self._events & MainLoop.EVENT_WRITE):
            """
            all data sent, but EVENT_WRITE is monitored,
            to avoid necessary EVENT_WRITE event, remove EVENT_WRITE.
            """
            self._events ^= MainLoop.EVENT_WRITE
            self._loop.modify(self._socket, self._events)

    @return_val_if_wouldblock(0)
    def _write(self):
        if not self._wbuf:
            return 0
        n = self._socket.send(self._wbuf)
        self._wbuf = self._wbuf[n:]
        return n

    def close(self):
        if self._socket and self._events:
            self._loop.unregister(self._socket)
            self._socket.close()
