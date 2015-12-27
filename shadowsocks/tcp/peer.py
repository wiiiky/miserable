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
from shadowsocks.eventloop import *
from shadowsocks.exception import *


class return_val_if_wouldblock(object):

    def __init__(self, value):
        self._value = value

    def __call__(self, f):
        def wrapper(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except (OSError, IOError) as e:
                if exception_wouldblock(e):
                    return self._value
                raise e
        return wrapper


class Peer(object):
    """
    The base class that manages connection to specific peer.
    """

    def __init__(self, sock, addr, loop, encryptor=None):
        """
        @sock the socket connected to the peer
        @addr (address, port) tuple
        @loop eventloop
        @encryptor
        """
        self._socket = sock
        self._address = addr
        self._encryptor = encryptor
        self._bufsize = 4096
        self._sendbuf = b''
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

    def start(self, events, manager):
        self._events = events
        self._loop.add(self._socket, self._events, manager)

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
        return self._address

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
        self._sendbuf += data
        if not self.connected:
            return
        if self._sendbuf:
            try:
                total = len(self._sendbuf)
                n = self._socket.send(self._sendbuf)
                self._sendbuf = self._sendbuf[n:]
            except (OSError, IOError) as e:
                if not exception_wouldblock(e):
                    raise e

        if self._sendbuf and not (self._events & POLL_OUT):
            """
            not all data sent,
            monitor the POLL_OUT event so we can send them next time
            """
            self._events |= POLL_OUT
            self._loop.modify(self._socket, self._events)
        elif not self._sendbuf and (self._events & POLL_OUT):
            """
            all data sent, but POLL_OUT is monitored,
            to avoid necessary POLL_OUT event, remove POLL_OUT.
            """
            self._events ^= POLL_OUT
            self._loop.modify(self._socket, self._events)

    def close(self):
        if self._socket:
            self._loop.remove(self._socket)
            self._socket.close()
