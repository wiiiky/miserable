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


import errno
import socket
import logging
import traceback
from shadowsocks.exceptions import *
from shadowsocks.eventloop import *
from shadowsocks.encrypt import Encryptor
from shadowsocks.shell import print_exception

# SOCKS command definition
class SOCKS5Command(object):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3


class ClienState(object):
    INIT = 0            # waiting for hello message from client
    ADDR = 1
    UDP_ASSOC = 2
    DNS = 3
    CONNECTING = 4
    STREAM = 5
    DESTROYED = -1

class Client(object):

    def __init__(self, sock, addr, encryptor, close_notify):
        self._socket = sock
        self._address = addr
        self._state = ClienState.INIT
        self._encryptor = encryptor
        self._close_notify = close_notify
        self._bufsize = 4096
        self._sendbuf = b''

        self._socket.setblocking(False)
        self._socket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)

    @property
    def socket(self):
        return self._socket

    @property
    def address(self):
        return self._address

    def read(self):
        return self._socket.recv(self._bufsize)

    def write(self, data=b''):
        self._sendbuf += data
        total = len(self._sendbuf)
        n = self._socket.send(self._sendbuf)
        self._sendbuf = self._sendbuf[n:]
        return n

    def close(self):
        self._socket.close()




class TCPTransfer(object):

    def __init__(self, config, loop, sock, addr, dns_resolver):
        self._encryptor = Encryptor(config['password'], config['method'])
        self._loop = loop
        self._client = Client(sock, addr, self._encryptor)
        self._remote = None
        self._dns_resolver = dns_resolver


    def start(self):
        self._loop.add(self._client.socket, POLL_IN | POLL_ERR, self)


    def handle_event(self, sock, fd, event):
        if sock == self._client.socket:
            if event & POLL_ERR:
                self.stop(info='client %s error' % self._client.address)
                return
            self._handle_client(event)


    def _handle_client(self, event):
        if self._client.state == ClienState.INIT:



    def stop(self, info=None, warning=None):
        if info:
            logging.info(info)
        elif warning:
            logging.warning(warning)
        self._loop.remove(self._client.socket)
        self._client.close()
        if self._remote:
            self._loop.remove(self._remote.socket)
            self._remote.close()


class TCPProxy(object):
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
        logging.debug('fd %d %s', fd, eventloop.get_event_display_name(event))
        if event & eventloop.POLL_ERR:
            # TODO
            raise Exception('server_socket error')
        self._accept()

    def _accept(self):
        try:
            client, addr = self._server_socket.accept()
            logging.debug('accept %s' % str(addr))
            transfer = TCPTransfer(self._config, self._loop, client, addr,
                                   self._dns_resolver)
        except (OSError, IOError) as e:
            if errno_from_exception(e) in (errno.EAGAIN, errno.EINPROGRESS,
                                           errno.EWOULDBLOCK):
                return
            else:
                print_exception(e)
                if self._config['verbose']:
                    traceback.print_exc()

    def handle_periodic(self):
        if self._closed:
            if self._server_socket:
                self._loop.remove(self._server_socket)
                self._server_socket.close()
                self._server_socket = None
                logging.info('closed TCP port %d', self._listen_port)
            if not self._fd_to_handlers:
                logging.info('stopping')
                self._eventloop.stop()
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
