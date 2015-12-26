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
import struct
import logging
import traceback
from shadowsocks.exception import *
from shadowsocks.eventloop import *
from shadowsocks.decorator import *
from shadowsocks.encrypt import Encryptor
from shadowsocks.shell import print_exception
from shadowsocks.common import parse_header


# SOCKS command definition
class SOCKS5Command(object):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3


class ClientState(object):
    INIT = 0            # waiting for hello message from client
    ADDR = 1
    UDP_ASSOC = 2
    DNS = 3
    CONNECTING = 4
    CONNECTED = 5


class Peer(object):

    def __init__(self, sock, addr, loop, encryptor=None):
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
        return self._encryptor.encrypt(data)

    def decrypt(self, data):
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
        if not self.connected:
            return None
        return self._socket.recv(self._bufsize)

    def write(self, data=b''):
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
            self._events |= POLL_OUT
            self._loop.modify(self._socket, self._events)
        elif not self._sendbuf and (self._events & POLL_OUT):
            self._events ^= POLL_OUT
            self._loop.modify(self._socket, self._events)

    def close(self):
        self._socket.close()


class Client(Peer):

    def __init__(self, sock, addr, loop, encryptor=None):
        super(Client, self).__init__(sock, addr, loop, encryptor)
        self._state = ClientState.INIT

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, state):
        self._state = state


class RemoteState(object):

    DNS = 1
    CONNECTING = 2
    CONNECTED = 3


class Remote(Peer):

    def __init__(self, sock, addr, loop, encryptor=None):
        super(Remote, self).__init__(sock, addr, loop, encryptor)
        self._state = RemoteState.DNS

    def connect(self, addr):
        try:
            return self._socket.connect(addr)
        except (OSError, IOError) as e:
            if errno_from_exception(e) == errno.EINPROGRESS:
                return
            raise e

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, state):
        self._state = state

    def read(self):
        data = super(Remote, self).read()
        if data:
            data = self.decrypt(data)
        return data

    def write(self, data=b''):
        if data:
            data = self.encrypt(data)
        return super(Remote, self).write(data)


class TCPTransfer(object):

    def __init__(self, config, loop, sock, addr, dns_resolver):
        self._cfg_password = config['password']
        self._cfg_method = config['method']
        self._cfg_server = config['server']
        self._cfg_server_port = config['server_port']
        self._cfg_verbose = config['verbose']

        self._encryptor = Encryptor(self._cfg_password, self._cfg_method)
        self._loop = loop
        self._client = Client(sock, addr, loop, self._encryptor)
        self._remote_address = (self._cfg_server, self._cfg_server_port)
        self._remote = None
        self._server_address = None
        self._dns_resolver = dns_resolver

    def start(self):
        self._client.start(POLL_IN | POLL_ERR, self)

    def handle_event(self, sock, fd, event):
        if sock == self._client.socket:
            if event & POLL_ERR:
                self.stop(info='client %s:%s error' % self._client.address)
                return
            self._handle_client(event)
        elif sock == self._remote.socket:
            if event & POLL_ERR:
                self.stop(info='remote %s:%s error' % self._remote.address)
                return
            self._handle_remote(event)

    @stop_transfer_if_fail
    def _handle_client(self, event):
        data = None
        if event & POLL_IN:
            data = self._client.read()
            if data == b'':
                self.stop(info='client %s:%s closed' % self._client.address)
                return

        if self._client.state in (ClientState.INIT, ClientState.ADDR)\
                and not data:
            self.stop(info='client %s:%s closed' % self._client.address)
            return

        if self._client.state == ClientState.INIT:
            # Shall we verify the HELLO message from client?
            self._client.write(b'\x05\00')  # HELLO
            self._client.state = ClientState.ADDR
        elif self._client.state == ClientState.ADDR:
            vsn = data[0]
            cmd = data[1]
            if vsn != 5:
                raise InvalidSockVersionException(vsn)
            if cmd == SOCKS5Command.UDP_ASSOCIATE:
                logging.debug('UDP associate')
                family = self._client.socket.family
                if family == socket.AF_INET6:
                    header = b'\x05\x00\x00\x04'
                else:
                    header = b'\x05\x00\x00\x01'
                addr, port = self._client.address
                addr_to_send = socket.inet_pton(family, addr)
                port_to_send = struct.pack('!H', port)
                self._client.write(header + addr_to_send + port_to_send)
                self._client.stage = STAGE_UDP_ASSOC
                # just wait for the client to disconnect
                return
            elif cmd != SOCKS5Command.CONNECT:
                raise UnknownCommandException(cmd)
            else:
                # just trim VER CMD RSV
                data = data[3:]
            addrtype, server_addr, server_port, length = parse_header(data)
            logging.info('connecting %s:%d from %s:%d' %
                         (server_addr, server_port, self._client.address[0],
                          self._client.address[1]))
            self._server_address = (server_addr, server_port)
            # forward address to remote
            self._client.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x10\x10')
            self._client.state = ClientState.DNS
            self._remote = Remote(None, self._remote_address, self._loop,
                                  self._encryptor)
            self._remote.write(data)
            self._dns_resolver.resolve(self._remote_address[0],
                                       self._dns_resolved)
        elif data and self._remote:
            self._remote.write(data)

    @stop_transfer_if_fail
    def _handle_remote(self, event):

        if event & POLL_IN:
            data = self._remote.read()
            if data is b'':
                self.stop(info=('remote %s:%s closed' % self._remote.address))
                return
            self._client.write(data)

        if event & POLL_OUT:
            self._remote.write()
            self._remote.state = RemoteState.CONNECTED
            self._client.state = ClientState.CONNECTED

    @stop_transfer_if_fail
    def _dns_resolved(self, result, error):
        if error:
            self.stop(warning=error)
            return
        ip = result[1]
        port = self._remote_address[1]

        addrs = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM,
                                   socket.SOL_TCP)
        af, socktype, proto, canonname, sa = addrs[0]
        sock = socket.socket(af, socktype, proto)
        self._remote.socket = sock
        self._remote.connect((ip, port))
        self._remote.start(POLL_ERR | POLL_OUT | POLL_IN, self)
        self._remote.state = RemoteState.CONNECTING

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
        if event & POLL_ERR:
            # TODO
            raise Exception('server_socket error')
        self._accept()

    @return_val_if_wouldblock(None)
    def _accept(self):
        client, addr = self._server_socket.accept()
        logging.debug('accept %s' % str(addr))
        transfer = TCPTransfer(self._config, self._loop, client, addr,
                               self._dns_resolver)
        transfer.start()

    def handle_periodic(self):
        if self._closed:
            if self._server_socket:
                self._loop.remove(self._server_socket)
                self._server_socket.close()
                self._server_socket = None
                logging.info('closed TCP port %d', self._listen_port)
            if not self._fd_to_handlers:
                logging.info('stopping')
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
