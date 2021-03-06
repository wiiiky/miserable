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
import struct
from miserable.log import *
from miserable.utils import *
from miserable.exception import *
from miserable.protocol import *
from miserable.loop import MainLoop
from miserable.encrypt import Encryptor

from miserable.tcp.client import ClientState, Client
from miserable.tcp.remote import Remote
from miserable.config import LocalConfigManager


def stop_transfer_if_fail(f):
    """stop transfer if unexpected exception occurs"""
    def wrapper(transfer, *args, **kwargs):
        try:
            return f(transfer, *args, **kwargs)
        except Exception as e:
            transfer.stop(warning='%s closed because of %s' %
                          (transfer.display_name, str(e)))
            import traceback
            traceback.print_exc()
    return wrapper


class LocalTransfer(object):
    """
    client <==> local <==> remote
    """

    def __init__(self, loop, sock, addr, dns_resolver):
        cfg = LocalConfigManager.get_config()

        self._encryptor = Encryptor(cfg['password'], cfg['method'])
        self._loop = loop
        self._client = Client(sock, addr, loop, self._encryptor)
        self._remote = None
        self._dns_resolver = dns_resolver
        self._last_active = time.time()
        self._raddr = cfg['remote_address']
        self._laddr = cfg['local_address']
        self._saddr = None

    @property
    def closed(self):
        return self._client is None

    @property
    def last_active(self):
        return self._last_active

    @property
    def display_name(self):
        client = '%s:%s' % (self._client.ipaddr, self._client.port)
        if self._saddr is not None:
            server = '%s:%s' % (self._saddr.hostname,
                                self._saddr.port)
        else:
            server = 'None'
        return '%s <==> %s' % (client, server)

    def start(self):
        self._client.start(MainLoop.EVENT_READ, self.handle_event)

    def handle_event(self, sock, event):
        if self.closed:
            return
        self._last_active = time.time()
        if sock == self._client.socket:
            if event & MainLoop.EVENT_ERROR:
                self.stop(warning='client %s:%s error' %
                          (self._client.ipaddr, self._client.port))
                return
            self._handle_client(event)
        elif sock == self._remote.socket:
            if event & MainLoop.EVENT_ERROR:
                self.stop(warning='remote %s:%s error' %
                          (self._remote.ipaddr, self._remote.port))
                return
            self._handle_remote(event)

    @stop_transfer_if_fail
    def _handle_client(self, event):
        """handle the client events"""
        data = None
        if event & MainLoop.EVENT_READ:
            data = self._client.read()
            if data == b'':
                self.stop(info='%s closed by client' % self.display_name)
                return

        if self._client.state == ClientState.UDP_ASSOC:
            return
        elif self._client.state in (ClientState.INIT, ClientState.ADDR)\
                and not data:
            """in state INIT or ADDR, supposed to receive data from client"""
            self.stop(info='client %s:%s closed' %
                      (self._client.ipaddr, self._client.port))
            return

        if self._client.state == ClientState.INIT:
            """
            receive HELLO message from client, shall we verify it ?
            send a HELLO back
            """
            self._client.write(b'\x05\00')  # HELLO
            self._client.state = ClientState.ADDR
        elif self._client.state == ClientState.ADDR:
            """
            receive the server addr,
            give client a feedback and connect to remote
            """
            vsn, cmd, atype, server_addr, server_port = parse_tcp_request(data)
            if cmd == SOCKS5Command.UDP_ASSOCIATE:
                DEBUG('UDP associate')
                self._client.write(build_tcp_reply(5, 0, 0,
                                                   self._client.ipaddr,
                                                   self._client.port))
                self._client.state = ClientState.UDP_ASSOC
                # just wait for the client to disconnect
                return
            elif cmd != SOCKS5Command.CONNECT:
                raise UnknownCommandException(cmd)

            server_addr = tostr(server_addr)
            INFO('connecting %s:%d from %s:%d' %
                 (server_addr, server_port, self._client.ipaddr,
                  self._client.port))
            self._saddr = Address(server_addr, server_port)
            # forward address to remote
            self._client.write(build_tcp_reply(5, 0, 0, self._laddr.ipaddr,
                                               self._laddr.port))
            self._client.state = ClientState.DNS
            self._remote = Remote(None, self._raddr, self._loop,
                                  self._encryptor)
            self._remote.write(data[3:])
            if self._raddr.ipaddr:     # ipaddr
                self._connect_to_remote()
            else:
                self._dns_resolver.resolve(self._raddr.hostname,
                                           self._dns_resolved)
        elif data and self._remote:
            self._remote.write(data)
        if event & MainLoop.EVENT_WRITE:
            """some data unsent"""
            self._client.write()

    @stop_transfer_if_fail
    def _handle_remote(self, event):
        """handle remote events"""
        if event & MainLoop.EVENT_READ:
            data = self._remote.read()
            if data == b'':
                self.stop(info='%s closed by remote' % self.display_name)
                return
            self._client.write(data)

        if event & MainLoop.EVENT_WRITE:
            self._remote.write()
            self._client.state = ClientState.CONNECTED

    @stop_transfer_if_fail
    def _dns_resolved(self, result, error):
        """remote ip address is resolved"""
        if self._client is None:
            # ignore DNS resolve callback if transfer already closed
            return
        elif error:
            self.stop(warning=error)
            return
        self._raddr.ipaddr = result[1]
        self._connect_to_remote()

    def _connect_to_remote(self):
        ipaddr = self._raddr.ipaddr
        port = self._raddr.port
        self._remote.socket = socket.socket(ipaddr.family, socket.SOCK_STREAM,
                                            socket.SOL_TCP)
        self._remote.connect((ipaddr.compressed, port))
        self._remote.start(MainLoop.EVENT_READ | MainLoop.EVENT_WRITE,
                           self.handle_event)

    def stop(self, info=None, warning=None):
        """stop transfer"""
        if self._client is None:
            return
        if info:
            INFO(info)
        elif warning:
            WARN(warning)
        self._client.close()
        self._client = None
        if self._remote:
            self._remote.close()
