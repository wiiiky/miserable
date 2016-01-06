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
from miserable.eventloop import *
from miserable.protocol import *
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
#            import traceback
#            traceback.print_exc()
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
        self._server_address = None
        self._dns_resolver = dns_resolver
        self._last_active = time.time()
        self._remote_address = cfg['remote_address']
        self._local_address = cfg['local_address']

    @property
    def closed(self):
        return self._client is None

    @property
    def last_active(self):
        return self._last_active

    @property
    def display_name(self):
        client = '%s:%s' % (self._client.ipaddr, self._client.port)
        if self._server_address:
            server = '%s:%s' % (self._server_address.ipaddr,
                                self._server_address.port)
        else:
            server = 'None'
        return '%s <==> %s' % (client, server)

    def start(self):
        self._client.start(POLL_IN | POLL_ERR, self)

    def handle_event(self, sock, fd, event):
        self._last_active = time.time()
        if sock == self._client.socket:
            if event & POLL_ERR:
                self.stop(warning='client %s:%s error' %
                          (self._client.ipaddr, self._client.port))
                return
            self._handle_client(event)
        elif sock == self._remote.socket:
            if event & POLL_ERR:
                self.stop(warning='remote %s:%s error' %
                          (self._client.ipaddr, self._client.port))
                return
            self._handle_remote(event)

    @stop_transfer_if_fail
    def _handle_client(self, event):
        """handle the client events"""
        data = None
        if event & POLL_IN:
            data = self._client.read()
            if data == b'':
                self.stop(info='client %s:%s closed' %
                          (self._client.ipaddr, self._client.port))
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
            vsn, cmd, atype, server_addr, server_port = parse_request(data)
            if cmd == SOCKS5Command.UDP_ASSOCIATE:
                DEBUG('UDP associate')
                self._client.write(build_reply(5, 0, 0,
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
            self._server_address = Address(server_addr, server_port)
            # forward address to remote
            self._client.write(build_reply(5, 0, 0, self._local_address.ipaddr,
                                           self._local_address.port))
            self._client.state = ClientState.DNS
            self._remote = Remote(None, self._remote_address, self._loop,
                                  self._encryptor)
            self._remote.write(data[3:])
            if self._remote_address.ipaddr:
                self._connect_to_remote()
            else:
                self._dns_resolver.resolve(self._remote_address.hostname,
                                           self._dns_resolved)
        elif data and self._remote:
            self._remote.write(data)
        if event & POLL_OUT:
            """some data unsent"""
            self._client.write()

    @stop_transfer_if_fail
    def _handle_remote(self, event):
        """handle remote events"""
        if event & POLL_IN:
            data = self._remote.read()
            if data == b'':
                self.stop(info=('remote %s:%s closed' %
                                (self._server_address.hostname,
                                 self._server_address.port)))
                return
            self._client.write(data)

        if event & POLL_OUT:
            self._remote.write()
            self._client.state = ClientState.CONNECTED

    @stop_transfer_if_fail
    def _dns_resolved(self, result, error):
        """remote ip address is resolved"""
        if error:
            self.stop(warning=error)
            return
        self._remote_address.ipaddr = result[1]
        self._connect_to_remote()

    def _connect_to_remote(self):
        ipaddr = self._remote_address.ipaddr
        port = self._remote_address.port
        self._remote.socket = socket.socket(ipaddr.family, socket.SOCK_STREAM,
                                            socket.SOL_TCP)
        self._remote.connect((ipaddr.compressed, port))
        self._remote.start(POLL_ERR | POLL_OUT | POLL_IN, self)

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
