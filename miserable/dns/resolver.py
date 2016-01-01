#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2014-2015 clowwindy
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

import os
import socket

from miserable import eventloop
from miserable.log import *
from miserable.cache import LRUCache
from miserable.dns.protocol import *
from miserable.dns.utils import *
from miserable.utils import *


CACHE_SWEEP_INTERVAL = 30


class Socket(socket.socket):

    def __init__(self, servers, timeout=60):
        """
        use IPv6 socket
        convert the ipv4 address to ipv4-mapped ipv6 address
        """
        self._id = 0
        self._wait4 = {}
        self._wait6 = {}
        self._timeout = timeout
        self._servers = [ipv6_address(s) for s in servers]\
            if hasattr(servers, '__iter__') else [ipv6_address(servers)]
        super(Socket, self).__init__(socket.AF_INET6, socket.SOCK_DGRAM,
                                     socket.SOL_UDP)

    def recvfrom(self, bufsize):
        data, addrinfo = super(Socket, self).recvfrom(bufsize)
        return data, ip_address(addrinfo[0])

    def send_dns_request(self, hostname):
        """send IPv6 and IPv4 DNS query at the same time"""
        request4 = Request(hostname, TYPE.A, mid=self._id)
        request6 = Request(hostname, TYPE.AAAA, mid=self._id)
        for saddr in self._servers:
            self.sendto(request4.bytes, (saddr.compressed, 53))
            self.sendto(request6.bytes, (saddr.compressed, 53))
        self._wait4[self._id] = time.time()
        self._wait6[self._id] = time.time()
        self._increase_id()

    def recv_dns_response(self):
        """receive and parse DNS response
        """
        self._check_timeout()
        data, addr = self.recvfrom(1024)
        if not self. _check_server(addr):
            DEBUG('receive DNS response from unknown server %s' % addr)
            return
        response = Response(data)
        DEBUG('receive DNS response %s ' % response)
        if response.mid in self._wait4 and response.qtype == TYPE.A:
            del self._wait4[response.mid]
            if response.is_valid() and response.mid in self._wait6:
                """if this is a valid IPv4 response then we ignore IPv6"""
                del self._wait6[response.mid]
            return response
        elif response.mid in self._wait6 and response.qtype == TYPE.AAAA:
            del self._wait6[response.mid]
            if response.is_valid() and response.mid in self._wait4:
                """if this is a valid IPv6 response then we ignore IPv4"""
                del self._wait4[response.mid]
            return response
        return None

    def _increase_id(self):
        self._id += 1
        if self._id > 65535:
            """two bytes for message ID"""
            self._id = 0

    def _check_timeout(self):
        now = time.time()

        def kick(wait):
            for mid, t in list(wait.items()):
                if now - t > self._timeout:
                    del wait[mid]
        kick(self._wait4)
        kick(self._wait6)

    def _check_server(self, addr):
        for server in self._servers:
            if server.compressed == addr.compressed:
                return True
        return False


class DNSResolver(object):

    def __init__(self):
        self._loop = None
        self._hosts = load_hosts_conf()
        self._servers = load_resolv_conf()
        self._callbacks = {}
        self._cache = LRUCache(timeout=300, **self._hosts)
        self._sock = None
        # TODO monitor hosts change and reload hosts
        # TODO parse /etc/gai.conf and follow its rules

    def _refresh(self):
        # create or refresh DNS socket
        self._sock = Socket(self._servers)
        self._sock.setblocking(False)
        self._loop.add(self._sock, eventloop.POLL_IN, self)

    def add_to_loop(self, loop):
        if self._loop:
            raise Exception('already add to loop')
        self._loop = loop
        self._refresh()
        loop.add_periodic(self.handle_periodic)

    def _call_callback(self, hostname, ipaddr, error=None):
        DEBUG('DNS callback %s:%s' % (hostname, ipaddr))
        for callback in self._callbacks.get(hostname, []):
            if ipaddr or error:
                callback((hostname, ipaddr), error)
            else:
                callback((hostname, None),
                         Exception('unknown hostname %s' % hostname))
        if hostname in self._callbacks:
            del self._callbacks[hostname]

    def _send_request(self, hostname):
        DEBUG('query DNS %s' % hostname)
        self._sock.send_dns_request(hostname)

    def _handle_response(self, response):
        if not response:
            return
        if response.is_valid():
            self._cache[response.hostname] = response.answer
        self._call_callback(response.hostname, response.answer)

    def handle_event(self, sock, fd, event):
        if sock != self._sock:
            return
        if event & eventloop.POLL_ERR:
            ERROR('dns socket error')
            self._loop.remove(self._sock)
            self._sock.close()
            self._refresh()
        elif event & eventloop.POLL_IN:
            response = sock.recv_dns_response()
            self._handle_response(response)

    def handle_periodic(self):
        self._cache.sweep()

    def resolve(self, host, callback):
        hostname = tobytes(host)
        if not hostname or not check_hostname(hostname):
            callback(None, Exception('invalid hostname: %s' % hostname))
        elif ip_address(hostname):
            callback((hostname, hostname), None)
        elif hostname in self._cache:
            DEBUG('hit cache: %s' % host)
            ip = self._cache[hostname]
            callback((hostname, ip), None)
        else:
            arr = self._callbacks.get(hostname, None)
            if not arr:
                self._callbacks[hostname] = [callback]
                self._send_request(hostname)
            else:
                arr.append(callback)
                # TODO send again only if waited too long
                self._send_request(hostname)

    def close(self):
        if self._sock:
            if self._loop:
                self._loop.remove_periodic(self.handle_periodic)
                self._loop.remove(self._sock)
            self._sock.close()
            self._sock = None
