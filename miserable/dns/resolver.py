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
import struct

from miserable import eventloop
from miserable.log import *
from miserable.cache import LRUCache
from miserable.dns.protocol import *
from miserable.utils import *


CACHE_SWEEP_INTERVAL = 30


STATUS_IPV4 = 0
STATUS_IPV6 = 1


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
        self._sock = DNSSocket(self._servers)
        self._sock.setblocking(False)
        self._loop.add(self._sock, eventloop.POLL_IN, self)

    def add_to_loop(self, loop):
        if self._loop:
            raise Exception('already add to loop')
        self._loop = loop
        self._refresh()
        loop.add_periodic(self.handle_periodic)

    def _call_callback(self, hostname, ip, error=None):
        DEBUG('DNS callback %s:%s' % (hostname, ip))
        for callback in self._callbacks.get(hostname, []):
            if ip or error:
                callback((hostname, ip), error)
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
        if not hostname:
            callback(None, Exception('empty hostname'))
        elif check_ip(hostname):
            callback((hostname, hostname), None)
        elif hostname in self._cache:
            DEBUG('hit cache: %s' % host)
            ip = self._cache[hostname]
            callback((hostname, ip), None)
        elif not check_hostname(hostname):
            callback(None, Exception('invalid hostname: %s' % hostname))
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
