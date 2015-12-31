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
import re

from miserable import eventloop
from miserable.log import *
from miserable.cache import LRUCache
from miserable.dns.protocol import *
from miserable.utils import *


CACHE_SWEEP_INTERVAL = 30

VALID_HOSTNAME = re.compile(br'(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE)


def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == b'.':
        hostname = hostname[:-1]
    return all(VALID_HOSTNAME.match(x) for x in hostname.split(b'.'))


STATUS_IPV4 = 0
STATUS_IPV6 = 1


class DNSResolver(object):

    def __init__(self):
        self._loop = None
        self._hosts = load_hosts_conf()
        self._servers = load_resolv_conf()
        self._hostname_status = {}
        self._hostname_to_cb = {}
        self._cb_to_hostname = {}
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
        callbacks = self._hostname_to_cb.get(hostname, [])
        for callback in callbacks:
            if callback in self._cb_to_hostname:
                del self._cb_to_hostname[callback]
            if ip or error:
                callback((hostname, ip), error)
            else:
                callback((hostname, None),
                         Exception('unknown hostname %s' % hostname))
        if hostname in self._hostname_to_cb:
            del self._hostname_to_cb[hostname]
        if hostname in self._hostname_status:
            del self._hostname_status[hostname]

    def _send_request(self, hostname, atype=TYPE.A):
        DEBUG('query DNS %s' % hostname)
        self._sock.send_dns_request(hostname, atype)

    def _handle_response(self, response):
        if not response:
            return
        hostname = response.hostname
        ip = None
        for answer in response.answers:
            if answer['type'] in (TYPE.A, TYPE.AAAA) and \
                    answer['class'] == CLASS.IN:
                ip = answer['addr']
                break
        if not ip and self._hostname_status.get(hostname, STATUS_IPV6) \
                == STATUS_IPV4:
            self._hostname_status[hostname] = STATUS_IPV6
            self.send_request(hostname, TYPE.AAAA)
        elif ip:
            self._cache[hostname] = ip
            self._call_callback(hostname, ip)
        elif self._hostname_status.get(hostname, None) == STATUS_IPV6:
            for question in response.questions:
                if question['type'] == TYPE.AAA:
                    self._call_callback(hostname, None)
                    break

    def handle_event(self, sock, fd, event):
        if sock != self._sock:
            return
        if event & eventloop.POLL_ERR:
            ERROR('dns socket err')
            self._loop.remove(self._sock)
            self._sock.close()
            self._refresh()
        elif event & eventloop.POLL_IN:
            response = sock.recv_dns_response()
            self._handle_response(response)

    def handle_periodic(self):
        self._cache.sweep()

    def remove_callback(self, callback):
        hostname = self._cb_to_hostname.get(callback)
        if hostname:
            del self._cb_to_hostname[callback]
            arr = self._hostname_to_cb.get(hostname, None)
            if arr:
                arr.remove(callback)
                if not arr:
                    del self._hostname_to_cb[hostname]
                    if hostname in self._hostname_status:
                        del self._hostname_status[hostname]

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
        else:
            if not is_valid_hostname(hostname):
                callback(None, Exception('invalid hostname: %s' % hostname))
                return
            arr = self._hostname_to_cb.get(hostname, None)
            if not arr:
                self._hostname_status[hostname] = STATUS_IPV4
                self._hostname_to_cb[hostname] = [callback]
                self._cb_to_hostname[callback] = hostname
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
