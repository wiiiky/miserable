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


# rfc1035
# format
# +---------------------+
# |        Header       |
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
# +---------------------+
#
# header
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#
#
# All RRs have the same top level format shown below:
#
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                                               |
# /                                               /
# /                      NAME                     /
# |                                               |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      TYPE                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     CLASS                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      TTL                      |
# |                                               |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                   RDLENGTH                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
# /                     RDATA                     /
# /                                               /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

from shadowsocks.utils import *

import struct
import socket
import json
import random
import time


class TYPE:
    ANY = 255
    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MINFO = 14
    MX = 15
    TXT = 16
    AAAA = 28


class CLASS:
    ANY = 255
    IN = 1
    CS = 2
    CH = 3
    HS = 4


class Request(object):
    """DNS request"""

    def __init__(self, hostname, qtype, mid=None):
        """
        if message ID not specified, use a random one
        """
        self.hostname = hostname
        self.qtype = qtype
        self.mid = mid if type(mid) is int else random.randint(1, 65535)
        self.bytes = self.build_package(self.mid, self.hostname, self.qtype)

    @classmethod
    def build_hostname(klass, hostname):
        hostname = tobytes(hostname)
        labels = hostname.split(b'.')
        results = []
        for label in labels:
            l = len(label)
            if l > 63:
                return None
            results.append(tobytes(l))
            results.append(label)
        results.append(b'\0')
        return b''.join(results)

    @classmethod
    def build_package(klass, mid, hostname, qtype):
        """build the DNS request package"""
        header = struct.pack('!BBHHHH', 1, 0, 1, 0, 0, 0)
        addr = klass.build_hostname(hostname)
        qtype_qclass = struct.pack('!HH', qtype, CLASS.IN)
        return struct.pack('!H', mid) + header + addr + qtype_qclass


class Response(object):
    """DNS Result"""

    def __init__(self, data):
        self.mid, self.hostname, self.questions, self.answers\
            = self.parse_response(data)

    def is_valid(self):
        return bool(self.hostname) and bool(self.answers)\
            and bool(self.questions)

    @classmethod
    def parse_header(klass, data):
        """
        data should be a bytes with length 12
        """
        header = struct.unpack('!HBBHHHH', data)
        mid = header[0]
        qr = header[1] & 128
        tc = header[1] & 2
        ra = header[2] & 128
        rcode = header[2] & 15
        qdcount = header[3]
        ancount = header[4]
        nscount = header[5]
        arcount = header[6]
        return mid, qr, tc, ra, rcode, qdcount, ancount, nscount, arcount

    @classmethod
    def parse_name(klass, data):
        """parse hostname from DNS response"""
        labels = []
        p = 0
        while p < len(data) and data[p] > 0:
            l = data[p]
            if (l & (128 + 64)) == (128 + 64):
                # pointer
                ptr = struct.unpack('!H', data[p:p + 2])[0] & 0x3FFF
                r = klass.parse_name(data[ptr:])
                labels.append(r[1])
                p += 2
                # pointer is the end
                return p, b'.'.join(labels)
            else:
                labels.append(data[p + 1:p + 1 + l])
                p += 1 + l
        return p + 1, b'.'.join(labels)

    @classmethod
    def parse_ip(klass, data, rtype, length):
        if rtype == TYPE.A:
            return socket.inet_ntop(socket.AF_INET, data[:length])
        elif rtype == TYPE.AAAA:
            return socket.inet_ntop(socket.AF_INET6, data[:length])
        elif rtype in [TYPE.CNAME, TYPE.NS]:
            return klass.parse_name(data)[1]
        return data[:length]

    @classmethod
    def parse_record(klass, data, question=False):
        nlen, name = klass.parse_name(data)
        if not question:
            """DNS answer"""
            rtype, rclass, rttl, rlength = struct.unpack(
                '!HHiH', data[nlen:nlen + 10]
            )
            ip = klass.parse_ip(data[nlen + 10:], rtype, rlength)
            return nlen + 10 + rlength, (name, ip, rtype, rclass, rttl)
        """DNS question"""
        rtype, rclass = struct.unpack('!HH', data[nlen:nlen + 4])
        return nlen + 4, (name, None, rtype, rclass, None, None)

    @classmethod
    def parse_response(klass, data):
        """parse the DNS response"""
        if len(data) < 12:
            return

        mid, qr, tc, ra, rcode, qdcount, ancount, nscount,\
            arcount = klass.parse_header(data[:12])

        qds = []
        ans = []
        data = data[12:]
        for i in range(0, qdcount):
            l, r = klass.parse_record(data, True)
            qds.append(r)
            data = data[l:]
        for i in range(0, ancount):
            l, r = klass.parse_record(data)
            ans.append(r)
            data = data[l:]
        for i in range(0, nscount):
            l, r = klass.parse_record(data)
            data = data[l:]
        for i in range(0, arcount):
            l, r = klass.parse_record(data)
            data = data[l:]
        if qds:
            hostname = qds[0][0]
            questions = [{'addr': a[1], 'type': a[2], 'class': a[3]}
                         for a in qds if a]
            answers = [{'addr': a[1], 'type': a[2], 'class': a[3]}
                       for a in ans if a]
            mid = mid
            return mid, hostname, questions, answers
        return None, None, None, None


class DNSSocket(socket.socket):
    """UDP socket for sending DNS request & receiving DNS response"""

    def __init__(self, servers):
        self._id = 0
        self._wait = {}
        self._timeout = 60
        self._servers = servers if hasattr(servers, '__iter__') else [servers]
        # TODO when dns server is IPv6
        super(DNSSocket, self).__init__(socket.AF_INET, socket.SOCK_DGRAM,
                                        socket.SOL_UDP)

    def send_dns_request(self, hostname, qtype=TYPE.A):
        request = Request(hostname, qtype, mid=self._id)
        for server in self._servers:
            self.sendto(request.bytes, (server, 53))
        self._wait[self._id] = time.time()
        self._increase_id()

    def recv_dns_response(self):
        self._check_timeout()
        data, addr = self.recvfrom(1024)
        if addr[0] not in self._servers:
            return
        response = Response(data)
        if not response.is_valid() or response.mid not in self._wait:
            return None
        del self._wait[response.mid]
        return response

    def _increase_id(self):
        self._id += 1
        if self._id > 65535:
            """two bytes for message ID"""
            self._id = 0

    def _check_timeout(self):
        now = time.time()
        for mid, t in list(self._wait.items()):
            if now - t > self._timeout:
                del self._wait[mid]


def load_resolv_conf(path='/etc/resolv.conf'):
    """parse the resolv.conf file and returns DNS servers"""
    servers = []
    try:
        with open(path, 'r') as f:
            for line in f.readlines():
                line = line.strip()
                if line and line.startswith('nameserver'):
                    parts = line.split()
                    if len(parts) >= 2 and check_ip(parts[1]) \
                            == socket.AF_INET:
                        servers.append(parts[1])
    except IOError as e:
        pass
    if not servers:
        servers = ['8.8.4.4', '8.8.8.8']
    return servers


def load_hosts_conf(path='/etc/hosts'):
    """parse hosts file"""
    hosts = {}
    try:
        with open(path, 'r') as f:
            for line in f.readlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    ip = parts[0]
                    if check_ip(ip):
                        for hostname in parts[1:]:
                            if hostname:
                                hosts[hostname] = ip
    except IOError as e:
        hosts['localhost'] = '127.0.0.1'
    return hosts
