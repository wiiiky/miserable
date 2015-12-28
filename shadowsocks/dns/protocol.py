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
        self.hostname = hostname
        self.qtype = qtype
        self.mid = mid if type(mid) is int else random.randint(1, 65535)
        self.bytes = self._build_package()

    def _build_hostname(self):
        hostname = tobytes(self.hostname)
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

    def _build_package(self):
        """build the DNS request package"""
        header = struct.pack('!BBHHHH', 1, 0, 1, 0, 0, 0)
        addr = self._build_hostname()
        qtype_qclass = struct.pack('!HH', self.qtype, CLASS.IN)
        return struct.pack('!H', self.mid) + header + addr + qtype_qclass


class Response(object):
    """DNS Result"""

    def __init__(self, data):
        self.data = data
        self.hostname = None
        self.questions = None
        self.answers = None
        self.mid = None
        self._parse_response()

    def is_valid(self):
        return bool(self.hostname) and bool(self.answers) and bool(self.questions)

    def _parse_response(self):
        """parse the DNS response"""
        data = self.data
        try:
            if len(data) < 12:
                return

            res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount, \
                res_ancount, res_nscount, res_arcount = self._parse_header()

            qds = []
            ans = []
            offset = 12
            for i in range(0, res_qdcount):
                l, r = self._parse_record(offset, True)
                offset += l
                qds.append(r)
            for i in range(0, res_ancount):
                l, r = self._parse_record(offset)
                offset += l
                ans.append(r)
            for i in range(0, res_nscount):
                l, r = self._parse_record(offset)
                offset += l
            for i in range(0, res_arcount):
                l, r = self._parse_record(offset)
                offset += l
            if qds:
                self.hostname = qds[0][0]
                self.questions = [{'addr': a[1], 'type': a[2], 'class': a[3]}
                                  for a in qds if a]
                self.answers = [{'addr': a[1], 'type': a[2], 'class': a[3]}
                                for a in ans if a]
                self.mid = res_id
        except Exception as e:
            import traceback
            traceback.print_exc()

    def _parse_header(self):
        header = struct.unpack('!HBBHHHH', self.data[:12])
        res_id = header[0]
        res_qr = header[1] & 128
        res_tc = header[1] & 2
        res_ra = header[2] & 128
        res_rcode = header[2] & 15
        res_qdcount = header[3]
        res_ancount = header[4]
        res_nscount = header[5]
        res_arcount = header[6]
        return res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount,\
            res_ancount, res_nscount, res_arcount

    def _parse_record(self, offset, question=False):
        nlen, name = self._parse_name(offset)
        if not question:
            """DNS answer"""
            rtype, rclass, rttl, rlength = struct.unpack(
                '!HHiH', self.data[offset + nlen:offset + nlen + 10]
            )
            ip = self._parse_ip(rtype, rlength, offset + nlen + 10)
            return nlen + 10 + rlength, (name, ip, rtype, rclass, rttl)
        else:
            """DNS question"""
            rtype, rclass = struct.unpack(
                '!HH', self.data[offset + nlen:offset + nlen + 4]
            )
            return nlen + 4, (name, None, rtype, rclass, None, None)

    def _parse_name(self, offset):
        """parse hostname from DNS response"""
        p = offset
        labels = []
        l = self.data[p]
        while l > 0:
            if (l & (128 + 64)) == (128 + 64):
                # pointer
                ptr = struct.unpack('!H', self.data[p:p + 2])[0]
                ptr &= 0x3FFF
                r = self._parse_name(ptr)
                labels.append(r[1])
                p += 2
                # pointer is the end
                return p - offset, b'.'.join(labels)
            else:
                labels.append(self.data[p + 1:p + 1 + l])
                p += 1 + l
            l = self.data[p]
        return p - offset + 1, b'.'.join(labels)

    def _parse_ip(self, rtype, length, offset):
        if rtype == TYPE.A:
            return socket.inet_ntop(socket.AF_INET,
                                    self.data[offset:offset + length])
        elif rtype == TYPE.AAAA:
            return socket.inet_ntop(socket.AF_INET6,
                                    self.data[offset:offset + length])
        elif rtype in [TYPE.CNAME, TYPE.NS]:
            return self._parse_name(offset)[1]
        else:
            return self.data[offset:offset + length]


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
