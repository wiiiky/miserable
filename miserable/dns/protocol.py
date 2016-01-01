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

from __future__ import absolute_import, division, print_function, \
    with_statement

from miserable.utils import *
from miserable.log import *

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

    def __init__(self, hostname, atype=TYPE.A, mid=None):
        """
        if message ID not specified, use a random one
        """
        self.hostname = hostname
        self.mid = mid if type(mid) is int else random.randint(1, 65535)
        self.bytes = self.build_package(self.mid, self.hostname, atype)

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
    def build_package(klass, mid, hostname, atype):
        """build the DNS request package"""
        header = struct.pack('!BBHHHH', 1, 0, 1, 0, 0, 0)
        addr = klass.build_hostname(hostname)
        tc = struct.pack('!HH', atype, CLASS.IN)
        return struct.pack('!H', mid) + header + addr + tc


class Response(object):
    """DNS Result"""

    def __init__(self, data):
        self.mid, self.hostname, self.questions, self.answers\
            = self.parse_response(data)

        self.answer = None
        self.qtype = TYPE.ANY if not self.questions else self.questions[
            0]['type']
        for answer in self.answers:
            if answer['type'] in (TYPE.A, TYPE.AAAA) and \
                    answer['class'] == CLASS.IN:
                self.answer = ip_address(answer['addr'])
                return

    def __str__(self):
        return u'[%s] %s - %s' % (self.qtype, self.hostname, self.answer)

    def is_valid(self):
        return bool(self.hostname) and bool(self.answer)

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
        return None, None, [], []
