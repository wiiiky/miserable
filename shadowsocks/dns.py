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

from shadowsocks import common

import struct
import socket
import os


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

    def __init__(self, hostname, qtype):
        self.hostname = hostname
        self.qtype = qtype
        self.data = None

    @property
    def bytes(self):
        if not self.data:
            self.data = self._build_package()
        return self.data

    def _build_hostname(self):
        hostname = common.to_bytes(self.hostname)
        address = hostname.strip(b'.')
        labels = hostname.split(b'.')
        results = []
        for label in labels:
            l = len(label)
            if l > 63:
                return None
            results.append(common.chr(l))
            results.append(label)
        results.append(b'\0')
        return b''.join(results)

    def _build_package(self):
        """build the DNS request package"""
        mid = os.urandom(2)
        header = struct.pack('!BBHHHH', 1, 0, 1, 0, 0, 0)
        addr = self._build_hostname()
        qtype_qclass = struct.pack('!HH', self.qtype, CLASS.IN)
        return mid + header + addr + qtype_qclass


def parse_ip(rtype, data, length, offset):
    if rtype == TYPE.A:
        return socket.inet_ntop(socket.AF_INET, data[offset:offset + length])
    elif rtype == TYPE.AAAA:
        return socket.inet_ntop(socket.AF_INET6, data[offset:offset + length])
    elif rtype in [TYPE.CNAME, TYPE.NS]:
        return parse_name(data, offset)[1]
    else:
        return data[offset:offset + length]


def parse_name(data, offset):
    """parse hostname from DNS response"""
    p = offset
    labels = []
    l = common.ord(data[p])
    while l > 0:
        if (l & (128 + 64)) == (128 + 64):
            # pointer
            ptr = struct.unpack('!H', data[p:p + 2])[0]
            ptr &= 0x3FFF
            r = parse_name(data, ptr)
            labels.append(r[1])
            p += 2
            # pointer is the end
            return p - offset, b'.'.join(labels)
        else:
            labels.append(data[p + 1:p + 1 + l])
            p += 1 + l
        l = common.ord(data[p])
    return p - offset + 1, b'.'.join(labels)


def parse_record(data, offset, question=False):
    nlen, name = parse_name(data, offset)
    if not question:
        """DNS answer"""
        record_type, record_class, record_ttl, record_rdlength = struct.unpack(
            '!HHiH', data[offset + nlen:offset + nlen + 10]
        )
        ip = parse_ip(record_type, data, record_rdlength, offset + nlen + 10)
        return nlen + 10 + record_rdlength, \
            (name, ip, record_type, record_class, record_ttl)
    else:
        """DNS question"""
        record_type, record_class = struct.unpack(
            '!HH', data[offset + nlen:offset + nlen + 4]
        )
        return nlen + 4, (name, None, record_type, record_class, None, None)


def parse_header(data):
    if len(data) < 12:
        return None
    header = struct.unpack('!HBBHHHH', data[:12])
    res_id = header[0]
    res_qr = header[1] & 128
    res_tc = header[1] & 2
    res_ra = header[2] & 128
    res_rcode = header[2] & 15
    # assert res_tc == 0
    # assert res_rcode in [0, 3]
    res_qdcount = header[3]
    res_ancount = header[4]
    res_nscount = header[5]
    res_arcount = header[6]
    return (res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount,
            res_ancount, res_nscount, res_arcount)


def prase_response(data):
    """parse the DNS response"""
    try:
        if len(data) < 12:
            return
        header = parse_header(data)
        if not header:
            return
        res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount, \
            res_ancount, res_nscount, res_arcount = header

        qds = []
        ans = []
        offset = 12
        for i in range(0, res_qdcount):
            l, r = parse_record(data, offset, True)
            offset += l
            qds.append(r)
        for i in range(0, res_ancount):
            l, r = parse_record(data, offset)
            offset += l
            ans.append(r)
        for i in range(0, res_nscount):
            l, r = parse_record(data, offset)
            offset += l
        for i in range(0, res_arcount):
            l, r = parse_record(data, offset)
            offset += l
        if qds:
            return {
                'hostname': qds[0][0],
                'questions': [{'addr': a[1], 'type': a[2], 'class': a[3]}
                              for a in qds if a],
                'answers': [{'addr': a[1], 'type': a[2], 'class': a[3]}
                            for a in ans if a],
            }
    except Exception as e:
        shell.print_exception(e)


class Socket(socket.socket):
    """UDP socket for sending DNS request & receiving DNS response"""

    def __init__(self, servers):
        self._servers = servers if hasattr(servers, '__iter__') else [servers]
        # TODO when dns server is IPv6
        super(Socket, self).__init__(socket.AF_INET, socket.SOCK_DGRAM,
                                     socket.SOL_UDP)

    def send_dns_request(self, hostname, qtype=TYPE.A):
        req = Request(hostname, qtype)
        for server in self._servers:
            self.sendto(req.bytes, (server, 53))

    def recv_dns_response(self):
        data, addr = self.recvfrom(1024)
        if addr[0] not in self._servers:
            return
        return prase_response(data)


def load_resolv_conf(path='/etc/resolv.conf'):
    """parse the resolv.conf file and returns DNS servers"""
    servers = []
    try:
        with open(path, 'r') as f:
            for line in f.readlines():
                line = line.strip()
                if line and line.startswith('nameserver'):
                    parts = line.split()
                    if len(parts) >= 2 and common.is_ip(parts[1]) \
                            == socket.AF_INET:
                        servers.append(parts[1])
    except IOError as e:
        pass
    if not servers:
        servers = ['8.8.4.4', '8.8.8.8']
    return servers


def load_hosts_conf():
    """parse hosts file"""
    path = os.environ['WINDIR'] + '/system32/drivers/etc/hosts'\
        if 'WINDIR' in os.environ else '/etc/hosts'
    hosts = {}
    try:
        with open(path, 'r') as f:
            for line in f.readlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    ip = parts[0]
                    if common.is_ip(ip):
                        for hostname in parts[1:]:
                            if hostname:
                                hosts[hostname] = ip
    except IOError as e:
        hosts['localhost'] = '127.0.0.1'
    return hosts
