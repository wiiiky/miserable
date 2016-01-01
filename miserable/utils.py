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

import re
import socket
import ipaddress


def ip_address(addr):
    """
    convert a ip address string to
    ipaddress.IPv4Address or ipaddress.IPv6Address
    """
    try:
        return ipaddress.ip_address(addr)
    except Exception as e:
        return None


def ipv6_address(ipaddr):
    if ipaddr.version == 4:
        ipaddr = ipaddress.IPv6Address('::ffff:' + ipaddr.compressed)
    return ipaddr


def tostr(data):
    """convert bytes to str"""
    if type(data) is bytes:
        data = data.decode('utf8')
    return data


def tobytes(data):
    """convert str or int to bytes"""
    if type(data) is int:
        data = chr(data)
    if type(data) is str:
        data = data.encode('utf8')
    return data


def check_ip(address):
    """
    check to see if the address is a valid IP address
    """
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            address = tostr(address)
            socket.inet_pton(family, address)
            return family
        except (TypeError, ValueError, OSError, IOError):
            pass
    return False


VALID_HOSTNAME = re.compile(br'(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE)


def check_hostname(hostname):
    """
    check to see if the hostname is legal
    """
    if len(hostname) > 255:
        return False
    hostname = tobytes(hostname)
    if hostname[-1] == b'.':
        hostname = hostname[:-1]
    return all(VALID_HOSTNAME.match(x) for x in hostname.split(b'.'))


def addr2bytes(ip):
    """convert dotted ip address to bytes"""
    try:
        return socket.AF_INET, socket.inet_pton(socket.AF_INET, ip)
    except OSError:
        return socket.AF_INET6, socket.inet_pton(socket.AF_INET6, ip)
