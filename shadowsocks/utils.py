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

import socket


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
