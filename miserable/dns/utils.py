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


from miserable.utils import *


def load_resolv_conf(path='/etc/resolv.conf'):
    """parse the resolv.conf file and returns DNS servers"""
    servers = []
    try:
        with open(path, 'r') as f:
            for line in f.readlines():
                line = line.strip()
                if line and line.startswith('nameserver'):
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    addr = ip_address(parts[1])
                    if addr:
                        servers.append(addr)
    except IOError as e:
        pass
    if not servers:
        servers = [ip_address('8.8.4.4'), ip_address('8.8.8.8')]
    return servers


def load_hosts_conf(path='/etc/hosts'):
    """parse hosts file"""
    hosts = {}
    try:
        with open(path, 'r') as f:
            for line in f.readlines():
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                addr = ip_address(parts[0])
                if addr:
                    for hostname in parts[1:]:
                        if hostname:
                            hosts[hostname] = addr
    except IOError as e:
        hosts['localhost'] = '127.0.0.1'
    return hosts
