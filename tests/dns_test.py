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


import unittest
from shadowsocks import dns


class DNSTestCase(unittest.TestCase):

    def test_socekt(self):
        servers = dns.load_resolv_conf()
        self.assertTrue(bool(servers))

        hostname = b'www.baidu.com'
        sock = dns.Socket(servers)
        sock.send_dns_request(hostname)
        response = sock.recv_dns_response()
        self.assertTrue(response['hostname'] == hostname)
        self.assertTrue(len(response['answers']) > 0)
        sock.close()


if __name__ == '__main__':
    unittest.main()
