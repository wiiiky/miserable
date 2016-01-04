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


import unittest
from miserable.dns.utils import *


class HostnameTestCase(unittest.TestCase):

    def test_hostname(self):
        addr = Address('www.baidu.com', 80)
        self.assertTrue(addr.ipaddr is None)
        self.assertEqual(addr.port, 80)
        self.assertEqual(addr.hostname, 'www.baidu.com')
        addr.ipaddr = ip_address('127.0.0.1')
        self.assertTrue(addr.ipaddr is not None)

if __name__ == '__main__':
    unittest.main()
