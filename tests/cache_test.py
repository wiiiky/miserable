# encoding=utf8
#
# Copyright 2015-2016 Wiky L
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
from miserable.cache import *


class CacheTestCase(unittest.TestCase):

    def test_cache(self):
        c = LRUCache(timeout=0.3, const='const')

        c['a'] = 1
        self.assertEqual(c['a'], 1)

        time.sleep(0.5)
        c.sweep()
        self.assertTrue('a' not in c)
        self.assertTrue('const' in c)
        self.assertEqual(c['const'], 'const')

        c['a'] = 2
        c['b'] = 3
        time.sleep(0.2)
        c.sweep()
        self.assertEqual(c['a'], 2)
        self.assertEqual(c['b'], 3)

        time.sleep(0.2)
        c.sweep()
        self.assertTrue(c['b'] is not None)
        time.sleep(0.2)
        c.sweep()
        self.assertTrue('a' not in c)
        self.assertEqual(c['b'], 3)

        time.sleep(0.5)
        c.sweep()
        self.assertTrue('a' not in c)
        self.assertTrue('b' not in c)


if __name__ == '__main__':
    unittest.main()
