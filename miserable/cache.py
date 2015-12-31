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


import time
from collections import MutableMapping
from miserable.log import *


class LRUCache(MutableMapping):

    def __init__(self, timeout=100, **kwargs):
        """"""
        self._timeout = timeout
        self._values = {}
        self._last_active = {}
        self._contants = dict(kwargs)

    def __getitem__(self, key):
        if key in self._contants:
            return self._contants[key]
        elif key in self._values:
            self._last_active[key] = time.time()
            return self._values[key]

    def __setitem__(self, key, value):
        self._values[key] = value
        self._last_active[key] = time.time()

    def __contains__(self, key):
        return self._contants.__contains__(key) or\
            self._values.__contains__(key)

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def __delitem__(self, key):
        if key in self._values:
            del self._values[key]
            del self._last_active[key]

    def sweep(self):
        now = time.time()
        for key, last_active in list(self._last_active.items()):
            if now - last_active > self._timeout:
                del self._values[key]
                del self._last_active[key]
                DEBUG('cache %s expires' % key)
