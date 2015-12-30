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


from miserable.exception import *
from miserable.tcp.peer import Peer


def ignore_inprogress_exception(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (OSError, IOError) as e:
            if not exception_inprogress(e):
                raise e
    return wrapper


class Remote(Peer):
    """
    manages the socket connect to remote
    encrypt everything
    """

    @ignore_inprogress_exception
    def connect(self, addr):
        return self._socket.connect(addr)

    def read(self):
        data = super(Remote, self).read()
        if data:
            data = self.decrypt(data)
        return data

    def write(self, data=b''):
        if data:
            data = self.encrypt(data)
        return super(Remote, self).write(data)
