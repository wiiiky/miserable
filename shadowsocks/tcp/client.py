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

from shadowsocks.tcp.peer import Peer


class ClientState(object):
    INIT = 0            # waiting for hello message from client
    ADDR = 1
    UDP_ASSOC = 2
    DNS = 3
    CONNECTING = 4
    CONNECTED = 5


class Client(Peer):
    """manages the connection to client"""

    def __init__(self, sock, addr, loop, encryptor=None):
        super(Client, self).__init__(sock, addr, loop, encryptor)
        self._state = ClientState.INIT

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, state):
        self._state = state
