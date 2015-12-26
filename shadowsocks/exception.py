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

def errno_from_exception(e):
    """Provides the errno from an Exception object.

    There are cases that the errno attribute was not set so we pull
    the errno out of the args but if someone instatiates an Exception
    without any args you will get a tuple error. So this function
    abstracts all that behavior to give you a safe way to get the
    errno.
    """
    return getattr(e, 'errno', e.args[0] if e.args else None)


class BaseException(Exception):

    @property
    def message(self):
        return u''

    def __str__(self):
        return self.message


class InvalidAddressException(BaseException):

    def __init__(self, address, port):
        self._address = address
        self._port = port

    @property
    def message(self):
        return u'%s:%s is an invalid address!' % (self._address, self._port)


class UnsupportFeatureException(BaseException):

    def __init__(self, feature):
        self._feature = feature

    @property
    def message(self):
        return u'%s is not supported by you system!' % (self._feature, )
