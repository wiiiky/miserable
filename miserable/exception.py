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

import errno


def errno_from_exception(e):
    """Provides the errno from an Exception object.

    There are cases that the errno attribute was not set so we pull
    the errno out of the args but if someone instatiates an Exception
    without any args you will get a tuple error. So this function
    abstracts all that behavior to give you a safe way to get the
    errno.
    """
    return getattr(e, 'errno', e.args[0] if e.args else None)


def exception_wouldblock(e):
    """
    """
    return errno_from_exception(e) in\
        (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK)


def exception_inprogress(e):
    return errno_from_exception(e) == errno.EINPROGRESS


class BaseException(Exception):

    def __init__(self, msg):
        self._message = msg

    @property
    def message(self):
        return self._message

    def __str__(self):
        return self.message


class InvalidAddressException(BaseException):

    def __init__(self, address, port):
        msg = u'%s:%s is an invalid address!' % (address, port)
        super(InvalidAddressException, self).__init__(msg)


class UnsupportFeatureException(BaseException):

    def __init__(self, feature):
        msg = u'%s is not supported or enabled!' % (feature, )
        super(UnsupportFeatureException, self).__init__(msg)


class InvalidSockVersionException(BaseException):

    def __init__(self, version):
        msg = u'invalid SOCKS version %s' % (version, )
        super(InvalidSockVersionException, self).__init__(msg)


class InvalidFragmentException(BaseException):

    def __init__(self, frag):
        msg = u'invalid UDP fragment %s' % (frag, )
        super(InvalidFragmentException, self).__init__(msg)


class UnknownCommandException(BaseException):

    def __init__(self, cmd):
        msg = u'unknown command %s' % cmd
        super(UnknownCommandException, self).__init__(msg)


class UnexpectedEventError(BaseException):
    pass


class InvalidRequestException(BaseException):
    pass


class ProgrammingError(BaseException):
    pass
