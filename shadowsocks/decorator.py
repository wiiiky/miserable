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

import errno
from shadowsocks.exception import errno_from_exception


class return_val_if_wouldblock(object):

    def __init__(self, value):
        self._value = value

    def __call__(self, f):
        def wrapper(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except (OSError, IOError) as e:
                if errno_from_exception(e) in \
                        (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                    return self._value
                raise e
        return wrapper


def stop_transfer_if_fail(f):
    def wrapper(transfer, *args, **kwargs):
        try:
            return f(transfer, *args, **kwargs)
        except Exception as e:
            transfer.stop(info=str(e))
    return wrapper
