#!/usr/bin/env python3
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

import sys
import os
import signal


try:
    from miserable import eventloop
    from miserable.daemon import MiserableDaemon
    from miserable.dns.resolver import DNSResolver
    from miserable.tcp.proxy import TCPProxy
    from miserable.udp.proxy import UDPProxy
    from miserable.config import LocalConfigManager
    from miserable.loop import MainLoop
    from miserable.log import *
except ImportError as e:
    sys.path.append(os.path.curdir)
    from miserable import eventloop
    from miserable.daemon import MiserableDaemon
    from miserable.dns.resolver import DNSResolver
    from miserable.tcp.proxy import TCPProxy
    from miserable.udp.proxy import UDPProxy
    from miserable.config import LocalConfigManager
    from miserable.loop import MainLoop
    from miserable.log import *


def main():
    try:
        cfg = LocalConfigManager.get_config()

        logging_init(cfg)
        daemon = MiserableDaemon(cfg['daemon'], cfg['pid-file'], cfg['user'])
        daemon.execute()
        INFO('starting local at %s:%d' %
             (cfg['local_address'].ipaddr, cfg['local_address'].port))

        loop = MainLoop()

        dns_resolver = DNSResolver(loop)
        tcp_proxy = TCPProxy(dns_resolver, loop)
        #udp_proxy = UDPProxy(dns_resolver, loop)

        def sigint_handler(signum, _):
            DEBUG('received SIGINT, doing graceful shutting down..')
            tcp_proxy.close()
            #udp_proxy.close()
            loop.stop()
        signal.signal(signal.SIGINT, sigint_handler)

        loop.run()
    except OSError as e:
        ERROR(e)
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
