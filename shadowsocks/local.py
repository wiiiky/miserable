#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2012-2015 clowwindy
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

import sys
import os
import logging
import signal


try:
    from shadowsocks import shell, daemon, eventloop, udprelay
    from shadowsocks.dns.resolver import DNSResolver
    from shadowsocks.tcp.proxy import TCPProxy
    from shadowsocks.config import LocalConfig
    from shadowsocks import log
except ImportError as e:
    sys.path.append(os.path.curdir)
    from shadowsocks import shell, daemon, eventloop, udprelay
    from shadowsocks.dns.resolver import DNSResolver
    from shadowsocks.tcp.proxy import TCPProxy
    from shadowsocks.config import LocalConfig
    from shadowsocks import log


def main():
    shell.check_python()

    cfg = LocalConfig.get_config()

    log.initialize(cfg['verbose'])
    daemon.daemon_exec(cfg)

    try:
        logging.info('starting local at %s:%d' %
                     (cfg['local_address'], cfg['local_port']))

        dns_resolver = DNSResolver()
        tcp_proxy = TCPProxy(cfg, dns_resolver)
        udp_server = udprelay.UDPRelay(cfg, dns_resolver, True)
        loop = eventloop.EventLoop()
        dns_resolver.add_to_loop(loop)
        tcp_proxy.add_to_loop(loop)
        udp_server.add_to_loop(loop)

        def sigint_handler(signum, _):
            logging.warn('received SIGINT, doing graceful shutting down..')
            tcp_proxy.close(next_tick=True)
            udp_server.close(next_tick=True)
        signal.signal(signal.SIGINT, sigint_handler)

        daemon.set_user(cfg['user'])
        loop.run()
    except Exception as e:
        shell.print_exception(e)
        sys.exit(1)

if __name__ == '__main__':
    main()
