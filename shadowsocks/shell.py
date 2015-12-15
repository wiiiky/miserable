#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
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

import os
import json
import sys
import getopt
import logging
from shadowsocks.common import to_bytes, to_str, IPNetwork
from shadowsocks import encrypt


VERBOSE_LEVEL = 5

verbose = 0


def check_python():
    info = sys.version_info
    if info[0] == 2 and not info[1] >= 6:
        print('Python 2.6+ required')
        sys.exit(1)
    elif info[0] == 3 and not info[1] >= 3:
        print('Python 3.3+ required')
        sys.exit(1)
    elif info[0] not in [2, 3]:
        print('Python version not supported')
        sys.exit(1)


def print_exception(e):
    global verbose
    logging.error(e)
    if verbose > 0:
        import traceback
        traceback.print_exc()


def print_shadowsocks():
    version = ''
    try:
        import pkg_resources
        version = pkg_resources.get_distribution('shadowsocks').version
    except Exception:
        pass
    print('Shadowsocks %s' % version)


def check_config(config, is_local):
    if config['daemon'] == 'stop':
        # no need to specify configuration for daemon stop/restart
        return

    if is_local and not config['server']:
        """server must be specified when try to start sslocal"""
        logging.error('server addr not specified')
        print_local_help()
        sys.exit(2)

    if is_local and not config['password']:
        logging.error('password not specified')
        print_help(is_local)
        sys.exit(2)

    if not is_local and not config['password'] \
            and not config['port_password']:
        logging.error('password or port_password not specified')
        print_help(is_local)
        sys.exit(2)

    if config['local_address'] in [b'0.0.0.0']:
        logging.warn('warning: local set to listen on 0.0.0.0, it\'s not safe')
    if config['server'] in ['127.0.0.1', 'localhost']:
        logging.warn('warning: server set to listen on %s:%s, are you sure?' %
                     (config['server'], config['server_port']))
    if config['method'].lower() == 'table':
        logging.warn('warning: table is not safe; please use a safer cipher, '
                     'like AES-256-CFB')
    if config['method'].lower() == 'rc4':
        logging.warn('warning: RC4 is not safe; please use a safer cipher, '
                     'like AES-256-CFB')
    if config['timeout'] < 100:
        logging.warn('warning: timeout %ds seems too short' %
                     config.get('timeout'))
    if config['timeout'] > 600:
        logging.warn('warning: your timeout %d seems too long' %
                     config.get('timeout'))
    if config['password'] in [b'mypassword']:
        logging.error('DON\'T USE DEFAULT PASSWORD! Please change it in your '
                      'config.json!')
        sys.exit(1)
    if config['user']:
        if os.name != 'posix':
            logging.error('user can be used only on POSIX compatible system.')
            sys.exit(1)

    encrypt.try_cipher(config['password'], config['method'])


def get_config(is_local):
    """parse config from config.json and shell arguments"""
    global verbose

    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)-s: %(message)s')
    if is_local:
        shortopts = 'hd:s:b:p:k:l:m:c:t:vq'
        longopts = ['help', 'fast-open', 'pid-file=', 'log-file=', 'user=',
                    'version']
    else:
        shortopts = 'hd:s:p:k:m:c:t:vq'
        longopts = ['help', 'fast-open', 'pid-file=', 'log-file=', 'workers=',
                    'forbidden-ip=', 'user=', 'manager-address=', 'version']
    try:
        optlist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
    except getopt.GetoptError as e:
        print(e, file=sys.stderr)
        print_help(is_local)
        sys.exit(2)

    options = dict(optlist)

    if '-h' in options or '--help' in options:
        print_help(is_local)
        sys.exit(0)
    elif '--version' in options:
        print_shadowsocks()
        sys.exit(0)

    config = parse_config_file(options.get('-c'))

    def get_option(name, opt, default):
        """get command line argument if exists"""
        if opt in options:
            return options[opt] or True
        if name not in config:
            return default
        return config[name]

    config['server'] = to_str(get_option(
        'server', '-s', '' if is_local else '0.0.0.0'))
    config['server_port'] = int(get_option('server_port', '-p', 8388))
    config['password'] = to_bytes(get_option('password', '-k', b''))
    config['method'] = to_str(get_option('method', '-m', 'aes-256-cfb'))
    config['local_address'] = to_str(
        get_option('local_address', '-b', '127.0.0.1'))
    config['local_port'] = int(get_option('local_port', '-l', 1080))
    config['verbose'] = int(get_option('verbose', '-v', 0))
    config['timeout'] = int(get_option('timeout', '-t', 300))
    config['fast_open'] = get_option('fast_open', '--fast-open', False)
    config['workers'] = int(get_option('workers', '--workers', 1))
    config['manager_address'] = to_str(get_option(
        'manager_address', '--manager-address', ''))
    config['user'] = to_str(get_option('user', '--user', ''))
    config['forbidden_ip'] = to_str(
        get_option('forbidden_ip', '--forbidden-ip', '127.0.0.0/8,::1/128')).split(',')
    config['daemon'] = to_str(get_option('daemon', '-d', ''))
    config['pid-file'] = to_str(get_option('pid-file',
                                           '--pid-file', '/tmp/shadowsocks.pid'))
    config['log-file'] = to_str(get_option('log-file',
                                           '--log-file', '/tmp/shadowsocks.log'))
    config['verbose'] = config['verbose'] - \
        1 if '-q' in options else config['verbose']
    config['port_password'] = ''

    try:
        config['forbidden_ip'] = IPNetwork(config['forbidden_ip'])
    except Exception as e:
        logging.error(e)
        sys.exit(2)

    logging.getLogger('').handlers = []
    logging.addLevelName(VERBOSE_LEVEL, 'VERBOSE')
    if config['verbose'] >= 2:
        level = VERBOSE_LEVEL
    elif config['verbose'] == 1:
        level = logging.DEBUG
    elif config['verbose'] == -1:
        level = logging.WARN
    elif config['verbose'] <= -2:
        level = logging.ERROR
    else:
        level = logging.INFO
    verbose = config['verbose']
    logging.basicConfig(level=level,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    check_config(config, is_local)

    return config


def print_help(is_local):
    if is_local:
        print_local_help()
    else:
        print_server_help()


def print_local_help():
    print('''usage: sslocal [OPTION]...
A fast tunnel proxy that helps you bypass firewalls.

You can supply configurations via either config file or command line arguments.

Proxy options:
  -c CONFIG              path to config file
  -s SERVER_ADDR         server address
  -p SERVER_PORT         server port, default: 8388
  -b LOCAL_ADDR          local binding address, default: 127.0.0.1
  -l LOCAL_PORT          local port, default: 1080
  -k PASSWORD            password
  -m METHOD              encryption method, default: aes-256-cfb
  -t TIMEOUT             timeout in seconds, default: 300
  --fast-open            use TCP_FASTOPEN, requires Linux 3.7+

General options:
  -h, --help             show this help message and exit
  -d start/stop/restart  daemon mode
  --pid-file PID_FILE    pid file for daemon mode
  --log-file LOG_FILE    log file for daemon mode
  --user USER            username to run as
  -v, -vv                verbose mode
  -q, -qq                quiet mode, only show warnings/errors
  --version              show version information

Online help: <https://github.com/shadowsocks/shadowsocks>
''')


def print_server_help():
    print('''usage: ssserver [OPTION]...
A fast tunnel proxy that helps you bypass firewalls.

You can supply configurations via either config file or command line arguments.

Proxy options:
  -c CONFIG              path to config file
  -s SERVER_ADDR         server address, default: 0.0.0.0
  -p SERVER_PORT         server port, default: 8388
  -k PASSWORD            password
  -m METHOD              encryption method, default: aes-256-cfb
  -t TIMEOUT             timeout in seconds, default: 300
  --fast-open            use TCP_FASTOPEN, requires Linux 3.7+
  --workers WORKERS      number of workers, available on Unix/Linux
  --forbidden-ip IPLIST  comma seperated IP list forbidden to connect
  --manager-address ADDR optional server manager UDP address, see wiki

General options:
  -h, --help             show this help message and exit
  -d start/stop/restart  daemon mode
  --pid-file PID_FILE    pid file for daemon mode
  --log-file LOG_FILE    log file for daemon mode
  --user USER            username to run as
  -v, -vv                verbose mode
  -q, -qq                quiet mode, only show warnings/errors
  --version              show version information

Online help: <https://github.com/shadowsocks/shadowsocks>
''')


def _decode_list(data):
    rv = []
    for item in data:
        if hasattr(item, 'encode'):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv


def _decode_dict(data):
    rv = {}
    for key, value in data.items():
        if hasattr(value, 'encode'):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv


def parse_json_in_str(data):
    # parse json and convert everything from unicode to str
    return json.loads(data.encode('utf8'), object_hook=_decode_dict)


def parse_config_file(config_path):
    """parse the json format configuration file"""
    if not config_path:
        return {}

    logging.info('loading config from %s' % config_path)

    try:
        with open(config_path, 'rb') as f:
            config = parse_json_in_str(f.read())
    except (ValueError, IOError) as e:
        logging.error(str(e))
        logging.error('fail to load config from %s!' % (config_path, ))
        sys.exit(1)
    return config
