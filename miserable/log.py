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


import logging

VERBOSE_LEVEL = 5

verbose_level = 0

colored = lambda text, color, attrs=(): text


def enable_termcolor():
    """if termcolor installed, use it to print colorful logging"""
    global colored
    try:
        import termcolor
        colored = termcolor.colored
    except:
        pass


def logging_init(cfg):
    verbose = cfg['verbose']
    logging.getLogger('').handlers = []
    logging.addLevelName(VERBOSE_LEVEL, 'VERBOSE')
    if verbose >= 2:
        level = VERBOSE_LEVEL
    elif verbose == 1:
        level = logging.DEBUG
    elif verbose == -1:
        level = logging.WARN
    elif verbose <= -2:
        level = logging.ERROR
    else:
        level = logging.INFO
    verbose_level = verbose

    config = {
        'level': level,
        'format': '%(asctime)s %(levelname)-8s %(message)s',
        'datefmt': '%m-%d %H:%M:%S'
    }
    if cfg['daemon'] in ('start', 'restart') and cfg['log-file']:
        config['filename'] = cfg['log-file']
    else:
        """only enable colorful logging when log to terminal"""
        enable_termcolor()
    logging.basicConfig(**config)


def PRINT(text):
    """JUST make function looks similar
    """
    print(text)


def INFO(text):
    logging.info(colored(text, 'cyan'))


def VERBOSE(text):
    logging.info(colored(text, 'green'))


def DEBUG(text):
    logging.debug(colored(text, 'blue'))


def WARN(text):
    logging.warn(colored(text, 'yellow', attrs=('bold', )))


def ERROR(text):
    logging.error(colored(text, 'red', attrs=('bold', )))
