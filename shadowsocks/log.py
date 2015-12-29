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


import logging

VERBOSE_LEVEL = 5

verbose_level = 0


def logging_init(verbose):
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
    logging.basicConfig(level=level,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

try:
    """if termcolor installed, use it to print colorful logging"""
    from termcolor import colored
except ImportError:
    def colored(text, color):
        return text


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
