#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2014-2015 clowwindy
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
import sys
import atexit
import signal
import time


def setuser(username):
    if not username:
        return

    import pwd
    import grp

    try:
        pwrec = pwd.getpwnam(username)
    except KeyError:
        sys.stderr.write('user not found: %s\n' % username)
        raise
    user = pwrec[0]
    uid = pwrec[2]
    gid = pwrec[3]

    cur_uid = os.getuid()
    if uid == cur_uid:
        return
    if cur_uid != 0:
        sys.stderr.write('can not set user as nonroot user\n')
        # will raise later

    # inspired by supervisor
    if hasattr(os, 'setgroups'):
        groups = [grprec[2] for grprec in grp.getgrall() if user in grprec[3]]
        groups.insert(0, gid)
        os.setgroups(groups)
    os.setgid(gid)
    os.setuid(uid)


def dfork():
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write("fork failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)


def rpid(pidfile):
    """read pid from pid file"""
    try:
        pf = open(pidfile, 'r')
        pid = int(pf.read().strip())
        pf.close()
    except IOError:
        pid = None
    return pid


class Daemon(object):
    """
    A generic adamon class
    """

    def __init__(self, pidfile, stdin='/dev/null', stdout='/dev/null',
                 stderr='/dev/null', user=None):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
        self.user = user

    def daemonize(self):
        """"""
        dfork()

        os.chdir('/')
        os.setsid()
        os.umask(0)

        dfork()

        sys.stdout.flush()
        sys.stderr.flush()
        si = open(self.stdin, 'r')
        so = open(self.stdout, 'a+')
        se = open(self.stderr, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        atexit.register(self.delpid)
        pid = str(os.getpid())
        open(self.pidfile, 'w+').write('%s\n' % pid)

    def delpid(self):
        """delete pidfile at exit"""
        try:
            os.remove(self.pidfile)
        except:
            pass

    def start(self):
        """start daemon"""
        if self.user:
            setuser(self.user)

        pid = rpid(self.pidfile)

        if pid:
            message = 'pidfile %s already exists. Daemon is already running?\n'
            sys.stderr.write(message)
            sys.exit(1)

        self.daemonize()

    def stop(self):
        """Stop the daemon"""
        pid = rpid(self.pidfile)

        if not pid:
            message = 'pidfile %s does not exist,Daemon is not running?\n' % self.pidfile
            sys.stderr.write(message)
            return

        try:
            os.kill(pid, signal.SIGINT)
            time.sleep(0.5)
        except OSError as e:
            err = str(e)
            if 'No such process' in err:
                if os.path.exists(self.pidfile):
                    self.delpid()
            else:
                sys.stderr.write(err + '\n')
                sys.exit(1)

    def restart(self):
        self.stop()
        self.start()


class MiserableDaemon(Daemon):

    def __init__(self, cmd, pidfile, user):
        self._cmd = cmd
        super(MiserableDaemon, self).__init__(pidfile=pidfile, user=user)

    def execute(self):
        if self._cmd == 'start':
            self.start()
        elif self._cmd == 'stop':
            self.stop()
            sys.exit(0)
        elif self._cmd == 'restart':
            self.restart()
