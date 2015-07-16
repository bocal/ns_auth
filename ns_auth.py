#!/usr/bin/env python3.3
# Copyright 2013-2014 Emmanuel Vadot <elbarto@bocal.org>
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import socket
import select
import hashlib
import time
import urllib.parse
import getpass
import sys
import getopt
import os


class NetsoulConnectionError(BaseException):
    '''Disconnected'''


class Netsoul:

    def __init__(self, login, password=None,
                 host='ns-server.epitech.net', port=4242, verbose=False):
        self._host = host
        self._port = port
        self._login = login
        self._password = password
        self._verbose = verbose
        self._isconnected = False
        self._isauth = False
        self._buffer = None
        self._salut = None
        self._sock = None
        self._writefd = []

    def isauth_get(self):
        return self._isauth

    isauth = property(isauth_get)

    def connect(self):
        try:
            if self._verbose:
                print ('Connecting to ' + self._host + ' on port ' +
                       str(self._port))
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.connect((self._host, self._port))
            self._isconnected = True
            return True
        except:
            if self._verbose:
                print ("Couldn't connect to " + self._host + ' on port ' +
                       str(self._port))
            raise NetsoulConnectionError

    def _ns_auth_ag(self):
        self._buffer = b'auth_ag ext_user none none\n'
        self._expectedresp = '002'
        self._next = self._ns_ext_user_log
        self._writefd.append(self._sock)

    def _ns_ext_user_log(self):
        data = self._salut.split(' ')
        challenge = hashlib.md5()
        challenge.update(bytes(data[2] + '-' + data[3] + '/' + data[4] +
                               self._password, 'utf8'))
        self._buffer = bytes('ext_user_log ' + self._login + ' ' +
                             challenge.hexdigest() + ' ' + data[4] + ' ' +
                             urllib.parse.quote('NSLOG 0.1') + '\n', 'utf8')
        self._writefd.append(self._sock)
        self._next = self._ns_state

    def _ns_state(self):
        self._isauth = True
        self._buffer = bytes('state actif:' + str(int(time.time())) +
                             '\n', 'utf8')
        self._writefd.append(self._sock)
        self._next = None

    def loop(self):
        while 1:
            readfd, writefd, exceptfd = select.select([self._sock],
                                                      self._writefd, [])

            for i in readfd:
                if i == self._sock:
                    try:
                        rdata = self._sock.recv(4096).decode('utf8') \
                            .strip('\n')
                    except:
                        raise NetsoulConnectionError

                    if rdata == '':
                        raise NetsoulConnectionError

                    if self._verbose:
                        print ("Received : '" + rdata + "'")
                    data = rdata.split(' ')
                    if data[0] == 'salut':
                        self._salut = rdata
                        self._ns_auth_ag()
                    elif data[0] == 'rep':
                        if data[1] != self._expectedresp:
                            print ('Last command failed')
                        else:
                            if self._next:
                                self._next()
                    elif data[0] == 'ping':
                        self._buffer = bytes('ping ' + data[1], 'utf8')
                        self._writefd.append(self._sock)

            for i in writefd:
                if i == self._sock:
                    if self._verbose:
                        print ("Sent : '" + str(self._buffer) + "'")
                    self._sock.send(self._buffer)
                    self._writefd.remove(self._sock)


def daemonize():
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write("os.fork() failed: %s\n" + e.strerror)
        sys.exit(1)

    os.chdir('/')
    os.setsid()
    os.umask(0)

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write("os.fork() failed: %s\n" + e.strerror)
        sys.exit(1)


def usage():
    print ('Usage: ' + sys.argv[0] + ' [-u login] [-h] [-v]')
    sys.exit(0)

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'dhvu:',
                                   ['help', 'verbose', 'user='])
    except getopt.GetoptError as e:
        print (e)
        usage()

    verbose = False
    daemon = True
    user = getpass.getuser()

    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
        elif o in ('-v', '--verbose'):
            verbose = True
        elif o in ('-u', '--user'):
            user = a
        elif o in ('-d', ):
            daemon = False
        else:
            usage()

    password = getpass.getpass()

    if daemon:
        daemonize()

    while 1:
        ns = Netsoul(login=user, verbose=verbose, password=password)
        try:
            ns.connect()
            ns.loop()
        except NetsoulConnectionError:
            if verbose:
                print ('Disconnected, retrying in 10 seconds')
            time.sleep(10)
