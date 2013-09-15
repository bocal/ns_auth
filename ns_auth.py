#!/usr/bin/env python3.3

# Copyright (c) 2013 Emmanuel Vadot <elbarto@bocal.org>

import socket
import hashlib
import asyncore
import time
import urllib.parse
import getpass
import sys
import getopt

class Netsoul(asyncore.dispatcher):
    def __init__(self, login, password=None, token=None, host='ns-server.epitech.net', port=4242, verbose=False):
        asyncore.dispatcher.__init__(self)
        self._host = host
        self._port = port
        self._login = login
        self._password = password
        self._token = token
        self._verbose = verbose
        self._myhost = socket.gethostname()
        self._isauth = False
        self._buffer = b''
        self._salut = None
        self._challenge = None
        self._state = None

    def isauth_get(self):
        return self._isauth

    isauth = property(isauth_get)

    def nsconnect(self):
        self.create_socket()
        self.connect((self._host, self._port))

    def handle_read(self):
        data = self.recv(8192).decode('utf8').strip().split()
        if self._verbose:
            print ('Receive "' + str(data) + '"')
        if self._salut == None:
            self._salut = data
            if self._salut[0] != 'salut':
                return
            self._buffer = b'auth_ag ext_user none none\n'
        else:
            if self._isauth == False:
                if self._verbose:
                    print ('handle connection')
                if self._challenge == None:
                    secret = self._salut[2]
                    myhost = self._salut[3]
                    myport = self._salut[4]
                    self._password = getpass.getpass()
                    self._challenge = hashlib.md5()
                    self._challenge.update(bytes(secret + '-' + myhost + '/' + myport + self._password, 'utf8'))
                    self._buffer = bytes('ext_user_log ' + self._login + ' ' + self._challenge.hexdigest() + ' ' + self._myhost + ' ' + urllib.parse.quote('NSLOG 0.1') + '\n', 'utf8')
                else:
                    if data[1] == '033':
                        print ('Authentication Failed')
                        sys.exit(1)
                    else:
                        self._isauth = True
                        self._state = 'actif'
                        self._buffer = bytes('state actif:' + str(int(time.time())) + '\n', 'utf8')
            else:
                if self._verbose:
                    print ('handle message')

    def writable(self):
        return (len(self._buffer) > 0)

    def handle_write(self):
        if self._verbose:
            print ('Sending "' + str(self._buffer) + '"')
        sent = self.send(self._buffer)
        self._buffer = self._buffer[sent:]

    def handle_close(self):
        print ('disconnected')
        sys.exit(1)

    def loop(self, timeout=None):
        asyncore.loop(timeout=timeout)

def usage():
    print ('Usage: ' + sys.argv[0] + ' [-u login] [-h] [-v]')
    sys.exit(0)

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hvu:', ['help', 'verbose', 'user='])
    except getopt.GetoptError as e:
        print (e)
        usage()

    verbose = False
    user = getpass.getuser()

    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
        elif o in ('-v', '--verbose'):
            verbose = True
        elif o in ('-u', '--user'):
            user = a
        else:
            usage()

    ns = Netsoul(login=user, verbose=verbose)
    ns.nsconnect()
    ns.loop()
