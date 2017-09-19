"""
Dovecot Authentication Protocol client library.
"""

from __future__ import print_function

import argparse
import base64
import contextlib
import getpass
import os
import socket

__version__ = '0.0.1'

__all__ = [
    'DovecotAuthException',
    'ConnectionException',
    'UnsupportedVersion',
    'NoSupportedMechanisms',

    'connect',
    'Protocol',
]


class DovecotAuthException(Exception):
    """
    Base class for exceptions in this module.
    """


class ConnectionException(DovecotAuthException):
    """
    Something went wrong when connecting to the socket.
    """


class UnsupportedVersion(DovecotAuthException):
    """
    The protocol version supported by the server is incompatible with this
    client.
    """


class NoSupportedMechanisms(DovecotAuthException):
    """
    The server supplied no mechanism supported by this library.
    """


@contextlib.contextmanager
def connect(service, unix=None, inet=None):
    """
    Connect to a dovecot auth endpoint.
    """
    if (unix and inet) or (unix is None and inet is None):
        raise ConnectionException("Pass either 'unix' or 'inet'")
    if unix:
        sock = socket.socket(socket.AF_UNIX)
        sock.connect(unix)
    if inet:
        sock = socket.create_connection(inet)
    try:
        yield Protocol(service, sock.makefile())
    finally:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()


def _parse_inet(addr):
    """
    Parse inet address.
    """
    if addr is None:
        return None
    parts = addr.split(':', 1)
    if len(parts) != 2:
        raise ConnectionException('Inet address must have a port number')
    return parts[0], int(parts[1])


def _encode_plain(uname, pwd):
    """
    Encode a username/password pair with the SASL PLAIN mechanism.
    """
    # See https://tools.ietf.org/html/rfc4616
    return "\0{}\0{}".format(uname, pwd)


def _parse_args(args):
    """
    Parse an argument list.
    """
    result = {}
    for arg in args:
        if arg == '':
            continue
        if '=' in arg:
            key, value = arg.split('=', 1)
            result[key] = value
        else:
            result[arg] = True
    return result


class Protocol(object):
    """
    Implements the actual authentication wire protocol. This doesn't depend
    on the underlying transport and takes a file object.
    """

    handshake_completed = False
    spid = None
    cuid = None
    cookie = None

    _SUPPORTED = {
        'PLAIN': _encode_plain,
    }

    def __init__(self, service, fh):
        self.fh = fh
        self.service = service
        self.req_id = 0
        self.mechanisms = {}
        self._previous_cont = None

    def _read_line(self):
        """
        Parse a response line.
        """
        return self.fh.readline().rstrip('\n').split('\t')

    def _do_handshake(self):
        """
        Perform the initial protocol handshake.
        """
        self.fh.write("VERSION\t1\t1\n")
        self.fh.write("CPID\t{}\n".format(os.getpid()))
        self.fh.flush()

        unsupported = []
        while True:
            args = self._read_line()
            if args[0] == 'DONE':
                break

            if args[0] == 'SPID':
                self.spid = args[1]
            elif args[0] == 'CUID':
                self.cuid = args[1]
            elif args[0] == 'COOKIE':
                self.cookie = args[1]
            elif args[0] == 'VERSION':
                if args[1] != "1" and args[2] != "1":
                    raise UnsupportedVersion('.'.join(args[1:]))
            elif args[0] == 'MECH':
                if args[1] in self._SUPPORTED:
                    self.mechanisms[args[1]] = frozenset(args[2:])
                else:
                    unsupported.append(args[1])

        if len(self.mechanisms) == 0:
            raise NoSupportedMechanisms(unsupported)

        self.handshake_completed = True

    def auth(self, mechanism, uname, pwd,
             secured=False, valid_client_cert=False, no_penalty=False,
             **kwargs):
        """
        Send an auth request.
        """
        if not self.handshake_completed:
            self._do_handshake()

        self._previous_cont = None

        self.req_id += 1

        for prohibited in ('resp', 'no-penalty',
                           'secured', 'valid-client-cert'):
            if prohibited in kwargs:
                del kwargs[prohibited]

        args = ["{}={}".format(key, value)
                for key, value in kwargs.iteritems()]

        for flag, name in ((secured, 'secured'),
                           (valid_client_cert, 'valid-client-cert'),
                           (no_penalty, 'no-penalty')):
            if flag:
                args.append(name)

        resp = self._SUPPORTED[mechanism](uname, pwd)
        args.append('resp=' + base64.b64encode(resp))

        self.fh.write("AUTH\t{}\t{}\tservice={}\t{}\n".format(self.req_id,
                                                              mechanism,
                                                              self.service,
                                                              '\t'.join(args)))
        self.fh.flush()

        response = self._read_line()
        if response[0] == 'OK':
            return True, _parse_args(response[2:])
        if response[0] == 'FAIL':
            return False, _parse_args(response[2:])
        # I don't know what else to do with continues...
        self._previous_cont = response[2]
        return None, self._previous_cont

    def cont(self):
        """
        Send CONT request.
        """
        self.fh.write("CONT\t{}\t{}\n".format(self.req_id,
                                              self._previous_cont))
        self.fh.flush()


def main():
    """
    Demonstration client.
    """
    parser = argparse.ArgumentParser(description='Demo client.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--unix', help='Unix socket path')
    group.add_argument('--inet', help='Inet address:port')
    parser.add_argument('--service', default='imap', help='Service name')
    parser.add_argument('--user', default=os.environ['USER'], help='Username')
    parser.add_argument('--mech', default='PLAIN', help='SASL mechanism')
    args = parser.parse_args()

    inet = _parse_inet(args.inet)
    with connect(args.service, unix=args.unix, inet=inet) as proto:
        pwd = getpass.getpass()
        print(proto.auth(args.mech, args.user, pwd))


if __name__ == '__main__':
    main()
