#!/usr/bin/env python3
"""
A client library for the Dovecot Authentication Protocol v1.1
"""

import argparse
import base64
import contextlib
import getpass
import os
import socket
import socketserver
import uuid


__version__ = "1.0.1"

__all__ = [
    "DovecotAuthException",
    "ConnectionException",
    "UnsupportedVersion",
    "NoSupportedMechanisms",
    "connect",
    "Protocol",
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
        yield Protocol(service, sock.makefile("rwb"))
    finally:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()


def _parse_inet(addr):
    """
    Parse inet address.
    """
    if addr is None:
        return None
    parts = addr.split(":", 1)
    if len(parts) != 2:
        raise ConnectionException("Inet address must have a port number")
    return parts[0], int(parts[1])


def _encode_plain(uname, pwd):
    """
    Encode a username/password pair with the SASL PLAIN mechanism.
    """
    # See https://tools.ietf.org/html/rfc4616
    return "\0{}\0{}".format(uname, pwd)


_SUPPORTED = {
    "PLAIN": _encode_plain,
}


def _parse_args(args):
    """
    Parse an argument list.
    """
    result = {}
    for arg in args:
        arg = arg.decode()
        if arg == "":
            continue
        if "=" in arg:
            key, value = arg.split("=", 1)
            result[key] = value
        else:
            result[arg] = True
    return result


def _read_line(fh):
    """
    Parse a protocol line.
    """
    line = fh.readline()
    if not line:
        return None
    return line.rstrip(b"\n\r").split(b"\t")


def _write_line(fh, *args):
    fh.write("\t".join(args).encode())
    fh.write(b"\n")
    fh.flush()


class Protocol(object):
    """
    Implements the actual authentication wire protocol. This doesn't depend
    on the underlying transport and takes a file object.
    """

    handshake_completed = False
    spid = None
    cuid = None
    cookie = None

    def __init__(self, service, fh):
        self.fh = fh
        self.service = service
        self.req_id = 0
        self.mechanisms = {}
        self._previous_cont = None

    def _do_handshake(self):
        """
        Perform the initial protocol handshake.
        """
        _write_line(self.fh, "VERSION", "1", "1")
        _write_line(self.fh, "CPID", str(os.getpid()))

        unsupported = []
        while True:
            args = _read_line(self.fh)
            if args is None:
                raise ConnectionException()
            if args[0] == b"DONE":
                break

            if args[0] == b"SPID":
                self.spid = args[1]
            elif args[0] == b"CUID":
                self.cuid = args[1]
            elif args[0] == b"COOKIE":
                self.cookie = args[1]
            elif args[0] == b"VERSION":
                if args[1] != b"1" and args[2] != b"1":
                    raise UnsupportedVersion(b".".join(args[1:]))
            elif args[0] == b"MECH":
                mech = args[1].decode()
                if mech in _SUPPORTED:
                    self.mechanisms[mech] = frozenset(args[2:])
                else:
                    unsupported.append(mech)

        if len(self.mechanisms) == 0:
            raise NoSupportedMechanisms(unsupported)

        self.handshake_completed = True

    def auth(
        self,
        mechanism,
        uname,
        pwd,
        secured=False,
        valid_client_cert=False,
        no_penalty=False,
        **kwargs
    ):
        """
        Send an auth request.
        """
        if not self.handshake_completed:
            self._do_handshake()

        self._previous_cont = None

        self.req_id += 1

        for prohibited in ("resp", "no-penalty", "secured", "valid-client-cert"):
            if prohibited in kwargs:
                del kwargs[prohibited]

        args = ["{}={}".format(key, value) for key, value in kwargs.items()]
        args.insert(0, "service=" + self.service)  # 'service' must be first.

        for flag, name in (
            (secured, "secured"),
            (valid_client_cert, "valid-client-cert"),
            (no_penalty, "no-penalty"),
        ):
            if flag:
                args.append(name)

        resp = _SUPPORTED[mechanism](uname, pwd)
        args.append("resp=" + base64.b64encode(resp.encode()).decode())

        _write_line(self.fh, "AUTH", str(self.req_id), mechanism, *args)

        response = _read_line(self.fh)
        if response[0] == b"OK":
            return True, _parse_args(response[2:])
        if response[0] == b"FAIL":
            return False, _parse_args(response[2:])
        # I don't know what else to do with continues...
        self._previous_cont = response[2]
        return None, self._previous_cont

    def cont(self):
        """
        Send CONT request.
        """
        if self._previous_cont is not None:
            _write_line(self.fh, "CONT", str(self.req_id), self._previous_cont)


def _add_client_arg_parser(parent):
    parser = parent.add_parser("client", help="Demo client.")
    parser.add_argument("--service", default="imap", help="Service name")
    parser.add_argument("--user", default=os.environ["USER"], help="Username")
    parser.add_argument("--mech", default="PLAIN", help="SASL mechanism")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--unix", help="Unix socket path")
    group.add_argument("--inet", help="Inet address:port")


def _client(args):
    inet = _parse_inet(args.inet)
    with connect(args.service, unix=args.unix, inet=inet) as proto:
        pwd = getpass.getpass()
        print(proto.auth(args.mech, args.user, pwd))


def _add_server_arg_parser(parent):
    parser = parent.add_parser("server", help="Demo server.")
    parser.add_argument("--htpasswd", required=True, help="Path to htpasswd file")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--unix", help="Unix socket path")
    group.add_argument("--inet", help="Inet address:port")


class _RequestHandler(socketserver.StreamRequestHandler):

    cookie = None
    cpid = None
    rid = None

    def setup(self):
        super().setup()
        self.cookie = uuid.uuid4().hex.upper()

    def read_line(self):
        line = _read_line(self.rfile)
        if line is not None and len(line) > 2 and line[0] == b"AUTH":
            self.rid = line[1].decode()
        return line

    def write_line(self, *args):
        _write_line(self.wfile, *args)

    def fail(self, **kwargs):
        args = ["FAIL", self.rid]
        for key, value in kwargs.items():
            args.append("{}={}".format(key, value))
        self.write_line(*args)

    def ok(self, *args):
        self.write_line("OK", self.rid, *args)

    def handle(self):
        line = self.read_line()
        if line != [b"VERSION", b"1", b"1"]:
            return

        line = self.read_line()
        if len(line) != 2 and line[0] != b"CPID":
            return
        self.cpid = line[1]

        self.write_line("VERSION", "1", "1")
        self.write_line("SPID", str(os.getpid()))
        self.server.cuid += 1
        self.write_line("CUID", str(self.server.cuid))
        self.write_line("COOKIE", self.cookie)

        for mechanism in _SUPPORTED:
            self.write_line("MECH", mechanism, "")
        self.write_line("DONE")

        while True:
            line = self.read_line()
            # Disconnect on a bad line or end of session
            if line is None or len(line) < 2:
                return
            if line[0] == b"AUTH":
                if len(line) < 5:
                    self.fail(reason="insufficient arguments")
                    continue
                if line[2] != b"PLAIN":
                    self.fail(reason="only PLAIN supported")
                    continue
                fields = dict(kv.decode().split("=", 1) for kv in line[3:])
                if "service" not in fields:
                    self.fail(reason="please provide a service field")
                    continue
                if "resp" not in fields:
                    self.fail(reason="please provide a resp field")
                    continue
                _, uname, passwd = base64.b64decode(fields["resp"].encode()).split(b"\0")
                if self.server.db.check_password(uname.decode(), passwd.decode()):
                    self.ok("user=" + uname.decode())
                else:
                    self.fail(reason="bad username/password pair", user=uname.decode())


def _server(args):
    from passlib import apache

    db = apache.HtpasswdFile(args.htpasswd)

    if args.unix:
        svr_class = socketserver.UnixStreamServer
        addr = args.unix
    else:
        svr_class = socketserver.TCPServer
        addr = _parse_inet(args.inet)

    with svr_class(addr, _RequestHandler) as svr:
        svr.db = db
        svr.cuid = 0
        svr.serve_forever()


def main():
    """
    Runner.
    """
    parser = argparse.ArgumentParser(description="Demo server and client.")
    subparsers = parser.add_subparsers(dest="command")
    for subparser in [_add_client_arg_parser, _add_server_arg_parser]:
        subparser(subparsers)
    args = parser.parse_args()

    if args.command == "client":
        _client(args)
    elif args.command == "server":
        _server(args)
    else:
        parser.error("No command specified.")


if __name__ == "__main__":
    main()
