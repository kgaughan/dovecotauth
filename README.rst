===========
dovecotauth
===========

A client for the `Dovecot Authentication Protocol v1.1`__.

.. __: https://wiki2.dovecot.org/Design/AuthProtocol

Why?
====

Dovecot is a convenient authentication backend for some stuff running on my
server, most notably the OpenID provider it looks as if I'm going to have to
write, and it's less trouble to write a small client to talk to it than get
something talking to PAM.

I figure that somebody might be in the same position, so why not unbundle it
from the OpenID provider.

Development
===========

To set up your development environment, run::

    make dev

To upload a new release to PyPI::

    make release

Usage
=====

.. note::
   This API is subject to change.

Use the ``connect`` context manager to connect to a DAP server. This takes a
``service`` name (such as 'imap') and either a path to a Unix domain socket or in
the ``unix`` named parameter, or a tuple consisting of a hostname and port
number in the ``inet`` named parameter.

The context manager returns a ``Protocol`` object, on which you can called the
``auth`` method. This takes the name of a SASL_ mechanism (currently only
'PLAIN' is supported), a username, and a password, as well as a number of
additional arguments optional arguments, which I need to document.

The return value is a two tuple, consisting of a boolean indicating success or
failure and the arguments of the response as a dictionary, or ``None``,
indicating a *CONT* response and that further data is needed.

For instance::

    with connect('imap', unix='./auth.sock') as conn:
        status, flags = conn.auth('imap', username, password)
        if status:
            print("Authentication succeeded")
        else:
            print("Authentication failed or needs more data")

Demos
=====

The library comes with two demonstrations, allowing you to test it out
separately from Dovecot itself. Running ``dovecotauth.py server`` will give
you a simple DAP server, and ``dovecotauth.py client`` gives you a
command-line client. Note, however, that both are not intended to be robust,
but just to give you enough to test things out.

Both share two flags ``--unix`` and ``--inet``. The former lets you specify
a Unix domain socket path, and the latter allows you to specify an address to
bind/connect to in the form *address:port*.

The client also allows you to specify the service name with the ``--service``
flag ('imap' by default), the SASL_ mechanism to use with the ``--mech`` flag
(currently only 'PLAIN' is supported, so this can be ignored for now), and a
username, which defaults to the value of the ``USER`` environment variable.

For example::

    ./dovecotauth.py client --unix ./auth.sock --user user

You will then be prompted for a password.

The server takes a flag, ``--htpasswd``, which allows you to specify the path
to a htpasswd_ file to authenticate against::

    ./dovecotauth.py server --unix ./auth.sock --htpasswd ./passwd

.. _SASL: https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer
.. _htpasswd: https://httpd.apache.org/docs/2.4/en/programs/htpasswd.html

.. vim:set ft=rst:
