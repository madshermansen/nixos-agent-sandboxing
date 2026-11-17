"""Limits that mitmproxy lacks, put into mitmproxy from the outside.

THIS FILE CHANGES MITMPROXY'S OWN CODE WHILE IT RUNS. It is the one place in
the broker that does so. Read this before updating mitmproxy.

The broker reads what the VM sends, and the VM may be hostile. Before any
part of a request can be judged, mitmproxy has to take in enough of it to
make sense of it, and in three places it takes in as much as it is sent,
without end:

1. The first lines of an HTTP/1 request (its "head"), which end at an empty
   line. A head that never ends was collected in memory for as long as it
   kept coming: the broker grew from 99 MB to 1.7 GB in a test. The same
   goes for the head of a server's answer, for the line that gives the size
   of a piece of a chunked body, and for whatever a program sends while the
   answer to its last request is still on the way. mitmproxy's own code
   marks the spot with "FIXME: protect against header size DoS".
2. The first message of a TLS connection, which may claim to be 16 MiB long.
3. The lines that may follow a chunked body ("trailers"). These are not
   collected without end, but mitmproxy cannot handle them at all: it stops
   with an error that leaves the connection half alive and fills the log.

mitmproxy has no setting for any of this. So install() below replaces three
of its functions with versions that call the original and add a limit:

- After each piece of data from a connection, whatever could not be made
  sense of yet may be at most MAX_UNREAD bytes. If it is more, the connection
  is closed. This covers every case under 1, in both directions, including a
  CONNECT request and the first line of a request, which arrive before any
  tunnel exists.
- The first TLS message may be at most MAX_HELLO bytes.
- Trailers close the connection, with a line in the log instead of an error.

With these, and with bodies never held in memory (see swap.reads_body), what
one connection can make the broker hold is bounded. proxy.py bounds the
number of connections.

Replacing another program's functions is fragile: it relies on how they look
inside. So install() first checks that each function is exactly the one this
file was written against, by a checksum of its source text. mitmproxy's
version is fixed by this repo's flake.lock, so the checksums only stop
matching when someone updates it. Then the broker refuses to start, which is
the point: a limit that silently stopped working would be worse.

When that happens: read the three functions in the new mitmproxy, check that
the replacements below still fit them, run tests/github-broker.sh, and put
the new checksums in EXPECTED. The error message prints them.
"""

import hashlib
import inspect
from collections.abc import Callable

from mitmproxy.connection import ConnectionState
from mitmproxy.proxy import commands, events
from mitmproxy.proxy.layers import tls as tls_layers
from mitmproxy.proxy.layers.http import _http1
from mitmproxy.proxy.layers.http._base import ReceiveHttp

# How much may have arrived on a connection without making sense yet. Real
# request heads are a few kilobytes; servers such as GitHub's refuse heads
# far smaller than this.
MAX_UNREAD = 128 * 1024

# How long the first message of a TLS connection may be. Real ones are a few
# kilobytes.
MAX_HELLO = 64 * 1024

# The functions that are replaced, and the SHA-256 of the source text each
# had when this file was written (mitmproxy 12.3.1).
EXPECTED = {
    "Http1Connection._handle_event": "2ac8db3e43ae743fd21f78709327091ff712e8c0addf4466f1f1f972c24750d2",
    "Http1Connection.read_body": "aece271029af36e4b7eaf84aa17ddcf4ee0efb35e7f04c842c2a7333804a71f1",
    "ClientTLSLayer.receive_handshake_data": "a0ee021f92f6d0ff887b1bf9cea7fe70c63f2625bc0d1f148948809736fcc3cb",
}

# The text of the error handed to mitmproxy when a limit is passed. proxy.py
# looks for the first word to tell these from other errors.
MARK = "broker-limit"
TOO_MUCH_UNREAD = f"{MARK}: more than {MAX_UNREAD} bytes arrived without making up a request or an answer"
TRAILERS = f"{MARK}: lines after a chunked body (trailers) are not passed on"


class LimitsError(Exception):
    """mitmproxy is not what this file was written against."""


def _targets() -> dict[str, tuple[type, str]]:
    return {
        "Http1Connection._handle_event": (_http1.Http1Connection, "_handle_event"),
        "Http1Connection.read_body": (_http1.Http1Connection, "read_body"),
        "ClientTLSLayer.receive_handshake_data": (
            tls_layers.ClientTLSLayer,
            "receive_handshake_data",
        ),
    }


def checksums() -> dict[str, str]:
    """The checksum of each function that install() replaces, as it is now."""
    found = {}
    for name, (owner, attribute) in _targets().items():
        try:
            source = inspect.getsource(owner.__dict__[attribute])
        except (KeyError, OSError, TypeError):
            found[name] = "missing"
        else:
            found[name] = hashlib.sha256(source.encode()).hexdigest()
    return found


def install(report: Callable[[str, object, bool], None]) -> None:
    """Put the limits into mitmproxy. Raises LimitsError if they do not fit.

    `report(reason, context, from_vm)` is called when a limit closes a
    connection, so that the broker can write a line in its log. `context` is
    mitmproxy's record of the connection, and `from_vm` says whether the data
    came from the VM or from a server.
    """
    found = checksums()
    if found != EXPECTED:
        changed = [name for name in EXPECTED if found.get(name) != EXPECTED[name]]
        raise LimitsError(
            "mitmproxy's code is not what broker/limits.py was written for, in: "
            + ", ".join(changed)
            + ". Was mitmproxy updated? Read the top of broker/limits.py. "
            "The checksums now are: "
            + ", ".join(f"{name}={value}" for name, value in found.items())
        )
    for needed in ("passthrough", "done", "read_headers", "ReceiveProtocolError"):
        if not hasattr(_http1.Http1Server, needed) or not hasattr(_http1.Http1Client, needed):
            raise LimitsError(f"mitmproxy's HTTP/1 code has no `{needed}` any more")

    handle_event = _http1.Http1Connection._handle_event
    read_body = _http1.Http1Connection.read_body
    receive_handshake_data = tls_layers.ClientTLSLayer.receive_handshake_data

    def give_up(connection, message: str, reason: str):
        """Close a connection whose data the broker will not go on reading."""
        from_vm = isinstance(connection, _http1.Http1Server)
        report(reason, connection.context, from_vm)

        state = connection.state
        # Forget what was collected, and take in no more.
        connection.buf = type(connection.buf)()
        connection.state = connection.done

        # Whether mitmproxy already knows of a request or answer on this
        # connection, which then has to be told that it has failed. A
        # request whose head is still being read is not known yet.
        known = connection.stream_id is not None and not (
            from_vm and state == connection.read_headers
        )
        if connection.conn.state & ConnectionState.CAN_WRITE:
            yield commands.CloseConnection(connection.conn)
        if known and state != connection.done:
            yield ReceiveHttp(
                connection.ReceiveProtocolError(
                    connection.stream_id,
                    message,
                    code=connection.ReceiveProtocolError.code,
                )
            )

    def limited_handle_event(self, event):
        yield from handle_event(self, event)
        if (
            isinstance(event, events.DataReceived)
            and self.state != self.passthrough
            and len(self.buf) > MAX_UNREAD
        ):
            yield from give_up(self, TOO_MUCH_UNREAD, "too-much-unread")

    def limited_read_body(self, event):
        try:
            yield from read_body(self, event)
        except NotImplementedError:
            # The one thing read_body() raises this for is trailers.
            yield from give_up(self, TRAILERS, "trailers")

    def limited_receive_handshake_data(self, data):
        if not self.client_hello_parsed and len(self.recv_buffer) + len(data) > MAX_HELLO:
            self.recv_buffer.clear()
            report("tls-hello-too-long", self.context, True)
            # mitmproxy knows an error that starts like this, and closes the
            # connection without more ado.
            return False, "Cannot parse ClientHello: it is too long"
        return (yield from receive_handshake_data(self, data))

    _http1.Http1Connection._handle_event = limited_handle_event
    _http1.Http1Connection.read_body = limited_read_body
    tls_layers.ClientTLSLayer.receive_handshake_data = limited_receive_handshake_data
