"""The parts of the broker that decide about one opened request.

For a destination marked `inspect: true` in rules.yaml the broker ends the
encrypted connection itself, so it can read each request before passing it
on. This file holds the decisions it then makes, as plain functions: they take
values and return values, and know nothing of mitmproxy. That keeps them easy
to test (tests/unit/test_swap.py) and easy to read in one sitting.

The idea behind the swap: programs in the VM log in with a placeholder, a
fixed text that is not a secret. The broker replaces it with the real token on
the way out. So the VM can use the token without ever holding it.
"""

import base64
import json
import os
import re
from dataclasses import dataclass

# What programs in the VM use in place of a token. It is public and gives no
# access by itself. vm/default.nix and tests/network-lock.sh hold the same
# text; tests/unit/test_swap.py checks that the three agree.
PLACEHOLDER = "nixt3-placeholder-not-a-real-token"

# The user name sent with the real token in "Basic" logins. GitHub ignores
# the name when the password is a token; this is the one its own tools use.
BASIC_USER = "x-access-token"

# A request body no larger than this is read in full before the request is
# decided on, so that a policy can look at it. Anything larger, or of unknown
# size, is passed on piece by piece and never held in memory. Keep it at or
# below `stream_large_bodies` in darwin/commands.nix.
MAX_READ_BODY = 1024 * 1024

# What a token may consist of: visible ASCII characters, no spaces. A line
# break in a token would let it add lines of its own to a request.
TOKEN_SHAPE = re.compile(r"[\x21-\x7e]{1,4096}")

# The names a token may have in rules.yaml and the tokens file.
TOKEN_ID_SHAPE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")


class Secret:
    """A token, wrapped so that it cannot be printed by accident.

    Printing the wrapper, or an object that holds it, shows `<secret>`. The
    token itself comes out only through `reveal()`.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "<secret>"

    __str__ = __repr__


@dataclass(frozen=True)
class Credential:
    """What to do about the login a request carries.

    action   "none"    the request has no login; pass it on as it is
             "swap"    it has the placeholder; send `value` in its place
             "refuse"  it has some other login; do not pass it on
    value    for "swap", the new Authorization header
    reason   for "refuse", a short word for the log
    """

    action: str
    value: str | None = None
    reason: str | None = None


def swap_authorization(values: list[str], token: Secret | None) -> Credential:
    """Decide about the Authorization headers of one request.

    `values` holds every Authorization header the request has. `token` is the
    real token for this destination, or None when the destination has none.

    The placeholder is accepted in the forms GitHub accepts a token in:

        Authorization: token PLACEHOLDER          gh, API clients
        Authorization: Bearer PLACEHOLDER         API clients
        Authorization: Basic base64(name:PLACEHOLDER)            git
        Authorization: Basic base64(PLACEHOLDER:)                git, old style
        Authorization: Basic base64(PLACEHOLDER:x-oauth-basic)   git, old style

    Any other login is refused rather than removed. An agent may have been
    handed a login by something it read, with instructions to push somewhere
    with it. Removing it would hide that and let the request through as an
    anonymous one; refusing it makes the attempt fail loudly and shows up in
    the broker's log.

    For "Basic", the header that goes out is built from scratch. Nothing the
    VM sent stays in it, so a second login cannot ride along in the name.
    """
    if not values:
        return Credential("none")
    if len(values) > 1:
        return Credential("refuse", reason="several-logins")

    scheme, _, rest = values[0].strip().partition(" ")
    scheme_lower = scheme.lower()
    rest = rest.strip()

    if scheme_lower in ("token", "bearer"):
        if rest != PLACEHOLDER:
            return Credential("refuse", reason="other-login")
        if token is None:
            return Credential("refuse", reason="no-token-for-host")
        return Credential("swap", value=f"{scheme} {token.reveal()}")

    if scheme_lower == "basic":
        try:
            decoded = base64.b64decode(rest, validate=True).decode("utf-8")
        except ValueError:
            # Not base64, not text, or not ASCII to begin with: each of
            # those is a kind of ValueError.
            return Credential("refuse", reason="other-login")
        name, colon, password = decoded.partition(":")
        placeholder_is_password = colon == ":" and password == PLACEHOLDER
        placeholder_is_name = (
            colon == ":" and name == PLACEHOLDER and password in ("", "x-oauth-basic")
        )
        if not (placeholder_is_password or placeholder_is_name):
            return Credential("refuse", reason="other-login")
        if token is None:
            return Credential("refuse", reason="no-token-for-host")
        pair = f"{BASIC_USER}:{token.reveal()}".encode()
        return Credential("swap", value="Basic " + base64.b64encode(pair).decode())

    return Credential("refuse", reason="other-login")


def names_the_host(
    authority: str, host_headers: list[str], host: str, port: int
) -> bool:
    """Whether a request names the host its connection was opened for.

    A request says which site it is for in its Host header, and in HTTP/2 or
    in a request line that holds a full address, in the "authority". The
    server at the other end uses those to pick the site, not the name the
    connection was made to. A company that serves many sites from the same
    machines might hand a request for `other.example` to that site even
    though it came in on a connection for `github.com`, and with it the
    token. So every name in the request has to be the host, with or without
    the port, and at least one has to be there.
    """
    allowed = {host.lower(), f"{host.lower()}:{port}"}
    names = [name.strip().lower() for name in host_headers]
    if authority:
        names.append(authority.strip().lower())
    return bool(names) and all(name in allowed for name in names)


# Headers by which a request tells a server that it is "really" something
# else: for another host, from another address, or with another method than
# its first line says. They are meant for proxies to set, and the broker is
# the proxy here, so what the VM sends in them is left out. Otherwise a rule
# about a request's method or host could be met by the first line and undone
# by a header.
DROPPED_HEADERS = frozenset(
    {
        # About the connection to the next server, not about the request.
        # `Proxy-Connection` and `Keep-Alive` can name or change what that
        # server keeps, and `TE` asks it for lines after the body. Neither
        # git nor gh sends them.
        "keep-alive",
        "proxy-connection",
        "te",
        # Claims about who sent the request and for which host.
        "forwarded",
        "x-host",
        "x-http-method",
        "x-http-method-override",
        "x-method-override",
        "x-original-url",
        "x-real-ip",
        "x-rewrite-url",
    }
)


def drops_header(name: str) -> bool:
    """Whether a request header is left out before the request is passed on."""
    name = name.strip().lower()
    return name in DROPPED_HEADERS or name.startswith("x-forwarded-")


def connection_is_plain(values: list[str]) -> bool:
    """Whether a request's Connection headers say nothing but the usual.

    `Connection: close` and `Connection: keep-alive` say what to do with the
    connection afterwards. The header can also name other headers, as in
    `Connection: keep-alive, Authorization`, which tells the next server on
    the way to remove them before it passes the request on. GitHub's own
    front servers are such a server. A request could in that way have a
    header taken out that the broker's decision rested on, after the
    decision was made. Nothing in the VM needs that, so only the two plain
    values are accepted.
    """
    return all(value.strip().lower() in ("close", "keep-alive") for value in values)


# What a header may consist of: for its name, the visible ASCII characters;
# for its value, those and the space and the tab.
HEADER_NAME = re.compile(r"[\x21-\x7e]+")
HEADER_VALUE = re.compile(r"[\t\x20-\x7e]*")


def headers_are_plain(headers: list[tuple[str, str]]) -> bool:
    """Whether every header is made of plain ASCII, name and value.

    `headers` holds each header as it was sent, one character per byte.

    A header value is passed on to GitHub byte for byte, but programs
    disagree about bytes outside plain ASCII. The policy reads a value after
    removing what Python counts as white space around it, and that is more
    than HTTP's space and tab: it includes the bytes 0x1c to 0x1f, 0x85 and
    0xa0. So `Content-Type: application/json` followed by the byte 0xa0 was
    read as `application/json`, and sent on with the byte. What GitHub makes
    of such a header nobody here knows. No real program sends one, so a
    request with one is refused.
    """
    return all(
        HEADER_NAME.fullmatch(name) and HEADER_VALUE.fullmatch(value)
        for name, value in headers
    )


def reads_body(
    http1: bool, content_lengths: list[str], has_transfer_encoding: bool
) -> bool:
    """Whether to read a request's body in full before deciding on it.

    True when the body is known to be small: its declared size is at most
    MAX_READ_BODY, or it is an HTTP/1 request that declares no body at all.
    False when the size is unknown or larger. Such a request is passed on
    piece by piece, which is what makes a large `git push` work, and it is
    decided on from its first lines alone.

    The body's real size cannot exceed what was declared: the HTTP code
    stops reading at the declared size.
    """
    if has_transfer_encoding:
        return False
    if not content_lengths:
        # HTTP/1 without a declared size has no body. HTTP/2 may still send
        # one, of any size.
        return http1
    if len(content_lengths) > 1:
        return False
    size = content_lengths[0].strip()
    # isdigit() alone would accept digits from other scripts.
    return size.isascii() and size.isdigit() and int(size) <= MAX_READ_BODY


def split_path(target: str) -> tuple[str, str]:
    """Split a request's target into the path and the query string.

    "/a/b?c=d" gives ("/a/b", "c=d"). The path is what may be logged; the
    query string can hold search words and other things that are nobody's
    business, so it never is.
    """
    target = target.partition("#")[0]
    path, _, query = target.partition("?")
    return path or "/", query


def parse_handover(text: str, needed: set[str]) -> dict[str, Secret]:
    """Read the tokens that the start command hands to the broker.

    `text` is what arrived: JSON of the form {"tokens": {"github": "..."}}.
    `needed` holds the token names that rules.yaml asks for. Raises
    ValueError when the text is not of that form or a needed token is
    missing. The message never contains any part of the text, because the
    text holds the tokens.
    """
    try:
        data = json.loads(text)
    except ValueError:
        raise ValueError("what arrived is not valid JSON") from None
    tokens = data.get("tokens") if isinstance(data, dict) else None
    if not isinstance(tokens, dict):
        raise ValueError("what arrived has no `tokens` table")

    result: dict[str, Secret] = {}
    for name in sorted(needed):
        value = tokens.get(name)
        if value is None:
            raise ValueError(f"the token `{name}` is not among them")
        if not isinstance(value, str) or not TOKEN_SHAPE.fullmatch(value):
            raise ValueError(
                f"the token `{name}` is empty or has characters a token cannot have"
            )
        if value == PLACEHOLDER:
            raise ValueError(
                f"the token `{name}` is the placeholder, not a real token"
            )
        result[name] = Secret(value)
    return result


def copy_scrubbed(source: int, target: int, secrets: list[Secret]) -> None:
    """Copy what arrives on one open file to another, with every token replaced.

    `source` and `target` are file numbers. The broker puts this between
    itself and its log: everything the process writes, by this code, by
    mitmproxy or by Python itself, goes into a pipe, and this function reads
    the other end. So no line reaches the log without passing through here.

    A token may arrive in two parts. So the last few bytes, as many as could
    be the start of a token, are held back until more arrives or the source
    is closed. Returns when the source is closed.
    """
    tokens = [secret.reveal().encode() for secret in secrets]
    hold = max((len(token) for token in tokens), default=1) - 1
    pending = b""

    def write(data: bytes) -> None:
        while data:
            try:
                data = data[os.write(target, data) :]
            except OSError:
                return  # Nobody reads the log any more. Keep taking input.

    while True:
        try:
            piece = os.read(source, 65536)
        except OSError:
            piece = b""
        pending += piece
        for token in tokens:
            pending = pending.replace(token, b"<secret>")
        if not piece:
            write(pending)
            return
        # Whole lines go out at once; a token has no line break in it.
        cut = max(pending.rfind(b"\n") + 1, len(pending) - hold)
        write(pending[:cut])
        pending = pending[cut:]


def scrub(text: str, secrets: list[Secret]) -> str:
    """Replace every token found in `text`. The last safeguard before a log.

    Nothing the broker logs should hold a token in the first place. This
    makes sure of it for text that comes from elsewhere, such as an error
    message from the HTTP code.
    """
    for secret in secrets:
        text = text.replace(secret.reveal(), "<secret>")
    return text
