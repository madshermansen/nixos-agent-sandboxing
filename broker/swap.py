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
import binascii
import json
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
        except (binascii.Error, UnicodeDecodeError):
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


def scrub(text: str, secrets: list[Secret]) -> str:
    """Replace every token found in `text`. The last safeguard before a log.

    Nothing the broker logs should hold a token in the first place. This
    makes sure of it for text that comes from elsewhere, such as an error
    message from the HTTP code.
    """
    for secret in secrets:
        text = text.replace(secret.reveal(), "<secret>")
    return text
