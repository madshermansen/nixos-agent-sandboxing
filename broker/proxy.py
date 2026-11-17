"""The broker: a mitmproxy addon that applies rules.yaml.

The agent VM can reach one thing, this proxy on the Mac. Programs in the VM
use it as an ordinary HTTP proxy, so nearly every request arrives as
"CONNECT host:443", which asks the proxy to open a tunnel to that host.

What the broker does:

- A destination (host and port) listed in rules.yaml gets its tunnel.
  Anything else gets "403" and a short text that tells the agent in the VM
  why, and what to ask the user for.
- For most destinations the encrypted traffic in the tunnel is passed on
  untouched. The broker cannot read it and the VM needs no extra certificate.
- A destination marked `inspect: true` is opened instead: the broker ends the
  encrypted connection itself, reads each request, and sends it on over a
  new encrypted connection that it checks goes to that host. This is how the
  VM uses GitHub without holding a token. Programs in the VM log in with a
  placeholder, and the broker puts the real token in its place. A request
  with any other login is refused. See swap.py for those decisions.
- Each decision is written as one line on standard output:

      2026-01-31T12:00:00+01:00 allowed api.anthropic.com 443 connect
      2026-01-31T12:00:01+01:00 refused example.com 443 connect host-not-listed
      2026-01-31T12:00:02+01:00 allowed github.com 443 https GET /o/r/info/refs 200

  The fields are the time, the decision, the host, the port, how the request
  arrived, and for a refusal the reason. For a request to an opened
  destination the line also has the method, the path without its query
  string, and the status of the answer. Nothing else from inside a request
  is logged: no headers, no bodies, no tokens. For a destination that is
  passed on untouched, the site named at the start of the encrypted
  connection is checked, but what is sent after that cannot be seen here.
  Two more kinds of line exist: "started" when the broker starts, and
  "failed" when an allowed destination could not be reached.

It fails closed. If rules.yaml is missing or has a mistake, or a token that
a rule asks for was not handed over, the broker prints the reason and exits.
mitmproxy itself exits when this file cannot be loaded.

Started by `nix run .#broker`, which runs mitmdump with this file as its
script and the path of the rules file in AGENT_BROKER_RULES. The tokens are
fetched before that, by fetch_tokens.py, and arrive here on an open pipe
whose number is in AGENT_BROKER_TOKENS_FD. This file runs no other program
and reads no token from a file or an environment variable.
"""

import ipaddress
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import datetime

from mitmproxy import connection, ctx, http, tls
from mitmproxy.proxy import server_hooks
from OpenSSL import SSL
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

# swap.py lies next to this file. mitmproxy puts this file's folder on the
# search path before loading it.
import swap

RULES_ENV = "AGENT_BROKER_RULES"

# Names the open pipe on which the start command hands over the tokens.
TOKENS_FD_ENV = "AGENT_BROKER_TOKENS_FD"

# More than any set of tokens needs, and small enough to read in one go.
MAX_HANDOVER = 64 * 1024

# Used for a destination that has no `ports` list.
DEFAULT_PORTS = frozenset({443})

# The number of the "encrypted client hello" part of a TLS hello message.
ENCRYPTED_CLIENT_HELLO = 0xFE0D

# The error mitmproxy is given for a connection stopped at the last gate.
REFUSED_OUTGOING = "refused by the sandbox broker"

# Every key a destination may have. An unknown key is an error rather than
# ignored, so a typing mistake cannot quietly change what a rule means. Later
# phases add their keys here.
DESTINATION_KEYS = {"host", "inspect", "note", "ports", "token"}

# Where the broker notes, on a request, how far it has come with it.
STATE = "nixt3"


# Letters, digits and hyphens, in parts separated by dots. This keeps out
# things that look right but would never match, such as "https://github.com",
# "github.com:443" and "*.github.com".
HOST_NAME = re.compile(
    r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*"
)


class RulesError(Exception):
    """rules.yaml cannot be used. The message says what to fix."""


@dataclass(frozen=True)
class Rule:
    """What rules.yaml says about one host.

    ports    the ports the VM may reach on it
    inspect  True when the broker opens the traffic instead of passing it on
    token    the name of the token to put in place of the placeholder, or
             None; only an opened destination can have one
    """

    ports: frozenset[int]
    inspect: bool = False
    token: str | None = None


def load_rules(path: str) -> dict[str, Rule]:
    """Read rules.yaml and return the rule for each host name.

    Host names are stored in lower case. Any mistake raises RulesError.
    """
    try:
        with open(path, encoding="utf-8") as file:
            data = YAML(typ="safe").load(file)
    except OSError as error:
        raise RulesError(f"cannot read it: {error.strerror}") from error
    except UnicodeDecodeError as error:
        raise RulesError("it is not plain UTF-8 text") from error
    except YAMLError as error:
        raise RulesError(f"it is not valid YAML: {error}") from error

    if not isinstance(data, dict):
        raise RulesError("it must start with a `destinations:` list")
    unknown = set(data) - {"destinations"}
    if unknown:
        raise RulesError(f"unknown top-level key: {sorted(map(str, unknown))[0]}")
    destinations = data.get("destinations")
    if not isinstance(destinations, list):
        raise RulesError("`destinations` must be a list")

    rules: dict[str, Rule] = {}
    for number, entry in enumerate(destinations, start=1):
        where = f"destination {number}"
        if not isinstance(entry, dict):
            raise RulesError(f"{where} must have a `host` and a `note`")

        host = entry.get("host")
        if not isinstance(host, str) or not host:
            raise RulesError(f"{where} has no `host`")
        where = f"{where} ({host})"
        host = host.lower()

        unknown = set(entry) - DESTINATION_KEYS
        if unknown:
            raise RulesError(
                f"{where} has an unknown key `{sorted(map(str, unknown))[0]}`. "
                f"Known keys: {', '.join(sorted(DESTINATION_KEYS))}"
            )
        if not HOST_NAME.fullmatch(host):
            raise RulesError(
                f"{where}: `host` must be one exact host name such as "
                "api.github.com, without https://, a port, a path or a wildcard"
            )
        # Besides "127.0.0.1", programs also read "127.1", "0x7f.0.0.1" and
        # "2130706433" as addresses. A real host name on the internet has a
        # dot and does not end in a number, which rules all of those out,
        # and "localhost" with them.
        if _is_ip_address(host) or "." not in host or host.rsplit(".", 1)[1].isdigit():
            raise RulesError(
                f"{where}: `host` must be a full name such as api.github.com, "
                "not an IP address or a short local name"
            )
        if host in rules:
            raise RulesError(f"{where} is listed twice")

        note = entry.get("note")
        if not isinstance(note, str) or not note.strip():
            raise RulesError(
                f"{where} has no `note`. Say in a few words why the VM needs it"
            )

        ports = entry.get("ports", sorted(DEFAULT_PORTS))
        if (
            not isinstance(ports, list)
            or not ports
            # `True` counts as a number in Python, so it is ruled out by type.
            or any(type(port) is not int or not 0 < port < 65536 for port in ports)
        ):
            raise RulesError(
                f"{where}: `ports` must be a list of port numbers, such as [443]"
            )

        inspect = entry.get("inspect", False)
        if type(inspect) is not bool:
            raise RulesError(f"{where}: `inspect` must be true or false")

        token = entry.get("token")
        if token is not None:
            if not isinstance(token, str) or not swap.TOKEN_ID_SHAPE.fullmatch(token):
                raise RulesError(
                    f"{where}: `token` must be the name of a token, in lower-case "
                    "letters, digits, `-` and `_`, such as github. The token "
                    "itself never goes in this file"
                )
            if not inspect:
                raise RulesError(
                    f"{where} has a `token` but not `inspect: true`. The broker "
                    "can only add a token to traffic that it opens"
                )

        rules[host] = Rule(frozenset(ports), inspect, token)
    return rules


class HandoverError(Exception):
    """The tokens did not arrive. The message says what to do."""


def receive_tokens(needed: set[str]) -> dict[str, swap.Secret]:
    """Take the tokens that the start command fetched, from an open pipe.

    The start command runs fetch_tokens.py, which asks the user's password
    manager, and leaves what it printed in a pipe that this process inherits.
    The pipe's number is in AGENT_BROKER_TOKENS_FD. A pipe is used because it
    is the one way to hand over a secret that no other program can look at:
    an environment variable can be read by other programs of the same user,
    and so can a file.

    The pipe is read once and closed. Raises HandoverError when a token in
    `needed` did not arrive.
    """
    number = os.environ.pop(TOKENS_FD_ENV, None)
    if number is None:
        if not needed:
            return {}
        raise HandoverError(
            f"the rules ask for the token `{sorted(needed)[0]}`, and no tokens "
            "were handed over. Start the broker with `nix run .#broker` or "
            "`nix run .#vm`; they fetch the tokens first"
        )
    try:
        fd = int(number)
        if fd < 3 or not stat.S_ISFIFO(os.fstat(fd).st_mode):
            raise ValueError
    except (ValueError, OSError):
        raise HandoverError(f"{TOKENS_FD_ENV} does not name an open pipe") from None
    with os.fdopen(fd, "rb") as pipe:
        raw = pipe.read(MAX_HANDOVER + 1)
    try:
        if len(raw) > MAX_HANDOVER:
            raise ValueError("it is too long")
        return swap.parse_handover(raw.decode("utf-8", "replace"), needed)
    except ValueError as error:
        # The messages of these errors are written with care not to hold any
        # part of what arrived.
        raise HandoverError(f"the tokens were handed over, but {error}") from None


def _is_ip_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _clean(text: object) -> str:
    """Make a value safe to be one field of a one-line log entry.

    Host names come from the VM, so they can hold anything. Fields are
    separated by spaces, so a space inside one becomes an underscore.
    """
    text = re.sub(r"\s+", "_", str(text).strip())
    return re.sub(r"[^\x21-\x7e]", "?", text)[:255] or "-"


# Every token the broker holds, so that log() can make sure none is written.
_secrets: list[swap.Secret] = []


def log(event: str, *fields: object) -> None:
    """Write one log line: the time, the event, then its fields."""
    stamp = datetime.now().astimezone().isoformat(timespec="seconds")
    line = " ".join([stamp, event, *map(_clean, fields)])
    print(swap.scrub(line, _secrets), flush=True)


# What the VM is told about each kind of refusal. The key is the reason that
# goes in the log. `{host}` and `{port}` are filled in.
REFUSALS = {
    "host-not-listed": "{host} is not an allowed destination.",
    "clear-text": (
        "requests to {host} must be encrypted. Use an https:// address."
    ),
    "clear-text-in-tunnel": (
        "the request sent through the tunnel to {host} was not encrypted. "
        "Use an https:// address."
    ),
    "not-the-opened-host": (
        "this connection was not opened for {host} on port {port}."
    ),
    "upstream-not-checked": (
        "the broker is running with certificate checks turned off, so it "
        "adds no tokens. This is a mistake in how it was started on the host."
    ),
    "not-http1": (
        "the broker reads requests to {host} in HTTP/1.1 only. This is a "
        "mistake in how it was started on the host."
    ),
    "method-not-passed-on": "this kind of request is not passed on to {host}.",
    "names-another-host": (
        "the request names another site than {host}, the one its connection "
        "was opened for."
    ),
    "other-login": (
        "the request to {host} carries a token or password that is not this "
        "sandbox's own.\n"
        "\n"
        "git and gh are already set up here. They log in with a placeholder,\n"
        "and the broker on the host puts the real token in its place, so no\n"
        "token is needed in this machine. Remove the other token or password\n"
        "from the command, the address, git's settings or the environment,\n"
        "and try again."
    ),
    "several-logins": "the request to {host} carries more than one login.",
    "no-token-for-host": (
        "the placeholder token was sent to {host}, but the broker has no "
        "token for that host."
    ),
}

REFUSAL_HELP = (
    "This machine is a sandbox. It reaches the internet only through a\n"
    "broker on the host, which passes on only what is allowed in\n"
    "broker/rules.yaml of the nixt3 repo on the host. Trying the same\n"
    "thing again, or with another tool, will not help.\n"
    "\n"
    "If the task needs this, tell the user. They can change that file and\n"
    "restart the broker.\n"
)


def is_http1(request: http.Request) -> bool:
    return request.is_http10 or request.is_http11


class Broker:
    def __init__(self, rules: dict[str, Rule], tokens: dict[str, swap.Secret]) -> None:
        self.rules = rules
        self.tokens = tokens
        # For each connection from the VM that holds a tunnel: the host and
        # port the tunnel was opened for. Everything that arrives on such a
        # connection afterwards is inside the tunnel.
        self.tunnels: dict[str, tuple[str, int]] = {}
        # Connections from the VM whose encryption the broker has agreed to
        # end itself, because they go to an opened destination.
        self.opening: set[str] = set()

    def refusal(self, host: str, port: int) -> str | None:
        """Why this destination is refused, or None when it is allowed."""
        rule = self.rules.get(host.lower())
        if rule is None:
            return "host-not-listed"
        if port not in rule.ports:
            return "port-not-listed"
        return None

    def refuse(self, flow: http.HTTPFlow, how: str, reason: str, *details: object) -> None:
        """Log a refusal, and answer the request with a 403 that explains it.

        `details` are extra log fields that go before the reason: for an
        opened request, its method and path.

        A request whose body is large, or of unknown size, gets no answer.
        Its connection is closed instead. To answer it, the broker would
        first have to take in the whole body, and a program in the VM could
        use that to fill the Mac's memory with a request that never ends.

        Which of the two a request is can be told from its first lines,
        because the broker speaks only HTTP/1 with the VM (`http2=false` in
        the start command). In HTTP/2 a request may carry a body without
        declaring one, and there would be no telling.
        """
        host, port = flow.request.host, flow.request.port
        log("refused", host, port, how, *details, reason)
        flow.metadata[STATE] = "refused"

        if flow.request.method != "CONNECT" and not self.body_is_small(flow):
            flow.kill()
            return

        if reason == "port-not-listed":
            allowed = ", ".join(map(str, sorted(self.rules[host.lower()].ports)))
            what = (
                f"{host} is an allowed destination, but not on port {port}. "
                f"Allowed on this host: port {allowed}."
            )
        else:
            # A reason without a text of its own comes from the policy.
            what = REFUSALS.get(reason, "this request to {host} is not allowed ({reason}).")
            what = what.format(host=host, port=port, reason=reason)
        flow.response = http.Response.make(
            403,
            f"Refused by the sandbox broker: {what}\n\n{REFUSAL_HELP}",
            {"Content-Type": "text/plain; charset=utf-8"},
        )
        # Many programs show only the first line of a refused CONNECT, so the
        # short version goes there as well.
        flow.response.reason = "Refused by the sandbox broker"

    def decide(self, flow: http.HTTPFlow, how: str) -> bool:
        """Allow a request by its host and port, or refuse it. True if allowed."""
        host, port = flow.request.host, flow.request.port
        reason = self.refusal(host, port)
        if reason is None:
            log("allowed", host, port, how)
            return True
        self.refuse(flow, how, reason)
        return False

    @staticmethod
    def body_is_small(flow: http.HTTPFlow) -> bool:
        """Whether the request's body is known to be small. See swap.reads_body."""
        request = flow.request
        return swap.reads_body(
            http1=is_http1(request),
            content_lengths=request.headers.get_all("content-length"),
            has_transfer_encoding="transfer-encoding" in request.headers,
        )

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """A program in the VM asks for a tunnel to host:port."""
        if flow.client_conn.id in self.tunnels:
            # A tunnel asked for inside a tunnel. Nothing honest does that,
            # and it would change where the outer tunnel leads.
            log("refused", flow.request.host, flow.request.port, "connect", "tunnel-in-tunnel")
            flow.kill()
            return
        if self.decide(flow, "connect"):
            self.tunnels[flow.client_conn.id] = (
                flow.request.host.lower(),
                flow.request.port,
            )

    def client_disconnected(self, client: connection.Client) -> None:
        """A connection from the VM ended. Forget what was noted about it."""
        self.tunnels.pop(client.id, None)
        self.opening.discard(client.id)

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        """A request the broker can read. There are three kinds.

        1. Plain HTTP sent to the broker directly, without a tunnel. It is
           allowed or refused by its host and port, like a tunnel.
        2. Plain HTTP sent inside a tunnel. A tunnel is for an encrypted
           connection; this is refused. Otherwise the broker would pass it
           on unencrypted, to a port that was allowed for encrypted traffic.
        3. A request inside a tunnel whose encryption the broker ended
           itself, which it does for an opened destination only. That is
           the kind that may get a token, see opened_request().

        mitmproxy sends a request to flow.request.host and port, so those
        are what is checked, not the Host header.

        The decision is made here, when only the first lines of the request
        have arrived, and not after the whole request has been read. A body
        is read in full only when it is known to be small; otherwise it is
        passed on piece by piece or, for a refused request, not read at
        all. That keeps a program in the VM from filling the Mac's memory
        with a request that never ends.
        """
        tunnel = self.tunnels.get(flow.client_conn.id)
        if tunnel is None:
            host, port = flow.request.host, flow.request.port
            rule = self.rules.get(host.lower())
            if rule is not None and rule.inspect and port in rule.ports:
                # An opened destination is never contacted without
                # encryption, on whatever port.
                self.refuse(flow, "http", "clear-text")
            elif self.decide(flow, "http"):
                flow.metadata[STATE] = "plain"
                flow.request.stream = True
        elif not flow.client_conn.tls_established:
            self.refuse(flow, "http", "clear-text-in-tunnel")
        else:
            self.opened_request(flow, tunnel)

    def opened_request(self, flow: http.HTTPFlow, tunnel: tuple[str, int]) -> None:
        """A request to an opened destination: check it, then pass it on.

        The first check restates what the earlier steps have made sure of,
        so that a token is only ever added when all of it holds:

        - the request is on a connection whose tunnel was opened for this
          host and port, and the rules say the host is to be opened;
        - the encrypted connection from the VM named this host;
        - the request will leave over an encrypted connection (`scheme`).
          server_connect() below makes sure that connection is checked
          against this host's name.
        """
        request = flow.request
        host, port = request.host.lower(), request.port
        rule = self.rules.get(host)
        method = request.method
        path, _ = swap.split_path(request.path)

        if (
            rule is None
            or not rule.inspect
            or port not in rule.ports
            or (host, port) != tunnel
            or (flow.client_conn.sni or "").lower() != host
            or request.scheme != "https"
        ):
            reason = "not-the-opened-host"
        elif not is_http1(request):
            # See refuse() for why. The start command turns HTTP/2 off; this
            # is for a broker started some other way.
            reason = "not-http1"
        elif ctx.options.ssl_insecure:
            # Someone started the broker with certificate checks off. Then
            # nothing proves where a token would go.
            reason = "upstream-not-checked"
        elif method.upper() == "TRACE":
            # A TRACE request asks the server to send the request back,
            # and that would include the real token.
            reason = "method-not-passed-on"
        elif not swap.names_the_host(
            request.authority, request.headers.get_all("host"), host, port
        ):
            reason = "names-another-host"
        else:
            credential = swap.swap_authorization(
                request.headers.get_all("authorization"), self.token_for(rule)
            )
            reason = credential.reason if credential.action == "refuse" else None
        if reason is not None:
            self.refuse(flow, "https", reason, method, path)
            return

        if self.body_is_small(flow):
            # Wait for the body, so that the policy can look at it. The
            # request is passed on from request() below.
            flow.metadata[STATE] = "reading"
        elif self.pass_on(flow, body=None):
            flow.request.stream = True

    def request(self, flow: http.HTTPFlow) -> None:
        """The whole of a request has arrived, body included."""
        if flow.metadata.get(STATE) != "reading":
            return
        if "content-encoding" in flow.request.headers:
            # A compressed body. Unpacking it could take far more memory
            # than its size suggests, so the policy does not get to see it.
            body = None
        else:
            body = flow.request.raw_content or b""
        self.pass_on(flow, body)

    def token_for(self, rule: Rule) -> swap.Secret | None:
        return self.tokens.get(rule.token) if rule.token else None

    def policy(
        self, method: str, host: str, path: str, query: str, body: bytes | None
    ) -> str | None:
        """Whether this request to an opened destination may be passed on.

        PHASE 5 GOES HERE. This is the one place where a request that is
        about to leave with a token can still be stopped by what it asks
        for: which repo, which action. Call the decision function of
        broker/github_policy.py from here.

        Return None to allow the request, or a short reason without spaces,
        such as "repo-not-listed". The reason goes in the log and in the
        answer to the VM. Add a text for it to REFUSALS above.

        `path` is the request's path without the query string, and `query`
        is the query string, both as the VM sent them. `body` is the body
        when it was at most swap.MAX_READ_BODY long and not compressed.
        Otherwise it is None: the body is not known here, because it is
        passed on piece by piece. A large `git push` is one such request. A
        rule that needs to see the body must refuse when it is None, or a
        request could avoid the rule by sending its body in pieces.
        """
        return None

    def pass_on(self, flow: http.HTTPFlow, body: bytes | None) -> bool:
        """The last step for an opened request. True when it may leave.

        Asks the policy, then puts the real token in place of the
        placeholder. Nothing is changed before the policy has agreed.
        """
        request = flow.request
        host = request.host.lower()
        rule = self.rules[host]
        method = request.method
        path, query = swap.split_path(request.path)

        reason = self.policy(method, host, path, query, body)
        if reason is None:
            credential = swap.swap_authorization(
                request.headers.get_all("authorization"), self.token_for(rule)
            )
            # Checked in opened_request() already; here in case the headers
            # changed in between.
            reason = credential.reason if credential.action == "refuse" else None
        if reason is not None:
            self.refuse(flow, "https", reason, method, path)
            return False

        if credential.action == "swap":
            request.headers["authorization"] = credential.value
        # A cookie is a login too: one copied from a browser gives access to
        # the account it was taken from. Nothing in the VM needs GitHub's
        # cookies, so they are left out instead of refused; a program that
        # keeps the harmless cookies of an earlier answer still works.
        request.headers.pop("cookie", None)
        request.headers.pop("proxy-authorization", None)
        # Send "GET /path", never "GET https://host/path", so that the server
        # has one place to read the host from, the Host header.
        request.authority = ""
        flow.metadata[STATE] = "passed-on"
        return True

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        """The first lines of an answer have arrived from a server.

        The broker never needs the body of an answer, so it is passed on
        to the VM piece by piece. That lets a large `git clone` through
        without holding it in memory.
        """
        state = flow.metadata.get(STATE)
        response = flow.response
        if state not in ("plain", "passed-on") or response is None:
            return
        response.stream = True

        # Some answers do not say how long they are: they end when the
        # server closes the connection. GitHub's "Bad credentials" is one.
        # The VM would wait for that end forever, because the closing of a
        # connection does not get through to it: the helper that QEMU runs
        # for each connection of the VM does not pass it on. So such an
        # answer is sent to the VM in pieces that each state their size
        # ("chunked"), with a last piece that marks the end.
        if (
            flow.request.is_http11
            and flow.request.method.upper() != "HEAD"
            and response.status_code >= 200
            and response.status_code not in (204, 304)
            and "content-length" not in response.headers
            and "transfer-encoding" not in response.headers
        ):
            response.headers["transfer-encoding"] = "chunked"
        if state == "passed-on":
            request = flow.request
            path, _ = swap.split_path(request.path)
            log(
                "allowed", request.host, request.port, "https",
                request.method, path, response.status_code,
            )  # fmt: skip
            flow.metadata[STATE] = "answered"

    def error(self, flow: http.HTTPFlow) -> None:
        """A request that was passed on got no answer. Say so in the log."""
        if flow.metadata.get(STATE) != "passed-on":
            return
        request = flow.request
        path, _ = swap.split_path(request.path)
        log(
            "failed", request.host, request.port, "https",
            request.method, path, flow.error.msg if flow.error else "-",
        )  # fmt: skip
        flow.metadata[STATE] = "failed"

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """TLS starts inside a tunnel. Decide what to do with it.

        The first TLS message names the site the program wants. It has to be
        the host the tunnel was opened for. Without this check, a tunnel to
        an allowed host would also reach every other site that shares that
        host's servers, which for a large hosting company is a lot of sites.

        An honest connection to an opened destination is ended here, by the
        broker, so that it can read the requests inside. Any other honest
        connection is passed on untouched.
        """
        address = data.context.server.address
        name = data.client_hello.sni
        if address is None:
            # TLS to the broker itself, not inside a tunnel. Nothing in the
            # VM is set up to do that.
            log("refused", "-", 0, "tls", "not-in-a-tunnel")
            return
        host, port = address[0], address[1]
        reason = self.refusal(host, port)
        if reason is not None:
            # The tunnel was refused already; this is only a safeguard.
            log("refused", host, port, "tls", reason)
        elif name is None or name.lower() != host.lower():
            log("refused", host, port, "tls", "tls-name-differs", name or "-")
        elif any(kind == ENCRYPTED_CLIENT_HELLO for kind, _ in data.client_hello.extensions):
            # The message carries a second, encrypted site name that the
            # broker cannot read, so the name it did read proves nothing.
            log("refused", host, port, "tls", "tls-name-hidden")
        elif data.context.client.tls_established:
            # A second encrypted connection inside one the broker has
            # opened. Nothing honest does that.
            log("refused", host, port, "tls", "tls-in-tls")
        elif self.rules[host.lower()].inspect:
            self.opening.add(data.context.client.id)
        else:
            data.ignore_connection = True

    def tls_start_client(self, data: tls.TlsData) -> None:
        """Answer a TLS connection that is not passed on untouched.

        For a connection to an opened destination, mitmproxy has prepared an
        answer with a certificate of its own, made for that host and signed
        by the broker's certificate authority, which the VM trusts. That is
        left as it is.

        The only other connections that get here are the ones refused
        above. Handing mitmproxy a TLS setup without a certificate makes the
        handshake fail, which closes the connection.
        """
        client = data.context.client.id
        if client in self.opening:
            self.opening.discard(client)
            return
        data.ssl_conn = SSL.Connection(SSL.Context(SSL.TLS_SERVER_METHOD))
        data.ssl_conn.set_accept_state()

    def server_connect(self, data: server_hooks.ServerConnectionHookData) -> None:
        """The last gate: mitmproxy is about to open a connection to a server.

        Every connection the broker makes passes here, whatever kind of
        request led to it. The checks above should have stopped anything
        unlisted already. This one makes sure that a case they missed is
        refused instead of let through.

        A connection to an opened destination must be encrypted, and the
        name the server has to prove is set here to the host from the
        rules. mitmproxy then refuses a server whose certificate is not
        valid for that name. So a token can only reach a server that has
        proved to be the host the rule is for.
        """
        address = data.server.address
        host, port = (address[0], address[1]) if address else ("-", 0)
        reason = "no-address" if address is None else self.refusal(host, port)
        if reason is None and self.rules[host.lower()].inspect:
            if data.server.tls:
                data.server.sni = host.lower()
            else:
                reason = "clear-text"
        if reason is not None:
            log("refused", host, port, "outgoing", reason)
            data.server.error = REFUSED_OUTGOING

    def server_connect_error(self, data: server_hooks.ServerConnectionHookData) -> None:
        """An allowed destination could not be reached, say why in the log.

        The program in the VM often sees only a closed connection, so this
        line is where to look when an allowed destination does not answer.
        """
        if data.server.error == REFUSED_OUTGOING:
            return  # Logged as refused already.
        address = data.server.address
        host, port = (address[0], address[1]) if address else ("-", 0)
        log("failed", host, port, "outgoing", data.server.error)


def start() -> Broker:
    path = os.environ.get(RULES_ENV)
    try:
        if not path:
            raise RulesError(f"{RULES_ENV} is not set, so there is no rules file")
        rules = load_rules(path)
    except RulesError as error:
        print(
            f"broker: not starting, because the rules file cannot be used.\n"
            f"broker: {path or '(no file)'}: {error}",
            file=sys.stderr,
            flush=True,
        )
        # Leaving with an error stops mitmproxy. Carrying on would mean a
        # proxy without rules, which lets everything through.
        sys.exit(1)

    try:
        tokens = receive_tokens({rule.token for rule in rules.values() if rule.token})
    except HandoverError as error:
        print(
            f"broker: not starting, because a token is missing.\nbroker: {error}",
            file=sys.stderr,
            flush=True,
        )
        # Carrying on would mean a broker that opens GitHub's traffic and
        # then cannot log in, which fails in ways that are hard to read.
        sys.exit(1)
    _secrets.extend(tokens.values())

    log(
        "started",
        f"destinations={len(rules)}",
        f"opened={sum(rule.inspect for rule in rules.values())}",
        f"tokens={len(tokens)}",
        f"rules={path}",
    )
    return Broker(rules, tokens)


addons = [start()]
