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
- Because the broker adds the token, it also decides which requests to an
  opened destination go out at all: only those about a repo listed in the
  `github` part of rules.yaml, and only what that part allows there.
  github_policy.py makes that decision for each request, and
  github_request.py joins it with the token swap.
- Each decision is written as one line on standard output:

      2026-01-31T12:00:00+01:00 allowed api.anthropic.com 443 connect
      2026-01-31T12:00:01+01:00 refused example.com 443 connect host-not-listed
      2026-01-31T12:00:02+01:00 allowed github.com 443 https GET /o/r/info/refs 200 git-read
      2026-01-31T12:00:03+01:00 refused github.com 443 https GET /x/y/info/refs repo-not-listed

  The fields are the time, the decision, the host, the port, how the request
  arrived, and for a refusal the reason. For a request to an opened
  destination the line also has the method, the path without its query
  string, the status of the answer, and what kind of request the policy
  found it to be. Nothing else from inside a request
  is logged: no headers, no bodies, no tokens. For a destination that is
  passed on untouched, the site named at the start of the encrypted
  connection is checked, but what is sent after that cannot be seen here.
  Two more kinds of line exist: "started" when the broker starts, and
  "failed" when an allowed destination could not be reached.

It fails closed, in four ways:

- If rules.yaml is missing or has a mistake, or a token that a rule asks for
  was not handed over, the broker prints the reason and exits. mitmproxy
  itself exits when this file cannot be loaded.
- If the code below fails while it decides about a request or a connection,
  that request or connection is refused. mitmproxy by itself would log the
  error and carry on as if the code had agreed. See `fail_closed`.
- If mitmproxy is not the version that limits.py was written for, the broker
  does not start.
- If mitmproxy would run with a setting that the broker does not allow, or
  finds a settings file in its folder, the broker does not start. Some of
  mitmproxy's settings rewrite a request after the broker has judged it.
  See settings.py.

What the VM can make the broker hold in memory is bounded: limits.py bounds
what a connection may send before it makes sense, bodies are passed on in
pieces (swap.reads_body), and MAX_CLIENTS bounds the connections.

Started by `nix run .#broker`, which runs mitmdump with this file as its
script and the path of the rules file in AGENT_BROKER_RULES. The tokens are
fetched before that, by fetch_tokens.py, and arrive here on an open pipe
whose number is in AGENT_BROKER_TOKENS_FD. This file runs no other program
and reads no token from a file or an environment variable.

The start command runs all of this inside a sandbox of macOS, with the
profile sandbox.sb: a bug here or in mitmproxy then reaches the broker's own
folder and port 443, not the user's files. The broker asks macOS at start
whether it is held that way, and does not run if it is not (confinement.py).
"""

import atexit
import functools
import ipaddress
import os
import re
import stat
import sys
import threading
from dataclasses import dataclass
from datetime import datetime

from mitmproxy import connection, ctx, hooks, http, tls
from mitmproxy import flow as mitmproxy_flow
from mitmproxy.proxy import server_hooks
from OpenSSL import SSL
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

# These lie next to this file. mitmproxy puts this file's folder on the
# search path before loading it.
import confinement
import github_policy
import github_request
import limits
import settings
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

# How many connections from the VM the broker holds at once. Each one can
# make the broker keep a bounded amount in memory (see limits.py and
# swap.MAX_READ_BODY), so this bounds the total, at roughly 1.5 MiB each in
# the worst case. Ordinary use is a few dozen: git, gh and each agent's
# connection to its model.
MAX_CLIENTS = 256

# Every key a destination may have. An unknown key is an error rather than
# ignored, so a typing mistake cannot quietly change what a rule means. Later
# phases add their keys here.
DESTINATION_KEYS = {"host", "inspect", "note", "ports", "token"}

# Where the broker notes, on a request, how far it has come with it, and
# what kind of request the policy found it to be.
STATE = "nixt3"
KIND = "nixt3-kind"


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


def load_rules(path: str) -> tuple[dict[str, Rule], github_policy.Policy | None]:
    """Read rules.yaml. Returns the rule for each host name, and the policy.

    The policy is the `github` part of the file: which repos the agent may
    use, and how. It is None only when the file opens no host at all. Host
    names are stored in lower case. Any mistake raises RulesError.
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
    unknown = set(data) - {"destinations", "github"}
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

    # The broker adds the token to what it lets through to an opened host,
    # so there must be rules for what that may be. See github_request.py.
    try:
        policy = github_request.load_policy(
            data, [host for host, rule in rules.items() if rule.inspect]
        )
    except github_policy.PolicyError as error:
        raise RulesError(str(error)) from error
    return rules, policy


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
    "trailers": (
        "the request announces lines after its body (a Trailer header), which "
        "the broker does not pass on."
    ),
    "upgrade": (
        "the request asks to switch to another protocol (an Upgrade header), "
        "such as WebSocket, which the broker does not pass on."
    ),
    "body-not-read": (
        "this request to {host} has a body that is larger than the broker "
        "reads (1 MiB), or that does not say how long it is. The broker "
        "has to read the body of a request to the GitHub API to decide "
        "about it, so it does not pass on one it cannot read."
    ),
    "no-policy": (
        "the broker has no rules for what may be sent to {host}. This is a "
        "mistake in how it was started on the host."
    ),
    "odd-method": (
        "the request's method is not written in capital letters, as in GET "
        "or POST. The broker passes a request on as it was sent, so it does "
        "not guess what a method in another spelling is meant to be."
    ),
    "odd-connection-header": (
        "the request has a Connection header that says more than `close` or "
        "`keep-alive`. Such a header can tell a server to drop other headers "
        "of the request, after the broker has looked at them."
    ),
    "odd-header": (
        "one of the request's header lines is split over several lines, or "
        "holds a character outside plain ASCII, such as a line break, a "
        "control character or an accented letter. The broker does not pass "
        "that on."
    ),
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


def as_sent(request: http.Request) -> tuple[str, str]:
    """A request's method and target, exactly as they were sent.

    The target is what followed the method in the first line: the path, with
    the query string if there is one.

    mitmproxy offers these as `request.method` and `request.path`, but those
    are for convenience, not for judging: `request.method` is in upper case
    whatever arrived, while the bytes that mitmproxy sends on keep their
    spelling. A request sent as `delete /repos/...` would be judged as
    DELETE and reach GitHub as `delete`. So the broker reads the bytes
    themselves, `request.data`, which is what mitmproxy sends on, and reads
    each byte as one character, so that no two byte strings look alike.
    """
    return request.data.method.decode("latin-1"), request.data.path.decode("latin-1")


def settings_problems() -> list[str]:
    """What is wrong with the settings mitmproxy runs with. See settings.py."""
    problems = [
        f"{path} is a settings file for mitmproxy, which reads it without "
        "being asked. Remove it"
        for path in settings.config_files(ctx.options.confdir)
    ]
    names = list(ctx.options.keys())
    return problems + settings.unreviewed(
        {name: getattr(ctx.options, name) for name in names},
        {name: ctx.options.default(name) for name in names},
    )


def limit_passed(reason: str, context: object, from_vm: bool) -> None:
    """limits.py closed a connection that sent more than the broker takes in."""
    address = getattr(getattr(context, "server", None), "address", None)
    host, port = (address[0], address[1]) if address else ("-", 0)
    log("refused" if from_vm else "failed", host, port, "limit", reason)


# --- Failing closed -----------------------------------------------------------
#
# mitmproxy calls the methods of Broker below ("hooks") at fixed points: when
# a connection comes in, when a request's first lines have arrived, and so
# on. If such a method stops with an error, mitmproxy logs the error and
# carries on as if the method had done nothing. For a method whose job is to
# refuse things, doing nothing means letting them through.
#
# So every hook is wrapped. When one fails for a reason nobody foresaw, the
# wrapper writes a `refused ... broker-error` line and stops the thing the
# hook was deciding about. ON_FAILURE says how, per hook. `fail_closed`
# applies the wrapper to the whole class, and refuses to load a class that
# has a hook without an entry, so that a hook added later cannot be left out.


def _stop_flow(broker: "Broker", flow: http.HTTPFlow) -> None:
    """End a request without passing it, or its answer, on."""
    flow.metadata[STATE] = "refused"
    try:
        if flow.killable:
            flow.kill()
    except Exception:
        flow.error = mitmproxy_flow.Error(mitmproxy_flow.Error.KILLED_MESSAGE)


def _stop_client(broker: "Broker", client: connection.Client) -> None:
    client.error = REFUSED_OUTGOING


def _stop_hello(broker: "Broker", data: tls.ClientHelloData) -> None:
    """Neither pass the TLS connection on nor open it: tls_start_client ends it."""
    data.ignore_connection = False
    broker.opening.discard(data.context.client.id)


def _stop_tls(broker: "Broker", data: tls.TlsData) -> None:
    """Make the handshake fail, as for a refused connection."""
    broker.opening.discard(data.context.client.id)
    data.ssl_conn = SSL.Connection(SSL.Context(SSL.TLS_SERVER_METHOD))
    data.ssl_conn.set_accept_state()


def _stop_server(broker: "Broker", data: server_hooks.ServerConnectionHookData) -> None:
    data.server.error = REFUSED_OUTGOING


def _stop_nothing(broker: "Broker", data: object) -> None:
    """For hooks that decide nothing: they only note or log."""


def _stop_broker(broker: "Broker", data: object) -> None:
    """Refuse every connection from now on, and end the broker."""
    broker.blocked = True
    ctx.master.shutdown()


ON_FAILURE = {
    "running": _stop_broker,
    "configure": _stop_broker,
    "client_connected": _stop_client,
    "client_disconnected": _stop_nothing,
    "http_connect": _stop_flow,
    "requestheaders": _stop_flow,
    "request": _stop_flow,
    "responseheaders": _stop_flow,
    "error": _stop_nothing,
    "tls_clienthello": _stop_hello,
    "tls_start_client": _stop_tls,
    "server_connect": _stop_server,
    "server_connect_error": _stop_nothing,
}


def _place(data: object) -> tuple[object, object]:
    """The host and port that a hook's argument is about, for the log."""
    request = getattr(data, "request", None)
    if request is not None:
        return request.host, request.port
    for holder in (getattr(data, "server", None), getattr(getattr(data, "context", None), "server", None)):
        address = getattr(holder, "address", None)
        if address:
            return address[0], address[1]
    return "-", 0


def _guarded(name: str, hook, stop):
    @functools.wraps(hook)
    def guarded(self, *arguments):
        # Most hooks are given one thing to decide about. `running` is
        # given nothing.
        data = arguments[0] if arguments else None
        try:
            return hook(self, *arguments)
        except Exception as error:
            # First stop it, then say so: writing the log line may be the
            # very thing that fails.
            try:
                stop(self, data)
            except Exception:
                pass
            try:
                # The kind of error and where it arose, never its message:
                # a message can hold parts of the request, or a token.
                trace, where = error.__traceback__, "-"
                while trace is not None:
                    code = trace.tb_frame.f_code
                    where = f"{os.path.basename(code.co_filename)}:{trace.tb_lineno}"
                    trace = trace.tb_next
                host, port = _place(data)
                log("refused", host, port, name, "broker-error", type(error).__name__, where)
            except Exception:
                pass

    return guarded


def fail_closed(cls):
    """Wrap every hook of a class so that an error in it refuses, see above."""
    for name in ON_FAILURE:
        if name not in hooks.all_hooks:
            raise TypeError(f"mitmproxy has no hook called `{name}` (ON_FAILURE in proxy.py)")
    for name in hooks.all_hooks:
        hook = cls.__dict__.get(name)
        if hook is None:
            continue
        if name not in ON_FAILURE:
            raise TypeError(
                f"the hook `{name}` has no entry in ON_FAILURE in proxy.py. "
                "Say there what must happen when it fails"
            )
        setattr(cls, name, _guarded(name, hook, ON_FAILURE[name]))
    return cls


@fail_closed
class Broker:
    def __init__(
        self,
        rules: dict[str, Rule],
        policy: github_policy.Policy | None,
        tokens: dict[str, swap.Secret],
    ) -> None:
        self.rules = rules
        self.policy = policy
        self.tokens = tokens
        # True when the broker has found that it must not run: it then
        # refuses every connection until it has ended.
        self.blocked = False
        # The connections from the VM that are open now.
        self.clients: set[str] = set()
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

    def refuse(
        self,
        flow: http.HTTPFlow,
        how: str,
        reason: str,
        *details: object,
        message: str | None = None,
    ) -> None:
        """Log a refusal, and answer the request with a 403 that explains it.

        `details` are extra log fields that go before the reason: for an
        opened request, its method and path. `message` is the whole text
        for the VM when the policy wrote one; it is never logged, because it
        can repeat part of the request.

        A request whose body is large, or of unknown size, gets no answer.
        Its connection is closed instead, which the program in the VM sees
        as a failed request within about a second. To answer it, the broker
        would first have to take in the whole body, and a program in the VM
        could use that to fill the Mac's memory with a request that never
        ends.

        Which of the two a request is can be told from its first lines,
        because the broker speaks only HTTP/1 with the VM (`http2=false` in
        the start command). In HTTP/2 a request may carry a body without
        declaring one, and there would be no telling.
        """
        host, port = flow.request.host, flow.request.port
        log("refused", host, port, how, *details, reason)
        flow.metadata[STATE] = "refused"
        # mitmproxy may have decided, before the broker was asked, to pass
        # this request's body on in pieces as it arrives, which means
        # sending the request's first lines to the server at once. A
        # refused request must not go anywhere.
        flow.request.stream = False

        method, target = as_sent(flow.request)
        if method != "CONNECT" and not self.body_is_small(flow):
            flow.kill()
            return

        if message is None:
            if reason == "port-not-listed":
                allowed = ", ".join(map(str, sorted(self.rules[host.lower()].ports)))
                what = (
                    f"{host} is an allowed destination, but not on port {port}. "
                    f"Allowed on this host: port {allowed}."
                )
            else:
                what = REFUSALS.get(reason, "this request to {host} is not allowed ({reason}).")
                what = what.format(host=host, port=port, reason=reason)
            message = f"Refused by the sandbox broker: {what}\n\n{REFUSAL_HELP}"
        if how == "https":
            # A request to an opened host. For the API the text is wrapped
            # the way `gh` expects an error, or `gh` would not show it.
            status, body, content_type = github_request.refusal_answer(host, target, message)
        else:
            status, body, content_type = 403, message.encode("utf-8"), "text/plain; charset=utf-8"
        flow.response = http.Response.make(status, body, {"Content-Type": content_type})
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

    def stopping(self, flow: http.HTTPFlow, how: str) -> bool:
        """End a request when the broker has found that it must not run.

        A broker that is stopping refuses new connections. This is for the
        requests that were under way on a connection it already had: they
        must not be finished under settings that the broker does not allow.
        """
        if not self.blocked:
            return False
        log("refused", flow.request.host, flow.request.port, how, "broker-stopping")
        flow.metadata[STATE] = "refused"
        flow.request.stream = False
        if flow.killable:
            flow.kill()
        return True

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """A program in the VM asks for a tunnel to host:port."""
        if self.stopping(flow, "connect"):
            return
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

    def check_settings(self) -> None:
        """Stop the broker if mitmproxy's settings are not what it allows.

        start() below makes the same check before the broker listens, and
        does not start it if the check fails. This is for what happens
        after that. From here the broker cannot simply not start, so it
        refuses every connection from now on and tells mitmproxy to end.
        """
        problems = settings_problems()
        if problems:
            self.blocked = True
            print(
                "broker: stopping, because mitmproxy runs with settings the "
                "broker does not allow.",
                *(f"broker: {problem}" for problem in problems),
                sep="\n",
                file=sys.stderr,
                flush=True,
            )
            ctx.master.shutdown()

    def running(self) -> None:
        """mitmproxy has started. Check its settings once more.

        By now mitmproxy has read everything it reads at start, so this is
        the check of what it really runs with. A settings file that appeared
        in its folder after start() looked is found here. See settings.py.
        """
        self.check_settings()

    def configure(self, updated: set[str]) -> None:
        """One of mitmproxy's settings was changed. Check them again.

        mitmproxy calls this whenever a setting changes, also long after
        the start: another script, or a command given to mitmproxy while it
        runs, can change one. A setting such as `modify_headers`, turned on
        an hour in, would rewrite requests after the broker judged them
        just as it would from the start.
        """
        self.check_settings()

    def client_connected(self, client: connection.Client) -> None:
        """A program in the VM connects. Refuse it when there are too many."""
        if self.blocked:
            log("refused", "-", 0, "connection", "broker-stopping")
            client.error = REFUSED_OUTGOING
            return
        if len(self.clients) >= MAX_CLIENTS:
            log("refused", "-", 0, "connection", "too-many-connections")
            client.error = REFUSED_OUTGOING
            return
        self.clients.add(client.id)

    def client_disconnected(self, client: connection.Client) -> None:
        """A connection from the VM ended. Forget what was noted about it."""
        self.clients.discard(client.id)
        self.tunnels.pop(client.id, None)
        self.opening.discard(client.id)

    @staticmethod
    def unwanted(request: http.Request) -> str | None:
        """Why a readable request is refused for what it asks of the broker.

        Three things mitmproxy would do with a request are not safe here.
        Lines after a chunked body ("trailers") it cannot pass on at all.
        A request to switch the connection to another protocol, such as
        WebSocket, would have mitmproxy collect each message of that
        protocol in memory, however long.

        And a header whose value runs on over a second line, or holds a
        stray line-break character, mitmproxy reads as one header and sends
        on as it came. A server that reads the second line as a header of
        its own would then see a header the broker never did: a login the
        broker did not check, or a header the broker meant to leave out.
        So no header may hold a line break at all.
        """
        for name, value in request.headers.fields:
            if any(mark in part for part in (name, value) for mark in (b"\r", b"\n")):
                return "odd-header"
        # Nor any other byte outside plain ASCII: programs disagree about
        # what such a byte in a header means. See swap.headers_are_plain.
        if not swap.headers_are_plain(
            [
                (name.decode("latin-1"), value.decode("latin-1"))
                for name, value in request.headers.fields
            ]
        ):
            return "odd-header"
        if "trailer" in request.headers:
            return "trailers"
        if "upgrade" in request.headers:
            return "upgrade"
        return None

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
        with a body that never ends. The first lines themselves are bounded
        before this method is called, by limits.py.
        """
        if self.stopping(flow, "http"):
            return
        tunnel = self.tunnels.get(flow.client_conn.id)
        if tunnel is None:
            host, port = flow.request.host, flow.request.port
            rule = self.rules.get(host.lower())
            reason = self.refusal(host, port)
            if reason is None and rule.inspect:
                # An opened destination is never contacted without
                # encryption, on whatever port.
                reason = "clear-text"
            reason = reason or self.unwanted(flow.request)
            if reason is not None:
                self.refuse(flow, "http", reason)
            else:
                log("allowed", host, port, "http")
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
        method, target = as_sent(request)
        path, _ = swap.split_path(target)

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
        elif not re.fullmatch(r"[A-Z]+", method):
            # A method in lower or mixed case, such as `delete`. Servers
            # differ on whether that is DELETE, an unknown method, or an
            # error, and the broker passes on what it was sent. No real
            # program writes a method that way, so it is refused.
            reason = "odd-method"
        elif method == "TRACE":
            # A TRACE request asks the server to send the request back,
            # and that would include the real token.
            reason = "method-not-passed-on"
        elif not swap.connection_is_plain(request.headers.get_all("connection")):
            reason = "odd-connection-header"
        elif self.unwanted(request) is not None:
            reason = self.unwanted(request)
        elif not swap.names_the_host(
            # The bytes, not `request.authority`, which mitmproxy decodes
            # from the form that names in other alphabets are sent in.
            request.data.authority.decode("latin-1"),
            request.headers.get_all("host"),
            host,
            port,
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

        # Whether the policy needs the body to decide, see github_request.py.
        when = github_request.when_to_decide(host, self.body_is_small(flow))
        if when == "refuse":
            self.refuse(flow, "https", "body-not-read", method, path)
        elif when == "after-body":
            # The request is decided on and passed on from request() below.
            # Nothing of it may be sent before that. mitmproxy may have
            # chosen to pass the body on in pieces, by a setting of its
            # own, before the broker was asked; that is undone here.
            flow.request.stream = False
            flow.metadata[STATE] = "reading"
        elif self.pass_on(flow, body=None):
            flow.request.stream = True

    def request(self, flow: http.HTTPFlow) -> None:
        """The whole of a request has arrived, body included."""
        if flow.metadata.get(STATE) != "reading":
            return
        # The body as it was sent, not unpacked: the policy must judge the
        # bytes GitHub will get, and it refuses a compressed body itself.
        self.pass_on(flow, flow.request.raw_content or b"")

    def token_for(self, rule: Rule) -> swap.Secret | None:
        return self.tokens.get(rule.token) if rule.token else None

    def pass_on(self, flow: http.HTTPFlow, body: bytes | None) -> bool:
        """The last step for an opened request. True when it may leave.

        This is where the policy decides: which repo the request is about,
        what it does there, and whether that is allowed
        (github_policy.py, called through github_request.plan). Every
        request to an opened host comes through here before the token is
        put in and before anything is sent. `body` is the whole body, or
        None when it was not read because the policy does not need it.

        What the policy is given is the request as it arrived and as it
        will be sent on: the method, the path and query string, the headers
        and the body are handed over unchanged, and nothing about them is
        changed before the policy has agreed. The host is the one the
        tunnel was opened for, which opened_request() has checked against
        the name in the encrypted connection and in the Host header.
        """
        if self.stopping(flow, "https"):
            return False
        request = flow.request
        host = request.host.lower()
        method, target = as_sent(request)
        path, _ = swap.split_path(target)
        # The headers as the bytes that arrived, one character per byte,
        # like the method and the target. See as_sent().
        headers = [
            (name.decode("latin-1"), value.decode("latin-1"))
            for name, value in request.headers.fields
        ]
        # The host the request names. opened_request() has made sure that
        # every Host header names the tunnel's host; with more than one,
        # the policy is told of none and refuses.
        named = [value for name, value in headers if name.lower() == "host"]

        plan = github_request.plan(
            self.policy,
            self.token_for(self.rules[host]),
            method=method,
            host=host,
            target=target,
            headers=headers,
            authority=named[0] if len(named) == 1 else None,
            body=body,
        )
        if not plan.allowed:
            self.refuse(flow, "https", plan.reason, method, path, message=plan.message)
            return False

        if plan.authorization is None:
            # No login was sent, or the policy allows this request only
            # without the token: it reads a repo that is not listed.
            request.headers.pop("authorization", None)
        else:
            request.headers["authorization"] = plan.authorization
        if plan.body is not None:
            # The body written out afresh from what the policy read, so
            # that GitHub reads exactly what was judged.
            request.content = plan.body
        flow.metadata[KIND] = plan.kind if plan.with_token else f"{plan.kind}-without-token"
        # A cookie is a login too: one copied from a browser gives access to
        # the account it was taken from. Nothing in the VM needs GitHub's
        # cookies, so they are left out instead of refused; a program that
        # keeps the harmless cookies of an earlier answer still works.
        request.headers.pop("cookie", None)
        request.headers.pop("proxy-authorization", None)
        # Headers that claim the request is really for another host or has
        # another method than it says, see swap.DROPPED_HEADERS.
        for name in {name for name in request.headers if swap.drops_header(name)}:
            request.headers.pop(name, None)
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
        # A closed connection is a poor way to tell the VM that an answer
        # is complete: it reaches the VM a second late (see the forward in
        # vm/default.nix), and looks the same as an answer that was cut
        # off. So such an answer is sent to the VM in pieces that each
        # state their size ("chunked"), with a last piece that marks the
        # end.
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
            method, target = as_sent(request)
            log(
                "allowed", request.host, request.port, "https",
                method, swap.split_path(target)[0], response.status_code, flow.metadata.get(KIND, "-"),
            )  # fmt: skip
            flow.metadata[STATE] = "answered"

    def error(self, flow: http.HTTPFlow) -> None:
        """A request that was passed on got no answer. Say so in the log."""
        if flow.metadata.get(STATE) != "passed-on":
            return
        if flow.error and flow.error.msg.startswith(limits.MARK):
            # Cut off by limits.py, which has written its own line.
            flow.metadata[STATE] = "refused"
            return
        request = flow.request
        method, target = as_sent(request)
        log(
            "failed", request.host, request.port, "https",
            method, swap.split_path(target)[0], flow.error.msg if flow.error else "-",
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
        if self.blocked:
            reason = "broker-stopping"
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


def scrub_output(secrets: list[swap.Secret]) -> None:
    """From here on, replace tokens in everything this process writes.

    log() above already does so for the broker's own lines. But mitmproxy
    and Python write to the same log, for example when something fails, and
    nothing in the broker's code is passed by those lines. So the two output
    channels of the process are each pointed at a pipe, and a small helper
    copies what comes out of the pipe to where the output went before, with
    tokens replaced (swap.copy_scrubbed). Nothing reaches the log unread.
    """
    if not secrets:
        return
    sys.stdout.flush()
    sys.stderr.flush()
    restore, helpers = [], []
    for number in (1, 2):  # standard output and standard error
        original = os.dup(number)
        read_end, write_end = os.pipe()
        os.dup2(write_end, number)
        os.close(write_end)
        helper = threading.Thread(
            target=swap.copy_scrubbed, args=(read_end, original, secrets), daemon=True
        )
        helper.start()
        restore.append((original, number))
        helpers.append(helper)

    def finish() -> None:
        """At exit, let the helpers write out what they still hold."""
        sys.stdout.flush()
        sys.stderr.flush()
        for original, number in restore:
            os.dup2(original, number)  # Closes the pipe, which ends the helper.
        for helper in helpers:
            helper.join(2)

    atexit.register(finish)


def start() -> Broker:
    try:
        limits.install(limit_passed)
    except limits.LimitsError as error:
        print(
            f"broker: not starting, because its limits do not fit this mitmproxy.\n"
            f"broker: {error}",
            file=sys.stderr,
            flush=True,
        )
        # Carrying on would mean a broker whose memory the VM can fill.
        sys.exit(1)

    # The variables this process was started with. mitmproxy has read some
    # of them already, so all that is left is not to run.
    problems = settings.unreviewed_environment(os.environ)
    if problems:
        print(
            "broker: not starting, because of what is in its environment.",
            *(f"broker: {problem}" for problem in problems),
            "broker: mitmproxy, Python and the TLS library read variables that "
            "change what they do or make them write data to a file. Start the "
            "broker with `nix run .#broker`, which gives it an environment of "
            "its own. broker/settings.py in the nixt3 repo has the list.",
            sep="\n",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)

    problems = settings_problems()
    if problems:
        print(
            "broker: not starting, because mitmproxy would run with settings "
            "the broker does not allow.",
            *(f"broker: {problem}" for problem in problems),
            "broker: broker/settings.py in the nixt3 repo says which settings "
            "are allowed and why.",
            sep="\n",
            file=sys.stderr,
            flush=True,
        )
        # Such a setting can change a request after the broker judged it.
        sys.exit(1)

    # The sandbox. The start command puts it on before this process starts;
    # here macOS is asked whether it holds. This comes before the rules are
    # read and the tokens are taken, so a broker that is not confined never
    # holds a token.
    problems = confinement.problems(os.getpid(), os.path.expanduser(ctx.options.confdir))
    if problems:
        print(
            "broker: not starting, because it is not confined. The broker reads "
            "what the VM sends, so it runs only inside the sandbox of "
            "broker/sandbox.sb.",
            *(f"broker: {problem}" for problem in problems),
            "broker: start it with `nix run .#broker` or `nix run .#vm`, which "
            "put the sandbox on.",
            sep="\n",
            file=sys.stderr,
            flush=True,
        )
        sys.exit(1)

    path = os.environ.get(RULES_ENV)
    try:
        if not path:
            raise RulesError(f"{RULES_ENV} is not set, so there is no rules file")
        rules, policy = load_rules(path)
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
    scrub_output(_secrets)

    log(
        "started",
        f"destinations={len(rules)}",
        f"opened={sum(rule.inspect for rule in rules.values())}",
        f"tokens={len(tokens)}",
        f"repos={len(policy.repos) if policy else 0}",
        f"rules={path}",
    )
    return Broker(rules, policy, tokens)


addons = [start()]
