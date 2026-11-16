"""The broker: a mitmproxy addon that applies rules.yaml.

The agent VM can reach one thing, this proxy on the Mac. Programs in the VM
use it as an ordinary HTTP proxy, so nearly every request arrives as
"CONNECT host:443", which asks the proxy to open a tunnel to that host.

What the broker does in this phase:

- A destination (host and port) listed in rules.yaml gets its tunnel. The
  encrypted traffic inside is passed on untouched. The broker cannot read it
  and the VM needs no extra certificate.
- Anything else gets "403" and a short text that tells the agent in the VM
  why, and what to ask the user for.
- Each decision is written as one line on standard output:

      2026-01-31T12:00:00+01:00 allowed github.com 443 connect
      2026-01-31T12:00:01+01:00 refused example.com 443 connect host-not-listed

  The fields are the time, the decision, the host, the port, how the request
  arrived, and for a refusal the reason. Nothing from inside a request is
  logged: no paths, no headers, no bodies. Two more kinds of line exist:
  "started" when the broker starts, and "failed" when an allowed destination
  could not be reached.

It fails closed. If rules.yaml is missing or has a mistake, the broker prints
the reason and exits. mitmproxy itself exits when this file cannot be loaded.

Started by `nix run .#broker`, which runs mitmdump with this file as its
script and the path of the rules file in AGENT_BROKER_RULES.
"""

import ipaddress
import os
import re
import sys
from datetime import datetime

from mitmproxy import http, tls
from mitmproxy.proxy import server_hooks
from OpenSSL import SSL
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

RULES_ENV = "AGENT_BROKER_RULES"

# Used for a destination that has no `ports` list.
DEFAULT_PORTS = frozenset({443})

# The error mitmproxy is given for a connection stopped at the last gate.
REFUSED_OUTGOING = "refused by the sandbox broker"

# Every key a destination may have. An unknown key is an error rather than
# ignored, so a typing mistake cannot quietly change what a rule means. Later
# phases add their keys here.
DESTINATION_KEYS = {"host", "note", "ports"}

# Letters, digits and hyphens, in parts separated by dots. This keeps out
# things that look right but would never match, such as "https://github.com",
# "github.com:443" and "*.github.com".
HOST_NAME = re.compile(
    r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*"
)


class RulesError(Exception):
    """rules.yaml cannot be used. The message says what to fix."""


def load_rules(path: str) -> dict[str, frozenset[int]]:
    """Read rules.yaml and return the allowed ports for each host name.

    Host names are stored in lower case. Any mistake raises RulesError.
    """
    try:
        with open(path, encoding="utf-8") as file:
            data = YAML(typ="safe").load(file)
    except OSError as error:
        raise RulesError(f"cannot read it: {error.strerror}") from error
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

    rules: dict[str, frozenset[int]] = {}
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
        if _is_ip_address(host):
            raise RulesError(f"{where}: `host` must be a name, not an IP address")
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

        rules[host] = frozenset(ports)
    return rules


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


def log(event: str, *fields: object) -> None:
    """Write one log line: the time, the event, then its fields."""
    stamp = datetime.now().astimezone().isoformat(timespec="seconds")
    print(stamp, event, *map(_clean, fields), flush=True)


class Broker:
    def __init__(self, rules: dict[str, frozenset[int]]) -> None:
        self.rules = rules

    def refusal(self, host: str, port: int) -> str | None:
        """Why this destination is refused, or None when it is allowed."""
        ports = self.rules.get(host.lower())
        if ports is None:
            return "host-not-listed"
        if port not in ports:
            return "port-not-listed"
        return None

    def decide(self, flow: http.HTTPFlow, how: str) -> None:
        """Allow the request, or answer it with a 403 that explains itself."""
        host, port = flow.request.host, flow.request.port
        reason = self.refusal(host, port)
        if reason is None:
            log("allowed", host, port, how)
            return
        log("refused", host, port, how, reason)

        if reason == "port-not-listed":
            allowed = ", ".join(map(str, sorted(self.rules[host.lower()])))
            what = (
                f"{host} is an allowed destination, but not on port {port}. "
                f"Allowed on this host: port {allowed}."
            )
        else:
            what = f"{host} is not an allowed destination."
        flow.response = http.Response.make(
            403,
            f"Refused by the sandbox broker: {what}\n"
            "\n"
            "This machine is a sandbox. It reaches the internet only through a\n"
            "broker on the host, and the broker passes on only the destinations\n"
            "listed in broker/rules.yaml of the nixt3 repo on\n"
            "the host. Trying again, or trying another tool, will not help.\n"
            "\n"
            "If the task needs this destination, tell the user. They can add\n"
            "it to that file and restart the broker.\n",
            {"Content-Type": "text/plain; charset=utf-8"},
        )
        # Many programs show only the first line of a refused CONNECT, so the
        # short version goes there as well.
        flow.response.reason = "Refused by the sandbox broker"

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """A program in the VM asks for a tunnel to host:port."""
        self.decide(flow, "connect")

    def request(self, flow: http.HTTPFlow) -> None:
        """A request the broker can read: plain HTTP, not inside TLS.

        mitmproxy sends it to flow.request.host and port, so those are what
        is checked, not the Host header.
        """
        self.decide(flow, "http")

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """TLS starts inside a tunnel. Pass it on untouched if it is honest.

        The first TLS message names the site the program wants. It has to be
        the host the tunnel was opened for. Without this check, a tunnel to
        an allowed host would also reach every other site that shares that
        host's servers, which for a large hosting company is a lot of sites.
        """
        address = data.context.server.address
        name = data.client_hello.sni
        if address is None:
            # TLS to the broker itself, not inside a tunnel. Nothing in the
            # VM is set up to do that.
            log("refused", "-", 0, "tls", "not-in-a-tunnel")
            return
        host, port = address[0], address[1]
        if self.refusal(host, port) is not None:
            # The tunnel was refused already; this is only a safeguard.
            log("refused", host, port, "tls", "host-not-listed")
        elif name is None or name.lower() != host.lower():
            log("refused", host, port, "tls", "tls-name-differs", name or "-")
        else:
            data.ignore_connection = True

    def tls_start_client(self, data: tls.TlsData) -> None:
        """End a TLS connection that was not passed on untouched.

        mitmproxy would otherwise answer it with a certificate of its own and
        read the traffic. No rule asks for that in this phase, so the only
        connections that get here are the ones refused above. Handing
        mitmproxy a TLS setup without a certificate makes the handshake fail,
        which closes the connection.
        """
        data.ssl_conn = SSL.Connection(SSL.Context(SSL.TLS_SERVER_METHOD))
        data.ssl_conn.set_accept_state()


    def server_connect(self, data: server_hooks.ServerConnectionHookData) -> None:
        """The last gate: mitmproxy is about to open a connection to a server.

        Every connection the broker makes passes here, whatever kind of
        request led to it. The checks above should have stopped anything
        unlisted already. This one makes sure that a case they missed is
        refused instead of let through.
        """
        address = data.server.address
        host, port = (address[0], address[1]) if address else ("-", 0)
        if address is None or self.refusal(host, port) is not None:
            log("refused", host, port, "outgoing", "host-not-listed")
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
    log("started", f"destinations={len(rules)}", f"rules={path}")
    return Broker(rules)


addons = [start()]
