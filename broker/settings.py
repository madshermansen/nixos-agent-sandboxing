"""Which settings of mitmproxy the broker agrees to run with.

The broker is a script inside mitmproxy, and mitmproxy has about a hundred
settings of its own. Several of them change a request after the broker's
code has judged it: `map_remote` sends it to another address, `modify_headers`
and `modify_body` rewrite it, `stickyauth` adds a login from an earlier
request, an upstream mode sends everything through another proxy. Others
write traffic to a file, token included (`save_stream_file`, `hardump`). With
one of those set, what the broker decided about a request is no longer what
happens to it.

mitmproxy also reads settings from a file, `config.yaml` or `config.yml` in
its configuration folder, without anyone asking it to. The broker's folder is
in the state folder on the Mac. Only a program that runs as the user can
write there, and such a program is outside what this project defends
against. Still, the broker should not run with settings that nobody chose.

So the broker checks both when it starts, and refuses to start otherwise:

- its configuration folder holds no settings file;
- every setting has the value mitmproxy gives it by itself, except the ones
  the start command sets (REQUIRED, which must have exactly the value given
  here) and a few that are free (FREE).

The rule is "not on the list, so it must be untouched", and not a list of
dangerous settings. A setting that a later mitmproxy adds is then covered
without anyone having to notice it.

This file knows nothing of mitmproxy, so that it can be tested by itself
(tests/unit/test_settings.py). proxy.py hands it the values.

When the start command in darwin/commands.nix gets a new `--set`, add the
setting here, or the broker will not start.
"""

import os

# The files mitmproxy reads settings from, in its configuration folder.
CONFIG_FILES = ("config.yaml", "config.yml")

# Settings the start command sets, and the one value each may have.
REQUIRED = {
    # Only programs on this Mac can connect. On every address, the broker
    # would add the token for anyone on the network.
    "listen_host": "127.0.0.1",
    # Contact a server only after the broker has decided to.
    "connection_strategy": "lazy",
    # mitmproxy prints nothing about the traffic. Above 0 it prints
    # addresses with their query strings, and headers.
    "flow_detail": 0,
    # No built-in page that hands out the certificate.
    "onboarding": False,
    # Traffic that is neither TLS nor HTTP is dropped, not passed on.
    "rawtcp": False,
    # HTTP/1.1 where the broker opens traffic; see proxy.py.
    "http2": False,
}

# Settings that may have any value. None of them changes what happens to a
# request after the broker has judged it.
FREE = frozenset(
    {
        # Where the broker listens and keeps its files.
        "listen_port",
        "confdir",
        # How much mitmproxy says about itself in the log.
        "termlog_verbosity",
        # A second safeguard against holding bodies in memory.
        "stream_large_bodies",
        # The scripts mitmproxy loads: the broker itself, and in
        # tests/github-broker.sh two more. They are named on the command
        # line, where the user chose them; a settings file cannot name any,
        # because the broker does not start when there is one.
        "scripts",
        # Which certificate authorities the broker believes when it checks
        # a server. The test uses this for its stand-in.
        "ssl_verify_upstream_trusted_ca",
        "ssl_verify_upstream_trusted_confdir",
    }
)


def config_files(folder: str) -> list[str]:
    """The settings files in mitmproxy's configuration folder, if any."""
    folder = os.path.expanduser(folder)
    return [
        os.path.join(folder, name)
        for name in CONFIG_FILES
        if os.path.lexists(os.path.join(folder, name))
    ]


def unreviewed(values: dict[str, object], defaults: dict[str, object]) -> list[str]:
    """The settings that are not what the broker agrees to run with.

    `values` holds every setting of mitmproxy with its value now, and
    `defaults` the value mitmproxy gives each by itself. Returns one line
    per setting that is wrong, without its value: a value can be long, and
    for some settings it is a password. An empty list means all is well.
    """
    wrong = []
    for name in sorted(values):
        value = values[name]
        if name in REQUIRED:
            if value != REQUIRED[name] or type(value) is not type(REQUIRED[name]):
                wrong.append(f"`{name}` must be {REQUIRED[name]!r}")
        elif name in FREE:
            continue
        elif name not in defaults or value != defaults[name]:
            wrong.append(f"`{name}` is set, and the broker does not allow that")
    for name in sorted(set(REQUIRED) - set(values)):
        wrong.append(f"`{name}` is not a setting of this mitmproxy")
    return wrong
