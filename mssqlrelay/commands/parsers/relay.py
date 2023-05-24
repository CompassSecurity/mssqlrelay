NAME = "relay"

import argparse
from typing import Callable, Tuple

from . import target


def entry(options: argparse.Namespace):
    from mssqlrelay.commands import relay

    relay.entry(options)

def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser("relay", help="NTLM Relay to MS SQL Endpoints")

    subparser.add_argument(
        "relaytarget",
        action="store",
        help="target name or IP Address (where you want to execute stuff)",
    )

    subparser.add_argument(
        "attacker",
        action="store",
        help="attacker name or IP Address (that's you!)",
    )

    relay_group = subparser.add_argument_group("relay options")
    relay_group.add_argument(
        "-listen-interface",
        action="store",
        metavar="ip address",
        help="IP Address of interface to listen on",
        default="0.0.0.0",
    )
    relay_group.add_argument(
        "-listen-port",
        action="store",
        help="Port to listen on",
        default=445,
        type=int
    )

    target.add_argument_group(subparser, connection_options=None)

    return NAME, entry