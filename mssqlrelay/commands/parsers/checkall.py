NAME = "checkall"

import argparse
from typing import Callable, Tuple

from . import target


def entry(options: argparse.Namespace):
    from mssqlrelay.commands import checkall

    checkall.entry(options)

def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser("checkall", help="Lists MSSQL servers (from LDAP), check if user has access and encryption settings")

    group = subparser.add_argument_group("connection options")
    group.add_argument(
        "-scheme",
        action="store",
        metavar="ldap scheme",
        choices=["ldap", "ldaps"],
        default="ldaps",
    )

    target.add_argument_group(subparser, connection_options=group)

    return NAME, entry