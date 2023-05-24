NAME = "check"

import argparse
from typing import Callable, Tuple

from . import target


def entry(options: argparse.Namespace):
    from mssqlrelay.commands import check

    check.entry(options)

def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser("check", help="Check if server enforces encryption")

    target.add_argument_group(subparser, connection_options=None)

    return NAME, entry