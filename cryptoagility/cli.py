"""Command entry point; subcommands are integrated as modules land."""

import argparse

from cryptoagility import __version__
from cryptoagility.openssl import run


def main() -> int:
    parser = argparse.ArgumentParser(prog="cryptoagility")
    parser.add_argument("--version", action="version", version=f"cryptoagility {__version__}")
    parser.add_argument("--openssl-version", action="store_true")
    args = parser.parse_args()
    if args.openssl_version:
        print(run(["version"]).decode().strip())
    else:
        parser.print_help()
    return 0
