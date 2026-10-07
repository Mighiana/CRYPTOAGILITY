"""Command entry point; subcommands are integrated as modules land."""

import argparse

from cryptoagility.openssl import run


def main() -> int:
    parser = argparse.ArgumentParser(prog="cryptoagility")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args()
    if args.version:
        print(run(["version"]).decode().strip())
    else:
        parser.print_help()
    return 0
