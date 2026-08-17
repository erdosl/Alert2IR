"""Bounded Alert2IR operator commands."""

import argparse
import json


def main() -> int:
    parser = argparse.ArgumentParser(prog="alert2ir")
    subcommands = parser.add_subparsers(dest="command", required=True)
    reconcile = subcommands.add_parser("reconcile")
    reconcile.add_argument("--once", action="store_true", required=True)
    arguments = parser.parse_args()

    if arguments.command == "reconcile":
        from alert2ir.main import processor

        report = processor.reconcile_once()
        print(
            json.dumps(
                {
                    "examined": report.examined,
                    "advanced": report.advanced,
                    "failed": report.failed,
                    "time_limit_reached": report.time_limit_reached,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1 if report.failed else 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
