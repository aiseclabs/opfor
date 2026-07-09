"""The command line entry point.

Minimal for now, it lists the registered scenarios. Running a campaign lands here
once the campaign loader and a real scenario ship, so the surface stays honest
about what it can do rather than pretending a run path that is not built yet.
"""

from __future__ import annotations

import argparse

from opfor.scenarios.registry import known_scenarios


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="opfor", description="Universal offensive-security engine")
    parser.add_argument("command", choices=("scenarios",), help="what to do")
    args = parser.parse_args(argv)
    if args.command == "scenarios":
        for name in known_scenarios():
            print(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
