"""Command line entry point.

Scan files or stdin; exit code is 1 when any input scores high, so the
scanner can gate a pipeline step.
"""

from __future__ import annotations

import argparse
import sys

from .report import render_json, render_text
from .scanner import scan_text


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="pinscan",
        description="Heuristic prompt-injection scanner for text inputs.")
    parser.add_argument("paths", nargs="*",
                        help="files to scan; reads stdin when empty")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--quiet", action="store_true",
                        help="only print inputs that score medium or high")
    args = parser.parse_args(argv)

    inputs = []
    if args.paths:
        for path in args.paths:
            with open(path, encoding="utf-8", errors="replace") as fh:
                inputs.append((path, fh.read()))
    else:
        inputs.append(("stdin", sys.stdin.read()))

    worst = 0
    for label, text in inputs:
        result = scan_text(text)
        worst = max(worst, result.score)
        if args.quiet and result.tier == "low":
            continue
        out = render_json(result) if args.json else render_text(result, label)
        print(out)
    return 1 if worst >= 60 else 0


if __name__ == "__main__":
    sys.exit(main())
