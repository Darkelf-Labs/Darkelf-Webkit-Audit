"""
cli.py

Command-line interface for Darkelf SecureAudit.
"""

import argparse
import json
import sys

from .sarif import write_sarif
from .scanner import scan_project
from .utils import count_high_findings

BANNER = "Darkelf SecureAudit BUILD 2026-07-31"


def build_parser():
    """
    Create the CLI argument parser.
    """
    parser = argparse.ArgumentParser(
        prog="darkelf-secureaudit",
        description=(
            "Advanced security auditing for WebKit, PyObjC, and Python applications."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version="Darkelf SecureAudit 5.0.0",
    )

    parser.add_argument(
        "target",
        help="Python file or project directory to scan.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON report.",
    )

    parser.add_argument(
        "--sarif",
        metavar="FILE",
        help="Write SARIF 2.1.0 report.",
    )

    return parser


def print_console_report(results):
    """
    Print a human-readable console report.
    """

    print("=" * 70)
    print(BANNER)
    print("=" * 70)

    print(f"Files scanned : {results['files']}")
    print(f"Project Score : {results['score']}/100")
    print(f"HIGH Findings : {count_high_findings(results['findings'])}")

    print()

    for severity in ("HIGH", "MEDIUM", "INFO", "GOOD"):
        entries = results["findings"][severity]

        if not entries:
            continue

        print(f"[{severity}]")

        for line, message, confidence in entries:
            print(f"  Line {line:>5} | Confidence: {confidence:<6} | {message}")


def main():
    """
    CLI entry point.
    """

    parser = build_parser()
    args = parser.parse_args()

    #
    # Run scan
    #

    results = scan_project(args.target)

    #
    # SARIF
    #

    if args.sarif:
        write_sarif(
            results["findings"],
            args.sarif,
        )

    #
    # JSON mode
    #

    if args.json:
        print(
            json.dumps(
                results,
                indent=2,
            )
        )

        sys.exit(1 if count_high_findings(results["findings"]) else 0)

    #
    # Console mode
    #

    print_console_report(results)

    #
    # CI exit code
    #

    sys.exit(1 if count_high_findings(results["findings"]) else 0)


if __name__ == "__main__":
    main()
