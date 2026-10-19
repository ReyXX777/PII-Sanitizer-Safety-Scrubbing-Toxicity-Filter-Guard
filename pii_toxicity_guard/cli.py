"""Minimal command-line entry point."""
import argparse
import json
import sys

from .config import GuardSettings
from .guard import Guard


def main() -> int:
    parser = argparse.ArgumentParser(description="Redact PII and optionally filter toxicity.")
    parser.add_argument("text", nargs="?", help="Text to sanitize. If omitted, read stdin.")
    args = parser.parse_args()
    text = args.text if args.text is not None else sys.stdin.read()
    result = Guard(GuardSettings()).process(text)
    print(json.dumps(result.model_dump(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
