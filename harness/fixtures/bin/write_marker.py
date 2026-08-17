#!/usr/bin/env python3
"""Write one marker below a path selected by the harness case."""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("content")
    args = parser.parse_args()

    marker = Path(args.path)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(args.content, encoding="utf-8")
    print(f"marker={marker}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
