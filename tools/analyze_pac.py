#!/usr/bin/env python3
"""Read-only signature scanner for EPK8/PAC-like binary files.

This is a triage tool, not a decoder. Offsets are byte offsets from file start.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

SIGNATURES = (b"EPK8", b"EPAC", b"PACH", b"BIKi", b"YMKs", b"BPE ", b"DDS ", b"SKEL", b"BONE", b"ANIM", b"MESH", b"MOVT", b"MOVF", b"MOV ")

def scan(path: Path) -> dict:
    data = path.read_bytes()
    found = {}
    for sig in SIGNATURES:
        offsets = []
        start = 0
        while True:
            pos = data.find(sig, start)
            if pos < 0:
                break
            offsets.append(pos)
            start = pos + 1
        if offsets:
            found[sig.decode("ascii", errors="replace")] = offsets
    return {
        "file": path.name,
        "size_bytes": len(data),
        "header_hex_64_bytes": data[:64].hex(" "),
        "signatures": found,
        "limitations": [
            "Signature matches are clues only; they do not prove chunk semantics.",
            "No geometry, skeleton, texture, or animation decoding is performed.",
            "Input file is read only."
        ]
    }

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="path to a local PAC/EPK8-like file")
    parser.add_argument("--json", type=Path, help="also write report as JSON")
    args = parser.parse_args()
    if not args.file.is_file():
        parser.error(f"not a file: {args.file}")
    report = scan(args.file)
    print(json.dumps(report, indent=2))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\nJSON report written to: {args.json}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
