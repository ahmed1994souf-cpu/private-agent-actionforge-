#!/usr/bin/env python3
"""Read-only triage scanner for EPK8/EPAC/PAC-like binary files.

Reports signatures, candidate 32-byte PACH headers, and distances between
recognized markers. Marker positions are clues only, not validated chunk boundaries.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path

SIGNATURES = (
    b"EPK8", b"EPAC", b"PACH", b"BIKi", b"YMKs", b"BPE ",
    b"DDS ", b"SKEL", b"BONE", b"ANIM", b"MESH", b"MOVT", b"MOVF", b"MOV "
)

def all_offsets(data: bytes, sig: bytes) -> list[int]:
    out, start = [], 0
    while True:
        pos = data.find(sig, start)
        if pos < 0:
            return out
        out.append(pos)
        start = pos + 1

def scan(path: Path) -> dict:
    data = path.read_bytes()
    found = {}
    events = []
    for sig in SIGNATURES:
        offsets = all_offsets(data, sig)
        if offsets:
            label = sig.decode("ascii", errors="replace")
            found[label] = offsets
            events.extend({"offset": off, "signature": label} for off in offsets)
    events.sort(key=lambda x: (x["offset"], x["signature"]))

    sequence = []
    for i, event in enumerate(events):
        item = dict(event)
        if i:
            item["distance_from_previous_marker"] = event["offset"] - events[i - 1]["offset"]
        sequence.append(item)

    pachs = []
    for off in found.get("PACH", [])[:1000]:
        raw = data[off:off + 32]
        item = {
            "offset": off,
            "header_hex": raw.hex(" "),
            "header_bytes_available": len(raw),
        }
        if len(raw) == 32:
            item["u32_le_at_header_offsets_16_20_24_28"] = list(
                struct.unpack_from("<4I", raw, 16)
            )
        pachs.append(item)

    return {
        "file": path.name,
        "size_bytes": len(data),
        "header_hex_64_bytes": data[:64].hex(" "),
        "signatures": found,
        "marker_sequence": sequence[:5000],
        "pach_header_candidates": pachs,
        "limitations": [
            "Signature matches are clues only and do not prove chunk semantics.",
            "Marker distances are not asserted to be chunk sizes or boundaries.",
            "PACH integer fields are reported raw; their meanings are unverified.",
            "No mesh, skeleton, texture, or animation decoding is performed.",
            "Input file is read only; only the optional report file is written."
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
    rendered = json.dumps(report, indent=2)
    print(rendered)
    if args.json:
        args.json.write_text(rendered + "\n", encoding="utf-8")
        print(f"\nJSON report written to: {args.json}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
