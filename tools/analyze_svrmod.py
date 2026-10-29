#!/usr/bin/env python3
"""Inspect a .svrmod ZIP archive without extracting its contents to disk.

Lists members and optionally runs the PAC signature scanner on an embedded ch.pac.
Only a JSON/text report is written; archive contents are not modified.
"""
from __future__ import annotations
import argparse
import json
import tempfile
import zipfile
from pathlib import Path
from analyze_pac import scan

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="path to a .svrmod archive")
    parser.add_argument("--json", type=Path, help="write report JSON")
    parser.add_argument("--member", default="ch.pac", help="PAC member name to scan (default: ch.pac)")
    args = parser.parse_args()
    if not args.archive.is_file():
        parser.error(f"not a file: {args.archive}")
    if not zipfile.is_zipfile(args.archive):
        parser.error("archive is not recognized as a ZIP file; no data was extracted")
    with zipfile.ZipFile(args.archive) as zf:
        infos = zf.infolist()
        names = [i.filename for i in infos]
        result = {
            "archive": args.archive.name,
            "archive_size_bytes": args.archive.stat().st_size,
            "members": [
                {"name": i.filename, "size_bytes": i.file_size, "compressed_bytes": i.compress_size}
                for i in infos
            ],
            "selected_member": args.member,
            "pac_analysis": None,
            "limitations": [
                "Archive listing is metadata only; it does not identify asset semantics.",
                "Signature scanning is not mesh, skeleton, texture, or animation decoding.",
                "Archive and embedded files are read only."
            ]
        }
        matches = [n for n in names if Path(n).name.lower() == Path(args.member).name.lower()]
        if matches:
            selected = matches[0]
            with tempfile.TemporaryDirectory(prefix="svrmod-analysis-") as td:
                temp_path = Path(td) / Path(selected).name
                temp_path.write_bytes(zf.read(selected))
                result["selected_member"] = selected
                result["pac_analysis"] = scan(temp_path)
        else:
            result["member_not_found"] = True
    rendered = json.dumps(result, indent=2)
    print(rendered)
    if args.json:
        args.json.write_text(rendered + "\n", encoding="utf-8")
        print(f"\nJSON report written to: {args.json}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
