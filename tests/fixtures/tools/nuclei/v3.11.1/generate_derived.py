#!/usr/bin/env python3
"""Generate derived nuclei fixture with domain hostnames instead of IP literals.

The lab fixture records findings against http://127.0.0.1:3000. Because DAYSRA
scope rules intentionally reject IP literals, tests verifying engine scope filtering
use this derived fixture where '127.0.0.1' is replaced by 'app.example.com'.
"""

import json
from pathlib import Path


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    src_file = base_dir / "output.jsonl"
    dst_dir = base_dir / "derived"
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst_file = dst_dir / "output.jsonl"

    if not src_file.exists():
        raise FileNotFoundError(f"Source fixture not found: {src_file}")

    lines_out = []
    with open(src_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if "host" in entry and entry["host"] == "127.0.0.1":
                entry["host"] = "app.example.com"
            if "url" in entry:
                entry["url"] = entry["url"].replace("127.0.0.1", "app.example.com")
            if "matched-at" in entry:
                entry["matched-at"] = entry["matched-at"].replace("127.0.0.1", "app.example.com")
            lines_out.append(json.dumps(entry) + "\n")

    with open(dst_file, "w", encoding="utf-8") as f:
        f.writelines(lines_out)

    print(f"Generated {len(lines_out)} lines in {dst_file}")


if __name__ == "__main__":
    main()
