#!/usr/bin/env python3
"""Regenerate the JSON twins of every YAML catalogue.

PyYAML is optional at runtime, so the shipped YAML sources are mirrored into
compact JSON that `netmap` can load with no third-party packages. Run this after
editing any file in netmap/refs/.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

REFS = Path(__file__).resolve().parents[1] / "netmap" / "refs"


def sync(directory: Path = REFS) -> list[Path]:
    written: list[Path] = []
    for source in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
        target = source.with_suffix(".json")
        target.write_text(json.dumps(data, separators=(",", ":"), sort_keys=False) + "\n", encoding="utf-8")
        written.append(target)
    return written


def main() -> int:
    if not Path(sys.executable).name:  # pragma: no cover
        return 1
    written = sync()
    for path in written:
        print(f"  {path.relative_to(REFS.parents[1])}  {path.stat().st_size:,} bytes")
    print(f"synced {len(written)} catalogue(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
