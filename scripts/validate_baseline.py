#!/usr/bin/env python3
"""
Sprint 3 Phase C — baseline validation gate.

Run after every migration wave to prove that the total tool count and
the set of tool groups haven't drifted. Reads `.migration-baseline.json`
(written by `extract_tool_metadata.py`) and compares it to what
`src/mcp/registry.rs` currently reports.

Exits with code 0 on success, non-zero on any drift, so the wave script
can fail fast and trigger a `git reset --hard HEAD`.

Two gates are checked:

  1. Runtime count   — rebuilds scripts/tool_metadata.json on the fly
                       and asserts `total` matches baseline.
  2. Groups set      — asserts every group from the baseline still
                       appears in the metadata (may gain new groups —
                       that's a soft warning, not an error).

Run from the repo root:

    python3 scripts/validate_baseline.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASELINE = REPO / ".migration-baseline.json"
METADATA = REPO / "scripts" / "tool_metadata.json"


def main() -> int:
    if not BASELINE.exists():
        print(f"FATAL: {BASELINE.relative_to(REPO)} missing.")
        print("       Run `python3 scripts/extract_tool_metadata.py` first.")
        return 1

    baseline = json.loads(BASELINE.read_text())

    # Re-run the extractor to capture the current state.
    print("Re-extracting current tool metadata…")
    import subprocess

    r = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "extract_tool_metadata.py")],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        print("FATAL: extract_tool_metadata.py failed:")
        print(r.stdout)
        print(r.stderr)
        return r.returncode

    current = json.loads(METADATA.read_text())
    cur_total = current["total"]
    base_total = baseline["total"]

    print(f"  baseline total: {base_total}")
    print(f"  current  total: {cur_total}")

    if cur_total != base_total:
        print(f"\nFATAL: tool count drifted! {base_total} -> {cur_total}")
        return 1

    cur_groups = set(current["groups"])
    base_groups = set(baseline["groups"])

    missing = base_groups - cur_groups
    if missing:
        print(f"\nFATAL: baseline groups disappeared: {sorted(missing)}")
        return 1

    added = cur_groups - base_groups
    if added:
        print(f"\nWARN: new groups appeared (not in baseline): {sorted(added)}")
        print("      If you added new tools, update the baseline intentionally.")

    print("\nOK: baseline invariants hold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
