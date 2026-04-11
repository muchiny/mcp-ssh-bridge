#!/usr/bin/env python3
"""
Sprint 3 Phase C — per-handler migration helper.

Reads scripts/tool_metadata.json and for each tool name passed on the
command line:

  1. Loads the handler source file.
  2. Inserts `use crate::mcp_tool;` or `use crate::mcp_standard_tool;`
     at the end of the existing `use crate::ports::…` group.
  3. Finds the target struct (`pub struct <marker>;`) and inserts the
     `#[mcp_tool(...)]` / `#[mcp_standard_tool(...)]` attribute ABOVE
     any existing attributes.
  4. Writes the file back.

Then patches src/mcp/registry.rs:

  5. Removes the use import for the handler type from
     create_filtered_registry's `use super::tool_handlers::{…}` block.
  6. Removes the `Arc::new(<HandlerType>)` or `Arc::new(<HandlerType>::new())`
     line from the `all_handlers: Vec<_>` literal.

Usage:

    python3 scripts/migrate_handler.py ssh_docker_logs ssh_docker_inspect …

Or pass `--group <group>` to migrate every tool in that group:

    python3 scripts/migrate_handler.py --group docker

The script prints a summary and exits non-zero on any failure.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import List

REPO = Path(__file__).resolve().parent.parent
METADATA = REPO / "scripts" / "tool_metadata.json"
REGISTRY = REPO / "src" / "mcp" / "registry.rs"


def load_metadata() -> dict:
    if not METADATA.exists():
        print("FATAL: scripts/tool_metadata.json missing. Run extract_tool_metadata.py first.")
        sys.exit(1)
    return json.loads(METADATA.read_text())


def is_already_migrated(file_text: str) -> bool:
    """Return True if the file already contains an #[mcp_tool] attr."""
    return bool(
        re.search(r"#\[mcp_(standard_)?tool\s*\(", file_text)
    )


def insert_use_import(text: str, shape: str) -> str:
    """
    Insert `use crate::mcp_tool;` or `use crate::mcp_standard_tool;`
    at TOP-LEVEL scope only — never inside a nested `mod tests { … }`
    which would put the import out of reach of the `#[mcp_tool]`
    attribute above the struct.

    Strategy: walk lines from the top of the file. Track brace depth
    to stay at scope 0. As soon as we see the first `use crate::`
    line at depth 0, insert the new use before it (keeping imports
    roughly grouped). If no such line exists, insert after the file
    header comments / module docs.

    Idempotent: no-op if the import line already exists at any
    position (even inside a nested mod — that still satisfies Rust).
    """
    macro_name = "mcp_standard_tool" if shape == "standard" else "mcp_tool"
    needed = f"use crate::{macro_name};"

    # Short-circuit: already present (at any scope level).
    for line in text.splitlines():
        if line.strip() == needed:
            return text

    lines = text.splitlines(keepends=True)
    depth = 0
    first_top_level_use = None

    for idx, line in enumerate(lines):
        stripped = line.strip()

        # Track brace depth on the line BEFORE we classify it, so
        # `mod tests {` bumps depth before we check its content.
        # We skip strings — this is a rough approximation but handler
        # files don't contain brace-heavy string literals at the
        # top level.
        line_depth_before = depth
        for ch in line:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1

        # Only consider lines that STARTED at depth 0.
        if line_depth_before != 0:
            continue

        if stripped.startswith("use crate::"):
            first_top_level_use = idx
            break

    if first_top_level_use is not None:
        lines.insert(first_top_level_use, f"{needed}\n")
        return "".join(lines)

    # No top-level `use crate::` at all — find the first non-comment,
    # non-attribute line at depth 0 and insert before it.
    depth = 0
    for idx, line in enumerate(lines):
        stripped = line.strip()
        line_depth_before = depth
        for ch in line:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        if line_depth_before != 0:
            continue
        if (
            stripped
            and not stripped.startswith("//")
            and not stripped.startswith("/*")
            and not stripped.startswith("*")
            and not stripped.startswith("#!")
        ):
            lines.insert(idx, f"{needed}\n\n")
            return "".join(lines)

    raise RuntimeError("cannot find an insertion point for the use import")


def insert_attribute(
    text: str, marker_type: str, name: str, group: str, annotation: str, shape: str
) -> str:
    """
    Insert the `#[mcp_tool(...)]` or `#[mcp_standard_tool(...)]` attribute
    above the `pub struct <marker_type>` declaration.

    If the struct already has attributes (e.g. #[derive(Default)]), the
    new attribute is prepended to the attribute stack so it appears
    FIRST (above the #[derive]).
    """
    attr_name = "mcp_standard_tool" if shape == "standard" else "mcp_tool"
    attribute = (
        f'#[{attr_name}(name = "{name}", group = "{group}", annotation = "{annotation}")]'
    )

    # Find the struct declaration.
    struct_re = re.compile(
        rf"^(?P<indent>\s*)pub\s+struct\s+{re.escape(marker_type)}\b",
        re.MULTILINE,
    )
    m = struct_re.search(text)
    if m is None:
        raise RuntimeError(
            f"cannot find `pub struct {marker_type}` in handler file"
        )

    # Walk backwards from the struct line to find the start of any
    # existing attribute stack. Attributes look like `#[...]` on their
    # own line(s). Stop at the first non-attribute, non-empty line.
    struct_line_start = m.start()
    pos = struct_line_start - 1
    while pos > 0:
        # Walk to start of previous line.
        prev_nl = text.rfind("\n", 0, pos)
        if prev_nl == -1:
            prev_line = text[:pos]
            prev_line_start = 0
        else:
            prev_line = text[prev_nl + 1 : pos + 1]
            prev_line_start = prev_nl + 1
        stripped = prev_line.strip()
        if stripped.startswith("#[") or stripped == "":
            pos = prev_line_start - 1
            if stripped:
                # This was an attribute line — keep it in the stack.
                struct_line_start = prev_line_start
            continue
        break

    indent = m.group("indent")
    new_block = f"{indent}{attribute}\n"
    return text[:struct_line_start] + new_block + text[struct_line_start:]


def migrate_file(name: str, meta: dict) -> None:
    file_path = REPO / meta["file"]
    text = file_path.read_text()

    if is_already_migrated(text):
        print(f"  {name}: already migrated, skipping")
        return

    marker = meta["marker_type"] if meta["shape"] == "standard" else meta["handler_type"]

    text = insert_use_import(text, meta["shape"])
    text = insert_attribute(
        text,
        marker_type=marker,
        name=meta["name"],
        group=meta["group"],
        annotation=meta["annotation"],
        shape=meta["shape"],
    )

    file_path.write_text(text)
    print(f"  {name}: migrated ({meta['shape']} → {marker})")


# ---------------------------------------------- registry.rs surgery


def strip_from_registry(handler_types: List[str]) -> None:
    """
    Remove `use super::tool_handlers::{…}` entries and
    `Arc::new(HandlerType…)` literal lines for each handler type.
    """
    text = REGISTRY.read_text()

    for type_name in handler_types:
        # Remove the use-import line (inside the big use block).
        # Pattern: `        SshFooHandler,`
        use_re = re.compile(rf"^\s+{re.escape(type_name)},\s*\n", re.MULTILINE)
        new_text, n = use_re.subn("", text, count=1)
        if n == 0:
            print(f"    WARN: `{type_name},` not found in use imports")
        text = new_text

        # Remove the vec entry: `Arc::new(SshFooHandler),` or `Arc::new(SshFooHandler::new()),`
        vec_re = re.compile(
            rf"^\s+Arc::new\({re.escape(type_name)}(?:::new\(\))?\),\s*\n",
            re.MULTILINE,
        )
        new_text, n = vec_re.subn("", text, count=1)
        if n == 0:
            print(f"    WARN: `Arc::new({type_name}...)` not found in vec")
        text = new_text

    REGISTRY.write_text(text)


# ---------------------------------------------- CLI


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("names", nargs="*", help="Tool names to migrate")
    parser.add_argument("--group", help="Migrate every tool in this group")
    args = parser.parse_args()

    metadata = load_metadata()
    tools = metadata["tools"]

    if args.group:
        names = sorted(n for n, t in tools.items() if t["group"] == args.group)
        if not names:
            print(f"FATAL: no tools found in group '{args.group}'")
            return 1
        print(f"Migrating group '{args.group}' ({len(names)} tools):")
    else:
        names = args.names
        if not names:
            parser.print_help()
            return 1
        print(f"Migrating {len(names)} tool(s):")

    handler_types: List[str] = []
    for name in names:
        if name not in tools:
            print(f"  {name}: not in metadata, skipping")
            continue
        meta = tools[name]
        if meta["name"] in {
            "ssh_exec",
            "ssh_status",
            "ssh_history",
            "ssh_health",
            "ssh_ls",
            "ssh_docker_ps",
        }:
            print(f"  {name}: already migrated in Phase C.2, skipping")
            continue
        migrate_file(name, meta)
        handler_types.append(meta["handler_type"])

    if handler_types:
        print(f"\nPatching registry.rs to drop {len(handler_types)} handlers from legacy vec:")
        strip_from_registry(handler_types)
        print("  done")

    return 0


if __name__ == "__main__":
    sys.exit(main())
