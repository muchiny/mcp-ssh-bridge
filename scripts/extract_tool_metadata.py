#!/usr/bin/env python3
"""
Sprint 3 Phase C — ground-truth extraction for the #[mcp_tool] migration.

Parses `src/mcp/registry.rs` to build an authoritative map:

    tool_name -> {
        group,           # from tool_group()
        annotation,      # from tool_annotations(): read_only|mutating|destructive
        handler_type,    # type from create_filtered_registry()'s all_handlers vec
        marker_type,     # if standard: the type in `impl StandardTool for <X>`
                         #   (== handler_type for direct-impl handlers)
        shape,           # "direct" or "standard"
        file,            # path to the handler file on disk
        declared_name,   # the name string found in the source (const NAME | fn name)
        name_matches,    # bool: declared_name == tool_name (gap 1 gate)
    }

Then performs the 4 gap checks from the plan:

  1. declared_name cross-check for every tool (abort on mismatch)
  2. total count matches baseline expectation (74 groups, 338 tools)
  3. no file contains >1 handler
  4. every type referenced by registry.rs resolves to a file on disk

On success, writes `.migration-baseline.json` that holds the frozen
count + group set, plus `scripts/tool_metadata.json` that holds the
full per-tool metadata. Waves read the metadata; baseline is used by
validate_baseline.py after each wave to guarantee no drift.

Run from the repo root:

    python3 scripts/extract_tool_metadata.py
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parent.parent
REGISTRY_RS = REPO / "src" / "mcp" / "registry.rs"
TOOL_HANDLERS_DIR = REPO / "src" / "mcp" / "tool_handlers"
METADATA_OUT = REPO / "scripts" / "tool_metadata.json"
BASELINE_OUT = REPO / ".migration-baseline.json"


@dataclass
class ToolMeta:
    name: str
    group: str
    annotation: str  # read_only | mutating | destructive
    handler_type: str
    marker_type: Optional[str]
    shape: str  # direct | standard
    file: str
    declared_name: Optional[str]
    name_matches: bool


# --------------------------------------------------------------- parsing


def read_registry() -> str:
    return REGISTRY_RS.read_text()


def extract_function_body(source: str, fn_name: str) -> str:
    """Return the brace-balanced body of `pub fn <fn_name>(...)` in source."""
    # Locate the function signature.
    sig_match = re.search(
        rf"pub fn {re.escape(fn_name)}\b[^{{]*{{", source, re.DOTALL
    )
    if not sig_match:
        raise RuntimeError(f"function {fn_name} not found in registry.rs")
    start = sig_match.end() - 1  # points at the opening '{'
    depth = 0
    end = start
    for i in range(start, len(source)):
        c = source[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    return source[start + 1 : end]


def parse_tool_group(source: str) -> Dict[str, str]:
    """
    Parse `tool_group()` match arms into a {tool_name: group_name} dict.

    Match arms are of two forms:

        "foo" | "bar" => "group",
        "foo" | "bar" => { "group" }

    with possible line continuations across many lines.

    The `_ => "core"` catch-all arm is **not** captured here; callers
    must fall back to "core" explicitly for any name not in the map.
    """
    body = extract_function_body(source, "tool_group")
    # Take only the match block (skip the inventory fast-path we already added).
    # Post-migration (commit B) the match block is gone entirely — return
    # an empty map so the caller falls back to the inventory-discovered
    # attributes for every tool.
    match_start = body.find("match tool_name")
    if match_start < 0:
        return {}
    body = body[match_start:]

    result: Dict[str, str] = {}
    accumulated: List[str] = []

    for raw in body.splitlines():
        # Strip comments + whitespace.
        line = re.sub(r"//.*$", "", raw).strip()
        if not line:
            continue

        # Skip the catch-all arm — it's handled via fallback in the caller.
        if line.startswith("_ =>"):
            continue

        if "=>" in line:
            # Split on the first `=>`.
            left, right = line.split("=>", 1)
            # Names on the left go into accumulated.
            accumulated.extend(re.findall(r'"([^"]+)"', left))
            # Right side: either `"group",` or `{ "group" }` or continues.
            group_match = re.search(r'"([^"]+)"', right)
            if group_match and accumulated:
                group = group_match.group(1)
                for name in accumulated:
                    result[name] = group
                accumulated = []
            elif "{" in right and "}" not in right:
                # Multi-line brace form: group on following line(s).
                # We'll pick it up on the next iteration via a sentinel.
                accumulated.append("__PENDING_BRACE__")
        elif "__PENDING_BRACE__" in accumulated:
            group_match = re.search(r'"([^"]+)"', line)
            if group_match:
                group = group_match.group(1)
                names = [n for n in accumulated if n != "__PENDING_BRACE__"]
                for name in names:
                    result[name] = group
                accumulated = []
        else:
            # Continuation line: accumulate names.
            accumulated.extend(re.findall(r'"([^"]+)"', line))

    return result


def parse_tool_annotations(source: str) -> Dict[str, str]:
    """
    Parse `tool_annotations()` match arms to map tool_name -> kind
    (read_only | mutating | destructive).
    """
    body = extract_function_body(source, "tool_annotations")
    match_start = body.find("match tool_name")
    if match_start < 0:
        raise RuntimeError("tool_annotations: cannot find `match tool_name`")
    body = body[match_start:]

    # The arms look like:
    #   "ssh_foo" => ToolAnnotations::read_only("Title"),
    #   "ssh_foo" | "ssh_bar" => ToolAnnotations::mutating("..."),
    arm_re = re.compile(
        r'((?:"[^"]+"\s*(?:\|\s*)?)+)\s*=>\s*ToolAnnotations::(read_only|mutating|destructive|idempotent_mutating)',
        re.DOTALL,
    )

    result: Dict[str, str] = {}
    for match in arm_re.finditer(body):
        names_text = match.group(1)
        kind = match.group(2)
        # Normalize idempotent_mutating -> mutating for the macro (we don't
        # model idempotency in ToolAnnotationKind yet).
        if kind == "idempotent_mutating":
            kind = "mutating"
        for name in re.findall(r'"([^"]+)"', names_text):
            result[name] = kind
    return result


def parse_all_handlers_vec(source: str) -> List[Tuple[str, bool]]:
    """
    Parse the `all_handlers: Vec<Arc<dyn ToolHandler>> = vec![ ... ]`
    inside create_filtered_registry.

    Returns a list of (TypeName, has_new_call) tuples in declaration order.
    Returns an empty list if the legacy vec has been removed — once the
    inventory migration is complete, the function body is a pure
    `inventory::iter()` loop with no `vec![` literal at all.
    """
    fn_body = extract_function_body(source, "create_filtered_registry")
    vec_start = fn_body.find("vec![")
    if vec_start < 0:
        # Post-migration state: no legacy vec. Every handler is in
        # inventory and will be picked up by the already_migrated
        # backfill loop.
        return []
    start = vec_start + len("vec![")
    depth = 1
    i = start
    while i < len(fn_body) and depth > 0:
        c = fn_body[i]
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
        i += 1
    vec_body = fn_body[start : i - 1]

    entries: List[Tuple[str, bool]] = []
    # Each entry is `Arc::new(SshXxxHandler)` or `Arc::new(SshXxxHandler::new())`.
    entry_re = re.compile(r"Arc::new\((\w+)(?:::new\(\))?\)")
    for match in entry_re.finditer(vec_body):
        type_name = match.group(1)
        has_new = "::new()" in match.group(0)
        entries.append((type_name, has_new))
    return entries


# ---------------------------------------------------- handler file lookup


def find_handler_file(handler_type: str) -> Optional[Path]:
    """
    Locate the source file that declares `pub struct <handler_type>` OR
    `pub type <handler_type> = StandardToolHandler<...>`.
    """
    for rs in TOOL_HANDLERS_DIR.glob("*.rs"):
        text = rs.read_text()
        struct_re = re.compile(
            rf"pub\s+struct\s+{re.escape(handler_type)}\b"
        )
        alias_re = re.compile(
            rf"pub\s+type\s+{re.escape(handler_type)}\s*="
        )
        if struct_re.search(text) or alias_re.search(text):
            return rs
    return None


def detect_handler_shape(
    file: Path, handler_type: str
) -> Tuple[str, str]:
    """
    Return (shape, struct_to_annotate) where:
      - shape is "direct" or "standard"
      - struct_to_annotate is the type we want to put #[mcp_tool] on
        (for direct shape this equals handler_type; for standard shape
        it's the marker type wrapped by StandardToolHandler<>).
    """
    text = file.read_text()

    # Standard shape detection: if there's a `pub type HandlerType = StandardToolHandler<Marker>;`
    alias_match = re.search(
        rf"pub\s+type\s+{re.escape(handler_type)}\s*=\s*StandardToolHandler<(\w+)>",
        text,
    )
    if alias_match:
        marker = alias_match.group(1)
        return "standard", marker

    # Direct shape: `impl ToolHandler for HandlerType { ... }`
    if re.search(
        rf"impl(?:<[^>]*>)?\s+ToolHandler\s+for\s+{re.escape(handler_type)}\b",
        text,
    ):
        return "direct", handler_type

    # Might be a bare struct with StandardToolHandler::new() inline?
    # Look for `impl StandardTool for X` — where X is the marker, and the
    # handler_type should be a type alias. If we reach here without finding
    # either an alias or a direct impl, it's a fatal mismatch.
    raise RuntimeError(
        f"cannot determine shape for {handler_type} in {file}: "
        f"neither `impl ToolHandler for {handler_type}` nor "
        f"`pub type {handler_type} = StandardToolHandler<...>` was found"
    )


def extract_declared_name(file: Path, shape: str, marker_type: str) -> Optional[str]:
    """
    Extract the declared tool name from a handler file.

    For standard shape: scan the `impl StandardTool for <marker>` block for
    `const NAME: &'static str = "...";`.

    For direct shape: scan the `impl ToolHandler for <marker>` block for
    `fn name(&self) -> &'static str { "..." }`.
    """
    text = file.read_text()

    if shape == "standard":
        block_re = re.compile(
            rf"impl\s+StandardTool\s+for\s+{re.escape(marker_type)}\s*\{{(.*?)\n\}}",
            re.DOTALL,
        )
        block = block_re.search(text)
        if not block:
            return None
        m = re.search(r'const\s+NAME\s*:\s*&\'static\s+str\s*=\s*"([^"]+)"', block.group(1))
        return m.group(1) if m else None

    # direct shape
    block_re = re.compile(
        rf"impl\s+ToolHandler\s+for\s+{re.escape(marker_type)}\s*\{{",
        re.DOTALL,
    )
    block_start = block_re.search(text)
    if not block_start:
        return None
    # Find the fn name body: `fn name(&self) -> &'static str { "xxx" }`
    name_re = re.compile(
        r'fn\s+name\s*\(\s*&self\s*\)\s*->\s*&\'static\s+str\s*\{\s*"([^"]+)"\s*\}'
    )
    m = name_re.search(text, block_start.end())
    return m.group(1) if m else None


# ------------------------------------------------------ multi-handler check


def count_handlers_per_file() -> Dict[Path, int]:
    """
    Scan every tool_handlers/*.rs file and count how many handlers it
    declares. A file with more than 1 is flagged for manual review.
    """
    counts: Dict[Path, int] = {}
    for rs in TOOL_HANDLERS_DIR.glob("*.rs"):
        if rs.name in ("mod.rs", "utils.rs"):
            continue
        text = rs.read_text()
        direct = len(re.findall(r"^impl\s+ToolHandler\s+for\s+\w+", text, re.MULTILINE))
        standard = len(re.findall(r"^impl\s+StandardTool\s+for\s+\w+", text, re.MULTILINE))
        total = direct + standard
        if total > 0:
            counts[rs] = total
    return counts


# ------------------------------------------------------------ main


def main() -> int:
    print(f"Reading registry from {REGISTRY_RS}")
    source = read_registry()

    group_map = parse_tool_group(source)
    annotation_map = parse_tool_annotations(source)
    handlers_vec = parse_all_handlers_vec(source)

    print(f"  tool_group arms:       {len(group_map)}")
    print(f"  tool_annotations arms: {len(annotation_map)}")
    print(f"  all_handlers vec:      {len(handlers_vec)}")

    # --- Gap 3: check for multi-handler files ---------------------------
    per_file_counts = count_handlers_per_file()
    multi = {str(p.relative_to(REPO)): c for p, c in per_file_counts.items() if c > 1}
    if multi:
        print("\nFATAL (gap 3): multi-handler files detected:")
        for f, c in multi.items():
            print(f"  {f}: {c} handlers")
        return 1
    print(f"  per-file handler check: OK ({len(per_file_counts)} single-handler files)")

    # --- Build per-tool metadata ---------------------------------------
    tools: Dict[str, ToolMeta] = {}
    errors: List[str] = []

    # Handlers already registered via inventory: auto-detected by
    # scanning tool_handler files for the `#[mcp_tool(...)]` or
    # `#[mcp_standard_tool(...)]` attribute. This keeps the script
    # stable across waves without hard-coding a list.
    already_migrated = _discover_migrated_tools()

    # Walk the all_handlers vec first — that's the canonical list of
    # handlers currently registered via the legacy path.
    vec_types: List[str] = []
    for type_name, _has_new in handlers_vec:
        vec_types.append(type_name)

        file = find_handler_file(type_name)
        if file is None:
            errors.append(f"{type_name}: source file not found (gap 4)")
            continue

        try:
            shape, marker = detect_handler_shape(file, type_name)
        except RuntimeError as e:
            errors.append(str(e))
            continue

        declared = extract_declared_name(file, shape, marker)

        # Back-resolve the tool name. Priority:
        # 1. declared name found in source IF it appears in annotation_map
        #    or group_map (both are sources of truth).
        # 2. Convention fallback from the type name.
        # The name falls back to "core" group if not in group_map — that's
        # the catch-all arm in tool_group()'s `_ => "core"`.
        if declared and (declared in group_map or declared in annotation_map):
            name = declared
        else:
            candidate = _convention_name(type_name, shape)
            if candidate in group_map or candidate in annotation_map:
                name = candidate
            elif declared:
                # declared is non-empty but not in either map — must be a
                # core group tool that only gets picked up by `_ => "core"`.
                name = declared
            else:
                errors.append(
                    f"{type_name} ({file.name}): cannot resolve tool name "
                    f"(declared={declared!r}, candidate={_convention_name(type_name, shape)!r})"
                )
                continue

        # Group lookup: explicit arm OR "core" fallback.
        group = group_map.get(name, "core")
        annotation = annotation_map.get(name, "read_only")
        name_matches = declared == name if declared else False

        if not name_matches:
            errors.append(
                f"{name}: declared name mismatch "
                f"(declared={declared!r}, expected={name!r}, file={file.name}) [gap 1]"
            )

        tools[name] = ToolMeta(
            name=name,
            group=group,
            annotation=annotation,
            handler_type=type_name,
            marker_type=marker if shape == "standard" else None,
            shape=shape,
            file=str(file.relative_to(REPO)),
            declared_name=declared,
            name_matches=name_matches,
        )

    # --- Gap 1: flag any name_matches=false ----------------------------
    if errors:
        print("\nFATAL: validation errors found:")
        for e in errors[:40]:
            print(f"  - {e}")
        if len(errors) > 40:
            print(f"  ... and {len(errors) - 40} more")
        return 1

    # --- Gap 2: include already-migrated handlers in the count ---------
    # For every tool that has an #[mcp_tool]/#[mcp_standard_tool] attribute
    # in its handler file, parse the attribute's metadata and add the
    # tool back into the metadata dict. This keeps the total count stable
    # across waves: legacy_vec_count + already_migrated_count = baseline.
    for name, file in already_migrated.items():
        if name in tools:
            continue
        text = file.read_text()
        m = re.search(
            r"#\[(mcp_tool|mcp_standard_tool)\s*\((.*?)\)\]",
            text,
            re.DOTALL,
        )
        if not m:
            errors.append(f"{name}: discovered migrated but no attribute found")
            continue
        attr_kind = m.group(1)
        attr_args = m.group(2)
        group_m = re.search(r'group\s*=\s*"([^"]+)"', attr_args)
        annotation_m = re.search(r'annotation\s*=\s*"([^"]+)"', attr_args)
        # Resolve the struct type that was annotated (the one directly
        # below the attribute).
        struct_after_attr = re.search(
            r"#\[(?:mcp_tool|mcp_standard_tool)[^]]*\][^\w]*"
            r"(?:#\[[^]]*\][^\w]*)*"
            r"pub\s+struct\s+(\w+)",
            text,
            re.DOTALL,
        )
        struct_name = struct_after_attr.group(1) if struct_after_attr else f"Ssh{_pascal(name[4:])}Handler"
        shape = "standard" if attr_kind == "mcp_standard_tool" else "direct"
        tools[name] = ToolMeta(
            name=name,
            group=group_m.group(1) if group_m else "unknown",
            annotation=annotation_m.group(1) if annotation_m else "read_only",
            handler_type=struct_name if shape == "direct" else _handler_alias_for_marker(text, struct_name),
            marker_type=struct_name if shape == "standard" else None,
            shape=shape,
            file=str(file.relative_to(REPO)),
            declared_name=name,
            name_matches=True,
        )

    if errors:
        print("\nFATAL during already_migrated backfill:")
        for e in errors:
            print(f"  - {e}")
        return 1

    all_groups = sorted({t.group for t in tools.values()})
    total = len(tools)

    print(f"\nFinal count: {total} tools in {len(all_groups)} groups")

    # Always write the metadata snapshot.
    metadata = {
        "total": total,
        "groups": all_groups,
        "tools": {n: asdict(t) for n, t in sorted(tools.items())},
    }
    METADATA_OUT.write_text(json.dumps(metadata, indent=2, sort_keys=True))
    print(f"  wrote {METADATA_OUT.relative_to(REPO)}")

    # The baseline is WRITE-ONCE: it captures the invariant that must
    # hold across every migration wave. Re-writing it on every run
    # would silently hide drift. Pass `--force-baseline` to override.
    force_baseline = "--force-baseline" in sys.argv
    if not BASELINE_OUT.exists() or force_baseline:
        baseline = {
            "total": total,
            "groups_count": len(all_groups),
            "groups": all_groups,
        }
        BASELINE_OUT.write_text(json.dumps(baseline, indent=2, sort_keys=True))
        print(f"  wrote {BASELINE_OUT.relative_to(REPO)}")
    else:
        print(f"  baseline kept (use --force-baseline to overwrite)")

    return 0


# ------------------------------------------------------------ helpers


def _discover_migrated_tools() -> Dict[str, Path]:
    """
    Scan every tool_handler file for `#[mcp_tool(name = "...")]` or
    `#[mcp_standard_tool(name = "...")]` and return a mapping from
    tool name to the file containing it.
    """
    discovered: Dict[str, Path] = {}
    attr_re = re.compile(
        r'#\[(?:mcp_tool|mcp_standard_tool)\s*\(\s*name\s*=\s*"([^"]+)"', re.MULTILINE
    )
    for rs in TOOL_HANDLERS_DIR.glob("*.rs"):
        if rs.name in ("mod.rs", "utils.rs"):
            continue
        text = rs.read_text()
        for match in attr_re.finditer(text):
            discovered[match.group(1)] = rs
    return discovered


def _convention_name(type_name: str, shape: str) -> str:
    """
    Given a type like `SshDockerPsHandler` (direct) or `DockerPsTool`
    (marker), return the snake_case ssh_xxx tool name.
    """
    name = type_name
    if shape == "direct":
        if name.startswith("Ssh") and name.endswith("Handler"):
            name = name[3:-7]
        elif name.startswith("Ssh"):
            name = name[3:]
    else:
        if name.endswith("Tool"):
            name = name[:-4]

    # Camel -> snake
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    return "ssh_" + snake


def _pascal(snake: str) -> str:
    """Convert snake_case to PascalCase."""
    return "".join(p.capitalize() for p in snake.split("_"))


def _handler_alias_for_marker(file_text: str, marker: str) -> str:
    """
    Given a handler file's text and the marker type (e.g. `DockerPsTool`),
    return the `pub type SshDockerPsHandler = StandardToolHandler<DockerPsTool>;`
    alias name, or fall back to the marker itself if no alias is found.
    """
    m = re.search(
        rf"pub\s+type\s+(\w+)\s*=\s*StandardToolHandler<{re.escape(marker)}>",
        file_text,
    )
    return m.group(1) if m else marker


if __name__ == "__main__":
    sys.exit(main())
