#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import re
import sys
import shutil
from datetime import datetime


def get_package_dir():
    """Locate the darktrace package in site-packages."""
    # Look for the package in all site-packages directories
    for path in sys.path:
        if "site-packages" in path:
            dt_path = os.path.join(path, "darktrace")
            if os.path.isdir(dt_path):
                return dt_path

    # Fallback/Guess if not found in sys.path (e.g. running outside venv)
    return "/opt/Synapse/venv/lib/python3.9/site-packages/darktrace"


PACKAGE_DIR = get_package_dir()
BACKUP_SUFFIX = f".bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

# Specific literal replacements for complex types
LITERAL_REPLACEMENTS = [
    ("float | tuple[float, float] | None", "Union[float, tuple[float, float], None]"),
    (
        "_Unset | None | float | tuple[float, float]",
        "Union[_Unset, None, float, tuple[float, float]]",
    ),
    ("dict | list", "Union[dict, list]"),
    ("Exception | None", "Optional[Exception]"),
    ("dict[str, Any] | None", "Optional[dict[str, Any]]"),
    ("dict[str, str] | None", "Optional[dict[str, str]]"),
    ("list[dict[str, Any]] | None", "Optional[list[dict[str, Any]]]"),
    ("list[str] | None", "Optional[list[str]]"),
    ("list[int] | None", "Optional[list[int]]"),
    ("requests.Response | None", "Optional[requests.Response]"),
    (
        "tuple[dict[str, str], dict[str, Any] | None]",
        "tuple[dict[str, str], Optional[dict[str, Any]]]",
    ),
    ("str | None", "Optional[str]"),
    ("int | None", "Optional[int]"),
    ("float | None", "Optional[float]"),
    ("bool | None", "Optional[bool]"),
]


def fix_typing_and_future(content: str) -> str:
    """Fixes typing imports and ensures __future__ is at the top."""
    lines = content.splitlines()

    # 1. Separate future imports, typing imports, and rest
    future_lines = []
    other_lines = []

    needs_union = "Union[" in content
    needs_optional = "Optional[" in content

    typing_import_found = False

    for line in lines:
        if line.startswith("from __future__ import"):
            future_lines.append(line)
        elif line.startswith("from typing import"):
            typing_import_found = True
            # Update existing typing import
            imported = set(
                i.strip() for i in line.replace("from typing import", "").split(",")
            )
            if needs_union:
                imported.add("Union")
            if needs_optional:
                imported.add("Optional")
            other_lines.append(f"from typing import {', '.join(sorted(imported))}")
        else:
            other_lines.append(line)

    # 2. Add typing if missing but needed
    if not typing_import_found and (needs_union or needs_optional):
        to_import = sorted(
            (["Union"] if needs_union else [])
            + (["Optional"] if needs_optional else [])
        )
        other_lines.insert(0, f"from typing import {', '.join(to_import)}")

    # 3. Assemble: Future first, then the rest
    return "\n".join(future_lines + other_lines) + "\n"


def patch_file(filepath: str) -> bool:
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    original_content = content

    # 1. Apply literal replacements
    for old, new in LITERAL_REPLACEMENTS:
        content = content.replace(old, new)

    # 2. General regex for 'A | B' -> 'Union[A, B]'
    def safe_union_replacer(match):
        expr = match.group(0)
        # Avoid non-type-hint pipes
        if any(c in expr for c in ["(", ")", '"', "'"]):
            return expr
        parts = [p.strip() for p in expr.split("|")]
        if any(re.match(r"^\d+$", p) for p in parts):
            return expr
        return f"Union[{', '.join(parts)}]"

    def patch_line(line):
        if line.strip().startswith("#"):
            return line
        # Identify lines that are likely type hints
        if re.search(r":\s*[\w\[\]|. ]+|->|^\s*\w+\s*=\s*[\w\[\]|. ]+", line):
            return re.sub(
                r"(?:[\w\.\[\]]+\s*\|\s*)+[\w\.\[\]]+", safe_union_replacer, line
            )
        return line

    content = "\n".join(patch_line(line) for line in content.splitlines())

    # 3. Fix order and imports
    content = fix_typing_and_future(content)

    if content == original_content:
        return False

    # 4. Backup and write
    shutil.copy2(filepath, filepath + BACKUP_SUFFIX)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

    return True


if __name__ == "__main__":
    print(f"Targeting Darktrace SDK at: {PACKAGE_DIR}")
    if not os.path.isdir(PACKAGE_DIR):
        print(f"Error: Darktrace package not found at {PACKAGE_DIR}")
        sys.exit(1)

    patched_count = 0
    for root, _, files in os.walk(PACKAGE_DIR):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                try:
                    if patch_file(path):
                        patched_count += 1
                        print(f"  [+] Patched: {os.path.relpath(path, PACKAGE_DIR)}")
                except Exception as e:
                    print(f"  [!] Error patching {file}: {e}")

    print(f"\nPatching complete. {patched_count} files modified.")
    print(f"Backups created with suffix: {BACKUP_SUFFIX}")
