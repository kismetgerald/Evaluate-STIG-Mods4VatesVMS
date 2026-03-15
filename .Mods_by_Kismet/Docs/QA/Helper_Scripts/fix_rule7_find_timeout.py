#!/usr/bin/env python3
r"""Fix Rule 7 violations: Add timeout+maxdepth to find commands.

Phase 4 QA Remediation -- ensures all `find /path` commands have:
1. `timeout N` wrapper (default 10)
2. `-maxdepth N` flag (default 5)

Transformation examples:
  $(find /opt/xo -name '*.js' 2>&1)
    -> $(timeout 10 find /opt/xo -maxdepth 5 -name '*.js' 2>&1)

  $(find /opt/xo -maxdepth 3 -name '*.js' 2>&1)  [has maxdepth, no timeout]
    -> $(timeout 10 find /opt/xo -maxdepth 3 -name '*.js' 2>&1)

  $(timeout 5 find /opt/xo -name '*.js' 2>&1)  [has timeout, no maxdepth]
    -> $(timeout 5 find /opt/xo -maxdepth 5 -name '*.js' 2>&1)
"""

import re
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[3] / "Evaluate-STIG" / "Modules"

MODULES = [
    BASE / "Scan-XO_WebSRG_Checks" / "Scan-XO_WebSRG_Checks.psm1",
    BASE / "Scan-XO_ASD_Checks" / "Scan-XO_ASD_Checks.psm1",
    BASE / "Scan-XCP-ng_Dom0_RHEL7_Checks" / "Scan-XCP-ng_Dom0_RHEL7_Checks.psm1",
    BASE / "Scan-XO_GPOS_Debian12_Checks" / "Scan-XO_GPOS_Debian12_Checks.psm1",
]

DEFAULT_TIMEOUT = 10
DEFAULT_MAXDEPTH = 5


def fix_find_commands(text):
    """Fix all find commands to have timeout and maxdepth."""
    count = 0
    lines = text.split('\n')
    new_lines = []

    for i, line in enumerate(lines):
        if line.lstrip().startswith('#'):
            new_lines.append(line)
            continue

        if not re.search(r'\bfind\s+/', line):
            new_lines.append(line)
            continue

        original_line = line
        changed = False

        has_timeout = bool(re.search(r'timeout\s+\d+\s+find', line))
        has_maxdepth = bool(re.search(r'-maxdepth\s+\d+', line))

        if has_timeout and has_maxdepth:
            new_lines.append(line)
            continue

        # Add maxdepth if missing -- insert after the first path argument
        if not has_maxdepth:
            # Pattern: find /path/to/dir [more paths] -name/-type/etc
            # Insert -maxdepth 5 after the last path argument before the first option
            line = re.sub(
                r'(\bfind\s+(?:/\S+\s*)+)',
                lambda m: m.group(0).rstrip() + f' -maxdepth {DEFAULT_MAXDEPTH} ',
                line,
                count=1
            )
            changed = True

        # Add timeout if missing -- wrap the find command
        if not has_timeout:
            line = re.sub(
                r'\bfind\s+/',
                f'timeout {DEFAULT_TIMEOUT} find /',
                line,
                count=1
            )
            changed = True

        if changed:
            count += 1

        new_lines.append(line)

    return '\n'.join(new_lines), count


def verify(text):
    """Count remaining violations."""
    remaining = []
    for j, line in enumerate(text.split('\n')):
        if line.lstrip().startswith('#'):
            continue
        if not re.search(r'\bfind\s+/', line):
            continue
        has_timeout = bool(re.search(r'timeout\s+\d+\s+find', line))
        has_maxdepth = bool(re.search(r'-maxdepth\s+\d+', line))
        if not has_timeout or not has_maxdepth:
            remaining.append((j + 1, line.strip()[:140]))
    return remaining


def fix_module(filepath):
    """Fix all find violations in a module file."""
    print(f"\nProcessing: {filepath.name}")
    original = filepath.read_text(encoding='utf-8')

    text, count = fix_find_commands(original)
    print(f"  Fixed {count} find commands")

    remaining = verify(text)
    print(f"  Remaining violations: {len(remaining)}")
    for lineno, line in remaining[:10]:
        print(f"    Line {lineno}: {line}")

    if text != original:
        filepath.write_text(text, encoding='utf-8')
        print(f"  Wrote: {filepath}")
    else:
        print(f"  No changes needed.")

    return count, len(remaining)


def main():
    total_fixed = 0
    total_remaining = 0

    for mod_path in MODULES:
        if not mod_path.exists():
            print(f"ERROR: {mod_path} not found")
            sys.exit(1)
        fixed, remaining = fix_module(mod_path)
        total_fixed += fixed
        total_remaining += remaining

    print(f"\n{'='*60}")
    print(f"Total find commands fixed: {total_fixed}")
    print(f"Total remaining violations: {total_remaining}")


if __name__ == "__main__":
    main()
