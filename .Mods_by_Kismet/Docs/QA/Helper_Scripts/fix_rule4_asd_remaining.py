#!/usr/bin/env python3
r"""Fix remaining Rule 4 violations in ASD module -- Phase 2D (pass 2)

Handles the 17 remaining sh -c / bash -c violations that use variable-based commands.
Converts command-string + sh -c $var pattern to direct curl/command calls.
"""

import re
import sys
from pathlib import Path

MODULE_FILE = (Path(__file__).resolve().parents[3] /
               "Evaluate-STIG" / "Modules" /
               "Scan-XO_ASD_Checks" /
               "Scan-XO_ASD_Checks.psm1")


def fix_variable_shc(text):
    """Replace variable-based sh -c calls with direct curl invocations."""
    count = 0
    lines = text.split('\n')
    new_lines = []
    skip_next = False

    for i, line in enumerate(lines):
        if skip_next:
            skip_next = False
            continue

        # Check for $varArgs = "command string" followed by $(... sh -c $varArgs ...)
        if i + 1 < len(lines):
            next_line = lines[i + 1]

            # Pattern: $pluginsArgs = "curl ..." + $(timeout 10 sh -c $pluginsArgs 2>&1)
            if re.match(r'\s*\$pluginsArgs\s*=', line) and 'sh -c $pluginsArgs' in next_line:
                indent = len(next_line) - len(next_line.lstrip())
                new_lines.append(' ' * indent + '$pluginsJson = $(timeout 10 curl -sk -H "cookie: authenticationToken=${apiToken}" "https://localhost/rest/v0/plugins" 2>/dev/null | head -c 8000)')
                skip_next = True
                count += 1
                continue

            # Pattern: $curlArgs = "curl ..." + $(timeout 15 sh -c $curlArgs 2>&1)
            if re.match(r'\s*\$curlArgs\s*=', line) and 'sh -c $curlArgs' in next_line:
                indent = len(next_line) - len(next_line.lstrip())
                new_lines.append(' ' * indent + '$auditJson = $(timeout 15 curl -sk -H "cookie: authenticationToken=${apiToken}" "https://localhost/rest/v0/plugins/audit/records?limit=200" 2>/dev/null | head -c 10000)')
                skip_next = True
                count += 1
                continue

            # Pattern: $auditArgs = "curl ..." + $(timeout 10 sh -c $auditArgs 2>&1)
            if re.match(r'\s*\$auditArgs\s*=', line) and 'sh -c $auditArgs' in next_line:
                indent = len(next_line) - len(next_line.lstrip())
                new_lines.append(' ' * indent + '$auditJson = $(timeout 10 curl -sk -H "cookie: authenticationToken=${apiToken}" "https://localhost/rest/v0/plugins/audit/records?limit=50" 2>/dev/null | head -c 16000)')
                skip_next = True
                count += 1
                continue

            # Pattern: $loginPageArgs = "curl ..." + $(timeout 15 sh -c $loginPageArgs 2>&1)
            if re.match(r'\s*\$loginPageArgs\s*=', line) and 'sh -c $loginPageArgs' in next_line:
                indent = len(next_line) - len(next_line.lstrip())
                new_lines.append(' ' * indent + '$loginPage = $(timeout 15 curl -sk --max-time 10 "https://localhost/" 2>/dev/null | head -c 20000)')
                skip_next = True
                count += 1
                continue

            # Pattern: $cmd = "..." + bash -c $cmd 2>$null (remaining)
            cmd_assign = re.match(r'(\s*)\$cmd\s*=\s*"(.*)"', line)
            bash_call = re.match(r'(\s*)(\$\w+)\s*=\s*bash -c \$cmd\s*2>\$null', next_line)
            if cmd_assign and bash_call:
                indent = bash_call.group(1)
                var_name = bash_call.group(2)
                cmd_body = cmd_assign.group(2)
                cmd_body = re.sub(r'\s*</dev/null', '', cmd_body)
                if '2>&1' not in cmd_body and '2>/dev/null' not in cmd_body:
                    cmd_body = cmd_body.rstrip() + " 2>&1"
                new_lines.append(f"{indent}{var_name} = $({cmd_body})")
                skip_next = True
                count += 1
                continue

        new_lines.append(line)

    return '\n'.join(new_lines), count


def verify(text):
    """Count remaining violations."""
    remaining = []
    for j, line in enumerate(text.split('\n')):
        stripped = line.lstrip()
        if stripped.startswith('#'):
            continue
        if 'sh -c' in line or re.search(r'bash -c', line):
            remaining.append((j+1, line.strip()[:120]))
    return remaining


def main():
    if not MODULE_FILE.exists():
        print(f"ERROR: Module file not found: {MODULE_FILE}")
        sys.exit(1)

    print(f"Reading: {MODULE_FILE}")
    original = MODULE_FILE.read_text(encoding='utf-8')

    text, count = fix_variable_shc(original)
    print(f"Fixed {count} variable-based sh -c / bash -c calls")

    remaining = verify(text)
    print(f"Remaining violations: {len(remaining)}")
    for lineno, line in remaining[:20]:
        print(f"  Line {lineno}: {line}")

    if text != original:
        MODULE_FILE.write_text(text, encoding='utf-8')
        print(f"\nWrote: {MODULE_FILE}")
    else:
        print("\nNo changes needed.")


if __name__ == "__main__":
    main()
