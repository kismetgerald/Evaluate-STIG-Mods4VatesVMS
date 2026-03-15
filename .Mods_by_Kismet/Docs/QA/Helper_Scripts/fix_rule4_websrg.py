#!/usr/bin/env python3
r"""Fix Rule 4 violations in WebSRG module -- Phase 2E QA Remediation

Removes all bash -c and sh -c wrappers (~583 violations).

Patterns:
1. $(bash -c "command" 2>&1) -> $(command 2>&1)
2. bash -c "command" -> $(command 2>&1)
3. $(bash -c $curlCmd 2>&1) -> inline curl call
4. $(sh -c "command" 2>&1) -> $(command 2>&1)
5. $(timeout N sh -c "command" 2>&1) -> $(timeout N command 2>&1)
"""

import re
import sys
from pathlib import Path

MODULE_FILE = (Path(__file__).resolve().parents[3] /
               "Evaluate-STIG" / "Modules" /
               "Scan-XO_WebSRG_Checks" /
               "Scan-XO_WebSRG_Checks.psm1")


def fix_variable_bash_c(text):
    """Fix bash -c $curlCmd and bash -c $variable patterns.

    Find $variable = "command string" followed by bash -c $variable and inline.
    """
    count = 0
    lines = text.split('\n')
    new_lines = []
    skip_next = False

    for i, line in enumerate(lines):
        if skip_next:
            skip_next = False
            continue

        if i + 1 < len(lines):
            next_line = lines[i + 1]

            # Pattern: $var = "cmd" followed by $result = $(bash -c $var 2>&1)
            var_assign = re.match(r'(\s*)\$(\w+)\s*=\s*"(.*)"', line)
            if var_assign:
                var_name = var_assign.group(2)
                # Check if next line uses bash -c $var or $(bash -c $var)
                bash_call = re.match(
                    rf'(\s*)(\$\w+)\s*=\s*\$\(bash -c \${var_name}\s*(2>&1|2>/dev/null)?\)',
                    next_line
                )
                if bash_call:
                    indent = bash_call.group(1)
                    result_var = bash_call.group(2)
                    cmd_body = var_assign.group(3)
                    cmd_body = re.sub(r'\s*</dev/null', '', cmd_body)
                    cmd_body = cmd_body.replace("\\$", "$")
                    if '2>&1' not in cmd_body and '2>/dev/null' not in cmd_body:
                        cmd_body = cmd_body.rstrip() + " 2>&1"
                    new_lines.append(f"{indent}{result_var} = $({cmd_body})")
                    skip_next = True
                    count += 1
                    continue

        new_lines.append(line)

    return '\n'.join(new_lines), count


def unwrap_dollar_bash_c(text):
    """Remove $(bash -c "...") wrappers."""
    count = 0
    lines = text.split('\n')
    new_lines = []

    for i, line in enumerate(lines):
        if 'bash -c' not in line or line.lstrip().startswith('#'):
            new_lines.append(line)
            continue

        original_line = line
        changed = False

        # Pattern: $(bash -c "..." redirect)
        while True:
            m = re.search(r'\$\((timeout \d+ )?bash -c "(.*?)"( 2>&1| 2>/dev/null)?\)', line)
            if not m:
                break
            timeout_prefix = m.group(1) or ""
            inner = m.group(2)
            redirect = m.group(3) or ""
            inner = inner.replace("\\$", "$")
            inner = re.sub(r'\s*</dev/null', '', inner)
            if not redirect and '2>&1' not in inner and '2>/dev/null' not in inner:
                redirect = " 2>&1"
            replacement = f"$({timeout_prefix}{inner}{redirect})"
            line = line[:m.start()] + replacement + line[m.end():]
            changed = True

        # Pattern: $var = bash -c "..." [2>$null|2>&1] (not wrapped in $())
        if not changed:
            m = re.match(r'(\s*\$\w+\s*=\s*)bash -c "(.*?)"(\s*2>\$null|\s*2>&1)?$', line)
            if m:
                indent_var = m.group(1)
                inner = m.group(2)
                inner = re.sub(r'\s*</dev/null', '', inner)
                inner = inner.replace("\\$", "$")
                if '2>&1' not in inner and '2>/dev/null' not in inner:
                    inner = inner.rstrip() + " 2>&1"
                line = f"{indent_var}$({inner})"
                changed = True

        # Pattern: bare bash -c "..." 2>&1 used in expressions
        if not changed and 'bash -c "' in line:
            m = re.search(r'bash -c "(.*?)"(\s*2>&1|\s*2>\$null|\s*2>/dev/null)?', line)
            if m:
                cmd = m.group(1)
                cmd = re.sub(r'\s*</dev/null', '', cmd)
                cmd = cmd.replace("\\$", "$")
                if '2>&1' not in cmd and '2>/dev/null' not in cmd:
                    cmd = cmd.rstrip() + " 2>&1"
                replacement = f"$({cmd})"
                line = line[:m.start()] + replacement + line[m.end():]
                changed = True

        # Pattern: bare bash -c 'single-quoted cmd' 2>&1
        if not changed and "bash -c '" in line:
            m = re.search(r"bash -c '(.*?)'(\s*2>&1|\s*2>\$null|\s*2>/dev/null)?", line)
            if m:
                cmd = m.group(1)
                cmd = re.sub(r'\s*</dev/null', '', cmd)
                if '2>&1' not in cmd and '2>/dev/null' not in cmd:
                    cmd = cmd.rstrip() + " 2>&1"
                replacement = f"$({cmd})"
                line = line[:m.start()] + replacement + line[m.end():]
                changed = True

        # Pattern: $(bash -c '...' redirect)
        if not changed:
            m = re.search(r"\$\((timeout \d+ )?bash -c '(.*?)'( 2>&1| 2>/dev/null)?\)", line)
            if m:
                timeout_prefix = m.group(1) or ""
                inner = m.group(2)
                redirect = m.group(3) or ""
                has_dev_null_stdin = '</dev/null' in inner
                inner = re.sub(r'\s*</dev/null', '', inner)
                if has_dev_null_stdin and 'openssl s_client' in inner:
                    prefix_str = f"echo '' | {timeout_prefix}"
                else:
                    prefix_str = timeout_prefix
                if not redirect and '2>&1' not in inner and '2>/dev/null' not in inner:
                    redirect = " 2>&1"
                replacement = f"$({prefix_str}{inner}{redirect})"
                line = line[:m.start()] + replacement + line[m.end():]
                changed = True

        if changed:
            count += 1

        new_lines.append(line)

    return '\n'.join(new_lines), count


def unwrap_dollar_sh_c(text):
    """Remove $(sh -c "...") and $(timeout N sh -c "...") wrappers."""
    count = 0
    lines = text.split('\n')
    new_lines = []

    for i, line in enumerate(lines):
        if not re.search(r'\bsh -c\b', line) or line.lstrip().startswith('#'):
            new_lines.append(line)
            continue

        original_line = line
        changed = False

        # Pattern: $(timeout N sh -c "..." redirect) or $(sh -c "..." redirect)
        while True:
            m = re.search(r'\$\((timeout \d+ )?sh -c "(.*?)"( 2>&1| 2>/dev/null)?\)', line)
            if not m:
                break
            timeout_prefix = m.group(1) or ""
            inner = m.group(2)
            redirect = m.group(3) or ""
            inner = inner.replace("\\$", "$")
            inner = re.sub(r'\s*</dev/null', '', inner)
            if not redirect and '2>&1' not in inner and '2>/dev/null' not in inner:
                redirect = " 2>&1"
            replacement = f"$({timeout_prefix}{inner}{redirect})"
            line = line[:m.start()] + replacement + line[m.end():]
            changed = True

        # Pattern: bare sh -c "..." 2>&1 (not wrapped in $())
        if not changed and re.search(r'\bsh -c\b', line):
            m = re.search(r'\bsh -c "(.*?)"(\s*2>&1|\s*2>/dev/null)?', line)
            if m and '$(' not in line[max(0,m.start()-2):m.start()]:
                cmd = m.group(1)
                cmd = re.sub(r'\s*</dev/null', '', cmd)
                cmd = cmd.replace("\\$", "$")
                if '2>&1' not in cmd and '2>/dev/null' not in cmd:
                    cmd = cmd.rstrip() + " 2>&1"
                replacement = f"$({cmd})"
                line = line[:m.start()] + replacement + line[m.end():]
                changed = True

        # Pattern: bare sh -c '...' 2>&1
        if not changed and re.search(r"\bsh -c '", line):
            m = re.search(r"\bsh -c '(.*?)'(\s*2>&1|\s*2>/dev/null)?", line)
            if m and '$(' not in line[max(0,m.start()-2):m.start()]:
                cmd = m.group(1)
                cmd = re.sub(r'\s*</dev/null', '', cmd)
                if '2>&1' not in cmd and '2>/dev/null' not in cmd:
                    cmd = cmd.rstrip() + " 2>&1"
                replacement = f"$({cmd})"
                line = line[:m.start()] + replacement + line[m.end():]
                changed = True

        # Pattern: $(timeout N sh -c '...' redirect)
        if not changed:
            m = re.search(r"\$\((timeout \d+ )?sh -c '(.*?)'( 2>&1| 2>/dev/null)?\)", line)
            if m:
                timeout_prefix = m.group(1) or ""
                inner = m.group(2)
                redirect = m.group(3) or ""
                has_dev_null_stdin = '</dev/null' in inner
                inner = re.sub(r'\s*</dev/null', '', inner)
                if has_dev_null_stdin and 'openssl s_client' in inner:
                    prefix_str = f"echo '' | {timeout_prefix}"
                else:
                    prefix_str = timeout_prefix
                if not redirect and '2>&1' not in inner and '2>/dev/null' not in inner:
                    redirect = " 2>&1"
                replacement = f"$({prefix_str}{inner}{redirect})"
                line = line[:m.start()] + replacement + line[m.end():]
                changed = True

        if changed:
            count += 1

        new_lines.append(line)

    return '\n'.join(new_lines), count


def verify(text):
    """Count remaining violations."""
    remaining = []
    for j, line in enumerate(text.split('\n')):
        stripped = line.lstrip()
        if stripped.startswith('#'):
            continue
        if re.search(r'\bbash -c\b', line) or re.search(r'\bsh -c\b', line):
            remaining.append((j+1, line.strip()[:120]))
    return remaining


def main():
    if not MODULE_FILE.exists():
        print(f"ERROR: Module file not found: {MODULE_FILE}")
        sys.exit(1)

    print(f"Reading: {MODULE_FILE}")
    original = MODULE_FILE.read_text(encoding='utf-8')
    text = original

    # Step 1: Fix variable-based bash -c calls
    text, var_count = fix_variable_bash_c(text)
    print(f"Step 1: Fixed {var_count} variable-based bash -c calls")

    # Step 2: Unwrap $(bash -c "...") patterns
    text, bash_count = unwrap_dollar_bash_c(text)
    print(f"Step 2: Unwrapped {bash_count} bash -c calls")

    # Step 3: Unwrap $(sh -c "...") patterns
    text, sh_count = unwrap_dollar_sh_c(text)
    print(f"Step 3: Unwrapped {sh_count} sh -c calls")

    # Verify
    remaining = verify(text)
    print(f"\nRemaining violations: {len(remaining)}")
    for lineno, line in remaining[:15]:
        print(f"  Line {lineno}: {line}")
    if len(remaining) > 15:
        print(f"  ... and {len(remaining) - 15} more")

    total = var_count + bash_count + sh_count
    print(f"\nTotal fixes: {total}")

    if text != original:
        MODULE_FILE.write_text(text, encoding='utf-8')
        print(f"Wrote: {MODULE_FILE}")
    else:
        print("No changes needed.")


if __name__ == "__main__":
    main()
