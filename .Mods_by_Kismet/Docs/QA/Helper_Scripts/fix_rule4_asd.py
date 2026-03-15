#!/usr/bin/env python3
r"""Fix Rule 4 violations in ASD module -- Phase 2D QA Remediation

Removes all sh -c and bash -c wrappers (~638 violations).
Also removes the `bash` filter function (lines 30-39).

Three categories:
1. $(sh -c "...") and $(timeout N sh -c "...") -- ~567 standard unwraps
2. bash -c "literal command" -- ~56 direct inline commands
3. bash -c $cmd 2>$null -- ~15 variable-based calls (inline the command)
"""

import re
import sys
from pathlib import Path

MODULE_FILE = (Path(__file__).resolve().parents[3] /
               "Evaluate-STIG" / "Modules" /
               "Scan-XO_ASD_Checks" /
               "Scan-XO_ASD_Checks.psm1")


def remove_bash_filter(text):
    """Remove the bash filter function (lines 30-39)."""
    old = """# ============================================================================
# Helper: bash function for shell command execution
# ============================================================================
filter bash {
    param([string]$c)
    try {
        $result = sh -c $c 2>&1
        return $result
    }
    catch {
        return $null
    }
}"""
    if old in text:
        text = text.replace(old, "# bash filter function removed (QA Phase 2D — Rule 4 remediation)")
        return text, 1
    return text, 0


def unwrap_dollar_sh_c(text):
    """Remove $(sh -c "...") and $(timeout N sh -c "...") wrappers."""
    count = 0
    lines = text.split('\n')
    new_lines = []

    for i, line in enumerate(lines):
        if 'sh -c' not in line or line.lstrip().startswith('#'):
            new_lines.append(line)
            continue

        original_line = line
        changed = False

        # Pattern: $(timeout N sh -c "..." redirect)
        while True:
            m = re.search(r'\$\((timeout \d+ )?sh -c "(.*?)"( 2>&1| 2>/dev/null)?\)', line)
            if not m:
                break
            timeout_prefix = m.group(1) or ""
            inner = m.group(2)
            redirect = m.group(3) or ""
            inner = inner.replace("\\$", "$")
            # Handle echo Q | openssl pattern
            has_echo_pipe = inner.startswith("echo Q |") or inner.startswith("echo |")
            has_dev_null_stdin = '</dev/null' in inner
            inner = re.sub(r'\s*</dev/null', '', inner)
            if not redirect and '2>&1' not in inner and '2>/dev/null' not in inner:
                redirect = " 2>&1"
            replacement = f"$({timeout_prefix}{inner}{redirect})"
            line = line[:m.start()] + replacement + line[m.end():]
            changed = True

        # Pattern: $(sh -c '...' redirect)
        while True:
            m = re.search(r"\$\((timeout \d+ )?sh -c '(.*?)'( 2>&1| 2>/dev/null)?\)", line)
            if not m:
                break
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


def fix_bash_c_inline(text):
    """Fix bash -c "literal command" calls.

    Pattern: $var = bash -c "command..." [2>$null]
    Transform to: $var = $(command... 2>&1)
    """
    count = 0
    lines = text.split('\n')
    new_lines = []

    for i, line in enumerate(lines):
        if 'bash -c "' not in line or line.lstrip().startswith('#'):
            new_lines.append(line)
            continue

        # Match: $var = bash -c "command" [2>$null]
        m = re.match(r'(\s*\$\w+\s*=\s*)bash -c "(.*?)"(\s*2>\$null)?$', line)
        if m:
            indent_var = m.group(1)
            inner = m.group(2)
            # Remove </dev/null from inner command
            inner = re.sub(r'\s*</dev/null', '', inner)
            # Ensure stderr handling
            if '2>&1' not in inner and '2>/dev/null' not in inner:
                inner = inner.rstrip() + " 2>&1"
            line = f"{indent_var}$({inner})"
            count += 1

        new_lines.append(line)

    return '\n'.join(new_lines), count


def fix_bash_c_variable(text):
    """Fix bash -c $cmd calls where $cmd is a variable.

    Pattern (two lines):
        $cmd = "shell command"
        $result = bash -c $cmd 2>$null

    Transform to:
        $result = $(shell command 2>&1)
    """
    count = 0
    lines = text.split('\n')
    new_lines = []
    skip_next = False

    for i, line in enumerate(lines):
        if skip_next:
            skip_next = False
            continue

        # Check if next line uses bash -c $cmd
        if i + 1 < len(lines):
            next_line = lines[i + 1]
            cmd_assign = re.match(r'(\s*)\$cmd\s*=\s*"(.*)"', line)
            bash_call = re.match(r'(\s*)(\$\w+)\s*=\s*bash -c \$cmd\s*2>\$null', next_line)

            if cmd_assign and bash_call:
                indent = bash_call.group(1)
                var_name = bash_call.group(2)
                cmd_body = cmd_assign.group(2)
                # Remove </dev/null
                cmd_body = re.sub(r'\s*</dev/null', '', cmd_body)
                # Ensure stderr handling
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
    sh_c = sum(1 for line in text.split('\n')
               if 'sh -c' in line and not line.lstrip().startswith('#'))
    bash_c = sum(1 for line in text.split('\n')
                 if re.search(r'bash -c', line) and not line.lstrip().startswith('#'))
    return sh_c, bash_c


def main():
    if not MODULE_FILE.exists():
        print(f"ERROR: Module file not found: {MODULE_FILE}")
        sys.exit(1)

    print(f"Reading: {MODULE_FILE}")
    original = MODULE_FILE.read_text(encoding='utf-8')
    text = original

    # Step 1: Remove bash filter function
    text, filter_count = remove_bash_filter(text)
    print(f"Step 1: Removed bash filter function: {filter_count}")

    # Step 2: Fix bash -c $cmd (variable-based) — must run before inline
    text, var_count = fix_bash_c_variable(text)
    print(f"Step 2: Fixed {var_count} bash -c $cmd variable calls")

    # Step 3: Fix bash -c "literal" calls
    text, inline_count = fix_bash_c_inline(text)
    print(f"Step 3: Fixed {inline_count} bash -c inline calls")

    # Step 4: Unwrap $(sh -c "...") standard patterns
    text, shc_count = unwrap_dollar_sh_c(text)
    print(f"Step 4: Unwrapped {shc_count} $(sh -c ...) calls")

    # Verify
    sh_remaining, bash_remaining = verify(text)
    print(f"\nRemaining: sh -c={sh_remaining}, bash -c={bash_remaining}")

    if sh_remaining > 0 or bash_remaining > 0:
        for j, line in enumerate(text.split('\n')):
            if ('sh -c' in line or re.search(r'bash -c', line)) and not line.lstrip().startswith('#'):
                print(f"  Line {j+1}: {line.strip()[:120]}")
                if j > 15 and sh_remaining + bash_remaining > 15:
                    print(f"  ... and more")
                    break

    total = filter_count + var_count + inline_count + shc_count
    print(f"\nTotal fixes: {total}")

    if text != original:
        MODULE_FILE.write_text(text, encoding='utf-8')
        print(f"Wrote: {MODULE_FILE}")
    else:
        print("No changes needed.")


if __name__ == "__main__":
    main()
