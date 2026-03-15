#!/usr/bin/env python3
r"""Fix Rule 1 violations: Replace backtick-n with $nl across all modules.

Phase 3 QA Remediation -- replaces `n in double-quoted PowerShell strings
with $nl variable references and adds $nl = [Environment]::NewLine declarations
to functions that need them.

Transformation examples:
  -split "`n"           -> -split $nl
  -join "`n"            -> -join $nl
  "text`n"              -> "text" + $nl
  "`ntext"              -> $nl + "text"
  "text`nmore"          -> "text" + $nl + "more"
  "`n`n"                -> $nl + $nl
  "text`n`n"            -> "text" + $nl + $nl
"""

import re
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[3] / "Evaluate-STIG" / "Modules"

MODULES = [
    BASE / "Scan-XO_WebSRG_Checks" / "Scan-XO_WebSRG_Checks.psm1",
    BASE / "Scan-XO_ASD_Checks" / "Scan-XO_ASD_Checks.psm1",
    BASE / "Scan-XCP-ng_VMM_Checks" / "Scan-XCP-ng_VMM_Checks.psm1",
]


def transform_quoted_string(content):
    """Transform a double-quoted string content containing `n into $nl concatenation.

    Args:
        content: The string content BETWEEN the double quotes (not including quotes).

    Returns:
        Replacement text (may include multiple parts joined with ' + ').
    """
    # Split by backtick-n
    parts = content.split('`n')

    # Build replacement pieces
    pieces = []
    for k, part in enumerate(parts):
        if part:
            pieces.append(f'"{part}"')
        if k < len(parts) - 1:
            pieces.append('$nl')

    return ' + '.join(pieces) if pieces else '$nl'


def process_line(line):
    """Replace backtick-n in double-quoted strings on a single line.

    Returns the transformed line (or unchanged if no backtick-n in strings).
    """
    if '`n' not in line:
        return line

    # Skip comments
    stripped = line.lstrip()
    if stripped.startswith('#'):
        return line

    result = []
    i = 0
    changed = False

    while i < len(line):
        if line[i] == '"':
            # Find the end of the double-quoted string
            j = i + 1
            while j < len(line):
                if line[j] == '"':
                    break
                elif line[j] == '`' and j + 1 < len(line) and line[j + 1] != 'n':
                    j += 2  # skip non-`n escape sequences
                else:
                    j += 1

            if j >= len(line):
                # Unclosed string -- copy rest as-is
                result.append(line[i:])
                i = len(line)
                continue

            # line[i..j] is the quoted string (inclusive of quotes)
            content = line[i + 1:j]

            if '`n' not in content:
                result.append(line[i:j + 1])
            else:
                replacement = transform_quoted_string(content)
                result.append(replacement)
                changed = True

            i = j + 1
        else:
            result.append(line[i])
            i += 1

    return ''.join(result) if changed else line


def add_nl_declarations(text):
    """Add $nl = [Environment]::NewLine to functions that use $nl but don't declare it."""
    count = 0
    func_pattern = re.compile(r'^([Ff]unction\s+Get-V\d+\s*\{)', re.MULTILINE)
    matches = list(func_pattern.finditer(text))

    # Process in reverse order so offsets don't shift
    for idx in range(len(matches) - 1, -1, -1):
        m = matches[idx]
        start = m.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        body = text[start:end]

        # Check if function uses $nl but doesn't declare it
        uses_nl = '$nl' in body
        has_decl = '[Environment]::NewLine' in body

        if uses_nl and not has_decl:
            # Find the right insertion point: after "if ($GetCorpParams) { ... }" block
            # Look for the closing brace of the GetCorpParams block
            corp_match = re.search(
                r'if\s*\(\$GetCorpParams\)\s*\{.*?return\s+Send-CheckResult\s+@SendCheckParams\s*\}',
                body, re.DOTALL
            )
            if corp_match:
                insert_pos = start + corp_match.end()
                # Find the next newline after the closing brace
                nl_pos = text.find('\n', insert_pos)
                if nl_pos != -1:
                    # Insert $nl declaration
                    indent = '    '
                    insertion = f'\n{indent}$nl = [Environment]::NewLine'
                    text = text[:nl_pos] + insertion + text[nl_pos:]
                    count += 1
            else:
                # Try alternate pattern: after param block closing paren
                # Look for the Param(...) block end
                param_match = re.search(r'\)\s*\n', body)
                if param_match:
                    # Find $ModuleName line
                    mod_match = re.search(r'\$ModuleName\s*=', body)
                    if mod_match:
                        # Insert after GetCorpParams if block or after ModuleName
                        line_end = body.find('\n', mod_match.end())
                        if line_end != -1:
                            insert_pos = start + line_end
                            nl_pos = text.find('\n', insert_pos)
                            if nl_pos != -1:
                                indent = '    '
                                insertion = f'\n{indent}$nl = [Environment]::NewLine'
                                text = text[:nl_pos] + insertion + text[nl_pos:]
                                count += 1

    return text, count


def fix_module(filepath):
    """Fix all backtick-n violations in a module file."""
    print(f"\nProcessing: {filepath.name}")
    original = filepath.read_text(encoding='utf-8')
    text = original

    # Step 1: Replace backtick-n in double-quoted strings
    lines = text.split('\n')
    new_lines = []
    line_count = 0

    for line in lines:
        new_line = process_line(line)
        if new_line != line:
            line_count += 1
        new_lines.append(new_line)

    text = '\n'.join(new_lines)
    print(f"  Step 1: Replaced backtick-n on {line_count} lines")

    # Step 2: Add $nl declarations to functions that need them
    text, decl_count = add_nl_declarations(text)
    print(f"  Step 2: Added {decl_count} $nl declarations")

    # Verify
    remaining = 0
    for j, line in enumerate(text.split('\n')):
        stripped = line.lstrip()
        if stripped.startswith('#'):
            continue
        if '`n' in line:
            remaining += 1
            if remaining <= 5:
                print(f"  REMAINING line {j+1}: {line.strip()[:120]}")

    print(f"  Remaining backtick-n lines: {remaining}")

    if text != original:
        filepath.write_text(text, encoding='utf-8')
        print(f"  Wrote: {filepath}")
    else:
        print(f"  No changes needed.")

    return line_count, decl_count, remaining


def main():
    total_lines = 0
    total_decls = 0
    total_remaining = 0

    for mod_path in MODULES:
        if not mod_path.exists():
            print(f"ERROR: {mod_path} not found")
            sys.exit(1)
        lines, decls, remaining = fix_module(mod_path)
        total_lines += lines
        total_decls += decls
        total_remaining += remaining

    print(f"\n{'='*60}")
    print(f"Total lines fixed: {total_lines}")
    print(f"Total $nl declarations added: {total_decls}")
    print(f"Total remaining violations: {total_remaining}")


if __name__ == "__main__":
    main()
