#!/usr/bin/env python3
"""Check which functions are missing $Username parameter."""
import re

PSM1 = 'Evaluate-STIG/Modules/Scan-XCP-ng_VMM_Checks/Scan-XCP-ng_VMM_Checks.psm1'
with open(PSM1, 'r') as f:
    content = f.read()

# Find all function starts
funcs = [(m.start(), m.group(1)) for m in re.finditer(r'^Function (Get-V\d+)', content, re.MULTILINE)]
missing = []
has_it = []
for i, (start, name) in enumerate(funcs):
    end = funcs[i+1][0] if i+1 < len(funcs) else len(content)
    block = content[start:end]
    if '$Username' in block:
        has_it.append(name)
    else:
        missing.append(name)

print(f'Total functions: {len(funcs)}')
print(f'Have $Username: {len(has_it)}')
print(f'Missing $Username: {len(missing)}')
if missing:
    print('\nMissing:')
    for m in missing:
        print(f'  {m}')
