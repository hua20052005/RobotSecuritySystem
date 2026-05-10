"""
Fix ui_theme.py by removing corrupted lines 1174-1597 (bare CSS outside a string).
The file currently has:
  - Line 1171: closing triple-quote of _HOME_EXTRA (correct)
  - Lines 1172-1172: blank (ok)
  - Lines 1173-1597: corrupted bare CSS that leaked outside the string
  - Line 1598: another stray triple-quote from a second _HOME_EXTRA definition
  - Lines 1599-...: blank + Python functions (correct)
We need to keep 1-1172 and 1599-end, discarding 1173-1598.
"""
with open(r'frontend/shared/ui_theme.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")

# Show what will be removed (lines are 0-indexed internally, 1-indexed in file)
print("--- First removed line (file line 1173) ---")
print(repr(lines[1172]))
print("--- Last removed line (file line 1598) ---")
print(repr(lines[1597]))
print("--- Line after removal (file line 1599) ---")
print(repr(lines[1598]))

# Keep: lines 0..1171 (file lines 1..1172) + lines 1598..end (file lines 1599..end)
# That means drop lines indices 1172..1597 (inclusive) which is 426 lines
new_lines = lines[:1172] + lines[1598:]

print(f"\nNew total lines: {len(new_lines)}")
print("--- Lines around the join ---")
for i in range(1168, min(1178, len(new_lines))):
    print(f"{i+1}: {repr(new_lines[i])}")

with open(r'frontend/shared/ui_theme.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("\nFile fixed successfully!")
