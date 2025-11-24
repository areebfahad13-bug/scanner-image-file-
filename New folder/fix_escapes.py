#!/usr/bin/env python3
"""Quick script to fix escaped strings in Python files."""
import sys

files_to_fix = [
    'app/threat_intelligence.py',
    'app/file_parser.py',
    'api/main.py'
]

for filepath in files_to_fix:
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Fix escaped triple quotes
        content = content.replace('\\"\\"\\"', '"""')
        content = content.replace("\\'\\'\\'", "'''")
        
        # Fix escaped double quotes in f-strings and regular strings
        # But be careful not to break legitimately escaped quotes
        content = content.replace('f\\"', 'f"')
        content = content.replace('\\"', '"')
        
        # Fix escaped single quotes
        content = content.replace("\\'", "'")
        
        # Fix literal \n in docstrings
        content = content.replace('."""\\n        ', '."""\n        ')
        content = content.replace(".'\\n        ", ".''\n        ")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"Fixed: {filepath}")
    
    except Exception as e:
        print(f"Error fixing {filepath}: {e}")

print("Done!")
