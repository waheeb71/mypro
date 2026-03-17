import os
from pathlib import Path

def replace_in_file(filepath, old_str, new_str):
    try:
        content = filepath.read_text(encoding='utf-8')
        if old_str in content:
            new_content = content.replace(old_str, new_str)
            filepath.write_text(new_content, encoding='utf-8')
            return True
    except Exception as e:
        pass
    return False

replacements = {
    'from system.core.engine ': 'from system.core.engine ',
    'import system.core.engine': 'import system.core.engine',
    'from system.core.flow_tracker': 'from system.core.flow_tracker',
    'import system.core.flow_tracker': 'import system.core.flow_tracker',
    'from system.core.router': 'from system.core.router',
    'import system.core.router': 'import system.core.router',
    'from system.telemetry.events': 'from system.telemetry.events',
    'import system.telemetry.events': 'import system.telemetry.events',
    'from system.telemetry.health': 'from system.telemetry.health',
    'import system.telemetry.health': 'import system.telemetry.health',
    'from system.ha': 'from system.ha',
    'import system.ha': 'import system.ha',
    'from modules.ssl_inspection.engine': 'from modules.ssl_inspection.engine',
    'import modules.ssl_inspection.engine': 'import modules.ssl_inspection.engine'
}

base_dir = Path(__file__).resolve().parent.parent
count = 0
for filepath in base_dir.rglob('*.py'):
    if 'venv' in filepath.parts or '.git' in filepath.parts: continue
    for old, new in replacements.items():
        if replace_in_file(filepath, old, new):
            count += 1
            print(f'Updated {old} in {filepath.name}')

print(f'Total updates: {count}')
