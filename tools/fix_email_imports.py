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
    'from .preprocessor': 'from modules.email_security.engine.utils.preprocessor',
    'import preprocessor': 'import modules.email_security.engine.utils.preprocessor',
    'from .spam_filter': 'from modules.email_security.engine.scanners.spam_filter',
    'from .phishing_detector': 'from modules.email_security.engine.scanners.phishing_detector',
    'from .url_scanner': 'from modules.email_security.engine.scanners.url_scanner',
    'from .attachment_guard': 'from modules.email_security.engine.scanners.attachment_guard',
    'from .sender_reputation': 'from modules.email_security.engine.scanners.sender_reputation',
    'from .risk_engine': 'from modules.email_security.engine.core.risk_engine',
    'from .settings': 'from modules.email_security.engine.core.settings',
    'from modules.email_security.engine.email_inspector': 'from modules.email_security.engine.core.email_inspector',
    'from .email_inspector': 'from modules.email_security.engine.core.email_inspector'
}

base_dir = Path(__file__).resolve().parent.parent / "modules" / "email_security"
base_dir2 = Path(__file__).resolve().parent.parent / "api"
count = 0

for d in [base_dir, base_dir2]:
    for filepath in d.rglob('*.py'):
        if 'venv' in filepath.parts or '.git' in filepath.parts: continue
        for old, new in replacements.items():
            if replace_in_file(filepath, old, new):
                count += 1
                print(f"Updated {old} -> {new} in {filepath.name}")

print(f"Total updates: {count}")
