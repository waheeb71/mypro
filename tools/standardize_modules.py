import os
from pathlib import Path

modules_dir = Path(__file__).resolve().parent.parent / "modules"
for mod in modules_dir.iterdir():
    if not mod.is_dir() or mod.name == '__pycache__': continue

    # Ensure __init__.py exists everywhere
    (mod / '__init__.py').touch(exist_ok=True)
    
    # API Router
    api_dir = mod / 'api'
    api_dir.mkdir(exist_ok=True)
    (api_dir / '__init__.py').touch(exist_ok=True)
    router_file = api_dir / 'router.py'
    if not router_file.exists():
        content = f'''from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/{mod.name}", tags=["{mod.name}"])

@router.get("/status")
async def get_status():
    return {{"status": "active", "module": "{mod.name}"}}
'''
        router_file.write_text(content, encoding='utf-8')
    
    # Config
    config_dir = mod / 'config'
    config_dir.mkdir(exist_ok=True)
    (config_dir / '__init__.py').touch(exist_ok=True)
    settings_file = config_dir / 'settings.yaml'
    if not settings_file.exists():
        content = f'''{mod.name}:
  enabled: true
  mode: "monitor"
'''
        settings_file.write_text(content, encoding='utf-8')

    # Engine
    engine_dir = mod / 'engine'
    engine_dir.mkdir(exist_ok=True)
    (engine_dir / '__init__.py').touch(exist_ok=True)

    # Policy
    policy_dir = mod / 'policy'
    policy_dir.mkdir(exist_ok=True)
    (policy_dir / '__init__.py').touch(exist_ok=True)

    # Models
    models_dir = mod / 'models'
    models_dir.mkdir(exist_ok=True)
    (models_dir / '__init__.py').touch(exist_ok=True)

print("Modules standardization complete.")
