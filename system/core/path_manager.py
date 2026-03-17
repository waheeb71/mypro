import os
from pathlib import Path
from typing import Union

# Resolve base project directory relative to this file
# system/core/path_manager.py -> system/core -> system -> enterprise_ngfw
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Centralized common directories
CONFIG_DIR = BASE_DIR / "system" / "config"
LOGS_DIR = BASE_DIR / "logs"
MODELS_DIR = BASE_DIR / "models"
DATA_DIR = BASE_DIR / "data"
CERTS_DIR = BASE_DIR / "certs"

def resolve_path(path_str: Union[str, Path, None]) -> Path:
    """
    Resolve a path string which might be absolute or relative to project root.
    If the path is already absolute, returns it as is.
    If it's relative, anchors it to BASE_DIR.
    """
    if not path_str:
        return Path(path_str) if path_str is not None else None
        
    p = Path(path_str)
    if p.is_absolute():
        return p
        
    return BASE_DIR / p
