import requests
import yaml
from pathlib import Path
from typing import Optional

CONFIG_FILE = Path.home() / ".ngfw" / "config.yaml"
DEFAULT_API_URL = "http://localhost:8000/api/v1"

class NGFWClient:
    """NGFW API client"""
    
    def __init__(self, api_url: str, token: Optional[str] = None):
        self.api_url = api_url.rstrip('/')
        self.token = token
        self.session = requests.Session()
        
        if token:
            self.session.headers['Authorization'] = f'Bearer {token}'
    
    def login(self, username: str, password: str) -> str:
        response = self.session.post(
            f"{self.api_url}/auth/login",
            json={"username": username, "password": password}
        )
        if response.status_code == 200:
            data = response.json()
            self.token = data['access_token']
            self.session.headers['Authorization'] = f'Bearer {self.token}'
            return self.token
        else:
            raise Exception(f"Login failed: {response.text}")
    
    def get(self, endpoint: str, **kwargs):
        response = self.session.get(f"{self.api_url}/{endpoint}", **kwargs)
        response.raise_for_status()
        return response.json()
    
    def post(self, endpoint: str, **kwargs):
        response = self.session.post(f"{self.api_url}/{endpoint}", **kwargs)
        response.raise_for_status()
        return response.json()
    
    def put(self, endpoint: str, **kwargs):
        response = self.session.put(f"{self.api_url}/{endpoint}", **kwargs)
        response.raise_for_status()
        return response.json()
    
    def delete(self, endpoint: str, **kwargs):
        response = self.session.delete(f"{self.api_url}/{endpoint}", **kwargs)
        response.raise_for_status()

def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f)
    return {}

def save_config(config: dict):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        yaml.dump(config, f)

def get_client() -> NGFWClient:
    config = load_config()
    api_url = config.get('api_url', DEFAULT_API_URL)
    token = config.get('token')
    return NGFWClient(api_url, token)
