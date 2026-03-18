import requests

url = "http://127.0.0.1:8000/api/v1/auth/login"
data = {"username": "admin", "password": "Admin@1234"}

try:
    print(f"Testing login at {url} with {data}")
    response = requests.post(url, json=data, headers={"Content-Type": "application/json"}, timeout=5)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response Headers: {response.headers}")
    print(f"Response Body: {response.text}")
    
except Exception as e:
    print(f"Test failed: {e}")
