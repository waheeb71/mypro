"""
Enterprise CyberNexus - Endpoints Package
All API routers live here as individual files.

# How to add a new endpoint group:
# 1. Create api/rest/endpoints/my_feature_routes.py
# 2. Define your APIRouter with prefix and tags
# 3. Import it in api/rest/main.py and call app.include_router(my_router)

Available routers:
  auth_routes.py       — Login, refresh, /me
  status_routes.py     — Health probes, /status, /metrics
  config_routes.py     — Config read/write, module toggle
  users_routes.py      — User CRUD, resource-level rules (RBAC)
  networking_routes.py — IPTables transparent proxy control
  update_routes.py     — GitHub OTA update check & apply
"""
