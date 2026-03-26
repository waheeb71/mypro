# طبقة API — الهيكل والتوثيق

## المجلد
`api/rest/`

## الهيكل الكامل

```
api/rest/
├── main.py                    ← المجمِّع الرئيسي (app factory)
├── auth.py                    ← JWT + RBAC
├── gunicorn_conf.py           ← إعدادات خادم الإنتاج
└── endpoints/                 ← كل endpoint في ملفه الخاص
    ├── __init__.py
    ├── auth_routes.py         → /api/v1/auth/*
    ├── status_routes.py       → /health, /api/v1/status, /metrics
    ├── config_routes.py       → /api/v1/config, /api/v1/modules/*
    ├── users_routes.py        → /api/v1/users/*
    ├── networking_routes.py   → /api/v1/system/networking/*
    └── update_routes.py       → /api/v1/system/update/*
```

---

## الـ Endpoints الكاملة

### 🔐 المصادقة (`auth_routes.py`)
| Method | URL | الصلاحية | الوصف |
|--------|-----|-----------|-------|
| `POST` | `/api/v1/auth/login` | عام | تسجيل دخول + JWT |
| `POST` | `/api/v1/auth/refresh` | مستخدم | تجديد التوكن |
| `GET` | `/api/v1/auth/me` | مستخدم | بيانات المستخدم الحالي |

### 📊 الحالة والصحة (`status_routes.py`)
| Method | URL | الصلاحية | الوصف |
|--------|-----|-----------|-------|
| `GET` | `/health` | عام | فحص الحياة (Load balancer) |
| `GET` | `/api/v1/health/liveness` | عام | Kubernetes liveness |
| `GET` | `/api/v1/health/readiness` | عام | Kubernetes readiness |
| `GET` | `/api/v1/health/detailed` | مستخدم | تفاصيل مكونات النظام |
| `GET` | `/api/v1/status` | مشغّل+ | مقاييس النظام الكاملة |
| `GET` | `/metrics` | عام | Prometheus metrics |

### ⚙️ الإعدادات (`config_routes.py`)
| Method | URL | الصلاحية | الوصف |
|--------|-----|-----------|-------|
| `GET` | `/api/v1/config` | مدير | قراءة الإعدادات الكاملة |
| `PUT` | `/api/v1/config` | مدير | تحديث قيمة إعداد |
| `GET` | `/api/v1/config/modules` | مشغّل+ | حالة كل الوحدات |
| `PUT` | `/api/v1/modules/{name}/toggle` | مدير | تفعيل/إيقاف وحدة |

### 👥 إدارة المستخدمين (`users_routes.py`)
| Method | URL | الصلاحية | الوصف |
|--------|-----|-----------|-------|
| `GET` | `/api/v1/users/` | مدير | قائمة المستخدمين |
| `POST` | `/api/v1/users/` | مدير | إنشاء مستخدم |
| `DELETE` | `/api/v1/users/{username}` | مدير | حذف مستخدم |
| `GET` | `/api/v1/users/{username}/rules` | مدير | صلاحيات المستخدم |
| `POST` | `/api/v1/users/{username}/rules` | مدير | منح صلاحية resource |
| `DELETE` | `/api/v1/users/{username}/rules/{id}` | مدير | سحب صلاحية |

### 🌐 الشبكة (`networking_routes.py`)
| Method | URL | الصلاحية | الوصف |
|--------|-----|-----------|-------|
| `GET` | `/api/v1/system/networking/status` | مدير | حالة IPTables |
| `POST` | `/api/v1/system/networking/transparent-proxy` | مدير | تفعيل/إيقاف الـ NAT |

### 🔄 التحديثات (`update_routes.py`)
| Method | URL | الصلاحية | الوصف |
|--------|-----|-----------|-------|
| `GET` | `/api/v1/system/update/check` | مدير | فحص GitHub للتحديثات |
| `POST` | `/api/v1/system/update/apply` | مدير | تثبيت التحديث |
| `GET` | `/api/v1/system/update/history` | مدير | سجل التحديثات |

---

## نظام الصلاحيات (RBAC)

### الأدوار
| الدور | الوصف |
|-------|-------|
| `admin` | صلاحية كاملة لكل شيء بدون قيود |
| `operator` | قراءة + إدارة الوحدات، بدون حذف مستخدمين |
| `viewer` | قراءة فقط للحالة والصحة |

### صلاحيات الـ Resources
للمستخدمين من غير `admin`، يجب أن يكون لديهم **rule** صريح لكل module:

```http
# المدير يمنح المستخدم صلاحية WAF
POST /api/v1/users/ali/rules
{ "resource": "waf" }

# صلاحيات أخرى
{ "resource": "firewall" }
{ "resource": "vpn" }
{ "resource": "ids_ips" }
{ "resource": "dns_security" }
```

### في كود كل Module
```python
from api.rest.auth import require_admin, make_permission_checker

# يسمح للمدير + أي مستخدم معه rule "waf"
require_waf = make_permission_checker("waf")

@router.get("/status")
async def status(token = Depends(require_waf)):
    ...
```

---

## إضافة Endpoint جديد

```python
# 1. أنشئ api/rest/endpoints/my_routes.py
from fastapi import APIRouter, Depends
from api.rest.auth import make_permission_checker

router = APIRouter(prefix="/api/v1/my-feature", tags=["My Feature"])
require_feature = make_permission_checker("my_feature")

@router.get("/status")
async def status(token = Depends(require_feature)):
    return {"status": "ok"}

# 2. سجِّله في api/rest/main.py (سطر واحد):
from api.rest.endpoints.my_routes import router as my_router
app.include_router(my_router)
```

---

## تشغيل API للتطوير
```bash
cd /opt/enterprise_CyberNexus
python -m api.rest.main

# أو مع uvicorn
uvicorn api.rest.main:app --reload --host 0.0.0.0 --port 8000
```

## وثائق Swagger
- Swagger UI: `http://localhost:8000/api/docs`
- ReDoc: `http://localhost:8000/api/redoc`
- OpenAPI JSON: `http://localhost:8000/api/openapi.json`
