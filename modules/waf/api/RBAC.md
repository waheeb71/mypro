# WAF Module API — Authorization & RBAC

## الملف
`modules/waf/api/router.py`

## نظام الصلاحيات المُطبَّق

### قبل التحديث
```python
# كل endpoint يتطلب admin فقط
async def waf_status(token = Depends(require_admin)):
```

### بعد التحديث (RBAC كامل)
```python
from api.rest.auth import require_admin, make_permission_checker

# يسمح للمدير + أي مستخدم لديه rule "waf" في قاعدة البيانات
require_waf = make_permission_checker("waf")
```

## جدول الصلاحيات

| Endpoint | الصلاحية المطلوبة | السبب |
|----------|-------------------|-------|
| `GET /status` | `require_waf` | قراءة فقط |
| `GET /gnn/status` | `require_waf` | قراءة فقط |
| `GET /gnn/logs` | `require_waf` | قراءة فقط |
| `GET /gnn/train/status` | `require_waf` | قراءة فقط |
| `POST /gnn/logs/flush` | `require_admin` | عملية تدميرية |
| `POST /gnn/train` | `require_admin` | تدريب مكلف |
| `PUT /gnn/activate` | `require_admin` | تغيير النموذج الحي |
| `PUT /gnn/toggle` | `require_admin` | تغيير سلوك الإنتاج |
| `PUT /waap/rate_limiter/config` | `require_admin` | تغيير أمني حساس |
| `PUT /waap/toggle/{feature}` | `require_admin` | تغيير أمني حساس |
| `WS /live` | JWT في query string | WebSocket |

## منح مستخدم صلاحية WAF

```http
POST /api/v1/users/ali/rules
Authorization: Bearer <admin-token>
Content-Type: application/json

{ "resource": "waf" }
```

## نمط تطبيق RBAC على أي Module جديد

```python
# في بداية router.py لأي module جديد
from api.rest.auth import require_admin, make_permission_checker

require_MY_MODULE = make_permission_checker("my_module")

@router.get("/status")
async def status(token = Depends(require_MY_MODULE)):
    # يدخل: admin + أي user معه rule "my_module"
    ...

@router.delete("/dangerous")
async def dangerous(token = Depends(require_admin)):
    # admin فقط
    ...
```

## الـ Endpoints الكاملة للـ WAF

| Method | URL | الوصف |
|--------|-----|-------|
| `GET` | `/api/v1/waf/status` | حالة WAF والميزات |
| `WS` | `/api/v1/waf/live` | بث مباشر للأحداث |
| `GET` | `/api/v1/waf/gnn/status` | حالة نموذج GNN |
| `GET` | `/api/v1/waf/gnn/logs` | بيانات سجلات الجلسات |
| `POST` | `/api/v1/waf/gnn/logs/flush` | إفراغ البافر للـ CSV |
| `POST` | `/api/v1/waf/gnn/train` | بدء تدريب GNN |
| `GET` | `/api/v1/waf/gnn/train/status` | حالة التدريب |
| `PUT` | `/api/v1/waf/gnn/activate` | تحميل النموذج المدرَّب |
| `PUT` | `/api/v1/waf/gnn/toggle` | تشغيل/إيقاف GNN |
| `PUT` | `/api/v1/waf/waap/rate_limiter/config` | ضبط حدود الطلبات |
| `PUT` | `/api/v1/waf/waap/toggle/{feature}` | تبديل ميزة WAAP |
| `POST` | `/api/v1/waf/waap/api_schema/upload` | رفع API Schema |
