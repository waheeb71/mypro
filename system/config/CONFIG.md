# إعدادات النظام المركزية — `base.yaml`

## الملف
`system/config/base.yaml`

## الغرض
ملف الإعدادات الرئيسي للنظام. يتحكم في كل وحدات الجدار الناري وطريقة عملها.

## القسم الجديد `modules:` (مُضاف في هذه الجلسة)

```yaml
modules:
  firewall:
    enabled: true
    mode: strict
  ssl_inspection:
    enabled: true
  dlp:
    enabled: true
  web_filter:
    enabled: true
  ids_ips:
    enabled: true
  malware_av:
    enabled: true
  dns_security:
    enabled: true
  http_inspection:
    enabled: true
  qos:
    enabled: true
  email_security:
    enabled: false
  uba:
    enabled: true
  predictive_ai:
    enabled: true
  vpn:
    enabled: false
  waf:
    enabled: true
```

## قراءة الإعدادات في الكود
```python
import yaml

with open("system/config/base.yaml", "r") as f:
    config = yaml.safe_load(f)

# التحقق من تفعيل وحدة
is_enabled = config.get("modules", {}).get("waf", {}).get("enabled", False)
```

## تعديل الإعدادات عبر API
```http
# قراءة كل الإعدادات
GET /api/v1/config
Authorization: Bearer <admin-token>

# تحديث قيمة معينة
PUT /api/v1/config
{ "category": "proxy", "key": "mode", "value": "transparent" }

# عرض حالة الوحدات
GET /api/v1/config/modules

# تفعيل/إيقاف وحدة
PUT /api/v1/modules/waf/toggle
{ "enabled": false }
```

## متغيرات البيئة
| المتغير | القيمة الافتراضية | الوصف |
|---------|------------------|--------|
| `CyberNexus_CONFIG` | `/etc/CyberNexus/config.yaml` | مسار ملف الإعدادات في الإنتاج |
| `CyberNexus_ENV` | `production` | بيئة التشغيل (`production`/`development`) |
| `CyberNexus_SECRET_KEY` | مُولَّد تلقائياً | مفتاح JWT (يجب تعيينه في الإنتاج) |
| `CyberNexus_ADMIN_PASSWORD` | `admin123` | كلمة مرور المدير الافتراضية |
