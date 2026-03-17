# وحدة تحميل الوحدات الديناميكية — `ModuleManager`

## الملف
`system/core/module_manager.py`

## الغرض
تحميل وتسجيل إضافات الفحص (Plugins) بشكل تلقائي بناءً على إعدادات `system/config/base.yaml`، بدلاً من التسجيل اليدوي الثابت (Hardcoded) داخل المحرك الرئيسي.

## كيف يعمل

```
base.yaml
  └── modules:
        ├── waf: enabled: true
        ├── dns_security: enabled: true
        └── malware_av: enabled: false  ← لا يُحمَّل
```

عند بدء التشغيل، يقرأ `ModuleManager` هذا القسم ويبحث عن ملف `plugin.py` داخل مجلد كل وحدة، ثم يسجله في `InspectionPipeline`.

## مسار كل Plugin
```
modules/<name>/engine/plugin.py  →  class <Name>Plugin(InspectorPlugin)
```

## الاستخدام من `engine.py`
```python
from system.core.module_manager import ModuleManager

module_manager = ModuleManager(self.config, self.inspection_pipeline)
module_manager.load_plugins()
```

## تفعيل / إلغاء تفعيل وحدة
### عبر ملف الإعدادات (`base.yaml`):
```yaml
modules:
  malware_av:
    enabled: false   # أوقف الوحدة
```

### عبر API (مباشرة):
```http
PUT /api/v1/modules/malware_av/toggle
Authorization: Bearer <admin-token>
Content-Type: application/json

{ "enabled": false }
```

## Plugins المُنشأة في هذه الجلسة

| الوحدة | الملف |
|--------|-------|
| WAF | `modules/waf/engine/plugin.py` |
| Malware AV | `modules/malware_av/engine/plugin.py` |
| Web Filter | `modules/web_filter/engine/plugin.py` |
| HTTP Inspection | `modules/http_inspection/engine/plugin.py` |
| DNS Security | `modules/dns_security/engine/plugin.py` |
| QoS | `modules/qos/engine/rate_limiter.py` |

## إضافة وحدة جديدة
1. أنشئ `modules/<اسم_الوحدة>/engine/plugin.py`
2. عرّف `class MyPlugin(InspectorPlugin)`
3. أضف الوحدة في `base.yaml` تحت `modules:`
4. **لا حاجة لتعديل أي ملف آخر.**
