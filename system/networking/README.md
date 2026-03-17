# مدير شبكة الـ Proxy الشفاف — `TransparentProxyManager`

## الملف
`system/networking/transparent_proxy.py`

## الغرض
استبدال سكربت `scripts/networking/setup-transparent-proxy.sh` بالكامل.  
يُدير قواعد `iptables` في Linux لإعادة توجيه حركة الشبكة إلى محرك الفحص.

## ما يفعله تلقائياً عند بدء التشغيل
1. يكتشف واجهة الشبكة الداخلية (LAN) والخارجية (WAN) تلقائياً
2. يُفعِّل IP Forwarding في النواة
3. ينشئ سلسلة `NGFW_REDIRECT` في جدول nat
4. يُعيد توجيه بورت 80 → 8080 و 443 → 8443
5. يُطبق Masquerade للإنترنت الصادر

## عند إيقاف التشغيل
يمسح كل القواعد التي أنشأها (Graceful Teardown) — الجهاز يعود لحالته الطبيعية تلقائياً.

## الاستخدام من `engine.py`
```python
# يتم تلقائياً عند proxy mode = transparent
self.transparent_networking = TransparentProxyManager(self.config)

# في start_firewall_components():
self.transparent_networking.enable_ip_forwarding()
self.transparent_networking.clear_existing_rules()
self.transparent_networking.setup_transparent_rules()

# في stop_firewall_components():
self.transparent_networking.teardown()
```

## التحكم عبر API
```http
# تفعيل قواعد الشبكة
POST /api/v1/system/networking/transparent-proxy
Authorization: Bearer <admin-token>
{ "enable": true }

# إلغاء التفعيل
{ "enable": false }

# فحص الحالة
GET /api/v1/system/networking/status
```

## الإعدادات في `base.yaml`
```yaml
proxy:
  mode: transparent   # transparent | forward | reverse | none

routing:
  default_mode: transparent
  port_mappings:
    80: transparent   # يُعاد توجيهه إلى 8080
    443: transparent  # يُعاد توجيهه إلى 8443
```

## متطلبات التشغيل
- صلاحيات `root` في Linux
- حزم `iptables` و `iproute2` مثبتة
- لا تعمل في Windows (يتجاهل بهدوء)

## ما تم استبداله
| القديم | الجديد |
|--------|--------|
| `scripts/networking/setup-transparent-proxy.sh` | `system/networking/transparent_proxy.py` |
| تشغيل يدوي قبل البدء | تلقائي داخل دورة حياة المحرك |
| لا يُلغى عند الإيقاف | يُلغى تلقائياً |
