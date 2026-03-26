# المثبّت الذكي — `smart_install.py`

## الملف
`scripts/install/smart_install.py`

## الغرض
استبدال `install.sh` بمثبّت Python ذكي يعمل على أي توزيعة Linux ويستخدم الذكاء الاصطناعي (Gemini API) لحل أخطاء التثبيت تلقائياً.

## التشغيل

```bash
# الطريقة القياسية
sudo python3 scripts/install/smart_install.py

# مع مفتاح Gemini لحل الأخطاء تلقائياً
sudo GEMINI_API_KEY="your-key" python3 scripts/install/smart_install.py

# تحديد مجلد التثبيت
sudo CyberNexus_HOME="/opt/my-CyberNexus" python3 scripts/install/smart_install.py
```

## ما يفعله تلقائياً

| الخطوة | الوصف |
|--------|-------|
| 1 | اكتشاف توزيعة Linux (Debian/Ubuntu/RHEL/Kali) |
| 2 | تثبيت حزم النظام (`python3`, `git`, `iptables`, إلخ) |
| 3 | نسخ الملفات إلى مجلد التثبيت (`/opt/enterprise_CyberNexus`) |
| 4 | إنشاء بيئة Python افتراضية (`venv`) |
| 5 | تثبيت مكتبات Python من `requirements.txt` |
| 6 | إنشاء ملفات الإعداد وشهادات TLS |
| 7 | إنشاء خدمة `systemd` (`CyberNexus.service`) |
| 8 | إنشاء أمر مختصر عالمي (`CyberNexus-start`) |

## الذكاء الاصطناعي (Gemini)

عند حدوث خطأ في أي خطوة، يُرسل المثبّت إلى Gemini API:
- وصف كامل لمكونات النظام
- رسالة الخطأ
- معلومات التوزيعة

Gemini يرد بأوامر bash لحل المشكلة، ثم المثبّت ينفذها تلقائياً ويُعيد المحاولة.

## متغيرات البيئة

| المتغير | الافتراضي | الوصف |
|---------|-----------|-------|
| `GEMINI_API_KEY` | - | مفتاح Gemini لحل الأخطاء |
| `CyberNexus_HOME` | `/opt/enterprise_CyberNexus` | مجلد التثبيت |
| `CyberNexus_ADMIN_PASSWORD` | `admin123` | **يجب تغييره** |

## ما تم استبداله
`scripts/install/install.sh` ← **إيقاف، استخدم `smart_install.py`**

## إنشاء الخدمة
بعد التثبيت:
```bash
# تشغيل النظام
CyberNexus-start

# أو عبر systemd
systemctl start CyberNexus
systemctl status CyberNexus
systemctl enable CyberNexus   # للتشغيل التلقائي عند البدء
```

## تسجيل الأحداث
```bash
journalctl -u CyberNexus -f          # سجل مباشر
tail -f /var/log/CyberNexus/CyberNexus.log # سجل ملف
```
