# سكربت التحديث — `update.sh`

## الملف
`scripts/update.sh`

## الغرض
تحديث نظام NGFW المثبَّت. يستخدم API النظام بشكل أساسي، وينتقل إلى git مباشرةً إذا كان API غير متاح.

## الاستخدام

```bash
# تحديث من الفرع الرئيسي
sudo ./scripts/update.sh

# تحديث من فرع معين
sudo ./scripts/update.sh --branch v2.1

# فحص وجود تحديثات فقط
sudo ./scripts/update.sh --check-only

# تحديث مع API مخصص
./scripts/update.sh --api-url http://ngfw-server:8000
```

## طريقة العمل

```
update.sh
   │
   ├── 1. يحاول الاتصال بـ API
   │       ├── تسجيل دخول + الحصول على token
   │       ├── GET /api/v1/system/update/check  (فحص التحديثات)
   │       └── POST /api/v1/system/update/apply (تطبيق التحديث)
   │
   └── 2. إذا فشل API → git مباشر
           ├── git reset --hard HEAD
           ├── git checkout <branch>
           ├── git pull
           ├── pip install -r requirements.txt
           ├── alembic upgrade head
           └── systemctl restart ngfw
```

## التحديث عبر API (الطريقة المفضلة)

```bash
# 1. احصل على token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 2. فحص التحديثات
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/system/update/check

# 3. تطبيق التحديث
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"branch":"main","run_migrations":true,"restart_service":true}' \
  http://localhost:8000/api/v1/system/update/apply

# 4. متابعة السجل
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/system/update/history
```

## متغيرات البيئة

| المتغير | الافتراضي | الوصف |
|---------|-----------|-------|
| `NGFW_API_URL` | `http://localhost:8000` | عنوان API |
| `NGFW_ADMIN_USER` | `admin` | اسم المدير |
| `NGFW_ADMIN_PASS` | `admin123` | كلمة مرور المدير |
| `NGFW_HOME` | `/opt/enterprise_ngfw` | مجلد التثبيت |

## سجلات التحديث
```
/var/log/ngfw/update-YYYYMMDD-HHMMSS.log
```
