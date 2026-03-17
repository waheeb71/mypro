# 🛡️ Enterprise NGFW (Next-Generation Firewall) 🚀

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![Status](https://img.shields.io/badge/status-Enterprise%20Ready-success)
![AI Layer](https://img.shields.io/badge/AI_Defense-7_Layers-blueviolet)

نظام أمان شبكات مؤسسي متكامل ومتقدم (Enterprise NGFW) مبني بلغة Python. تم تصميمه من الصفر لينافس حلول جدران الحماية الرائدة عبر دمج **7 طبقات من الذكاء الاصطناعي**، نظام فحص ذكي للبيانات (DLP/WAF)، توجيه حركة المرور، وفلترة eBPF، مع دعم كامل للـ High Availability.

---

## 🔥 الميزات المؤسسية (Enterprise Features)

### 1. 🧠 بنية الذكاء الاصطناعي السباعية (7-Layer AI Architecture)
النظام ليس مجرد جدار حماية تقليدي يعتمد على القواعد (Rule-based)، بل هو نظام دفاعي استباقي متكامل:
*   **Layer 1/2**: Deep Learning (CNN/LSTM) لتحليل حركة المرور وكشف الهجمات غير المعروفة.
*   **Layer 3**: User Behavior Analytics (UBA) لاكتشاف السلوك الشاذ للموظفين والمستخدمين.
*   **Layer 4**: Threat Intelligence لربط الـ IPs والـ Hashes بقواعد بيانات التهديدات العالمية.
*   **Layer 5**: Adaptive Policy Engine باستخدام الـ Reinforcement Learning (DQN) لضبط حساسية الحظر آلياً.
*   **Layer 6**: Predictive Analytics للتنبؤ بالهجمات المستقبلية وتحليل مسارات ثغرات الشبكة.
*   **Layer 7**: Autonomous Response (Mitigation Orchestrator) للقيام بعزل الأجهزة أو فرض MFA بشكل آلي دون تدخل بشري.

### 2. 🛡️ التفتيش العميق للحزم (Deep Packet Inspection)
*   **SSL/TLS Inspection**: فتح وتفتيش حركة مرور HTTPS المشفرة وتوليد الشهادات ديناميكياً مع دعم TLS 1.3 & SNI Routing.
*   **Data Loss Prevention (DLP)**: فحص البيانات الصادرة لمنع تسرب أرقام البطاقات الائتمانية والاعترافات السرية.
*   **Web Application Firewall (WAF)**: فحص البيانات الواردة لمنع هجمات (OWASP Top 10) مثل SQLi و XSS.
*   **Protocol Analysis**: دعم تحليل بروتوكولات HTTP, DNS, و SMTP بشكل أصلي.

### 3. 🌐 إدارة الشبكات المتقدمة (Network Management)
*   **Multi-Proxy Modes**: دعم (Transparent, Forward, Reverse) Proxy لتغطية كافة سيناريوهات نشر جدار الحماية.
*   **Smart Traffic Router**: توجيه ذكي للحزم وإحصائيات دقيقة لكل اتصال (Flow Tracker).
*   **Traffic Shaping (QoS)**: تحديد والتحكم بسرعة الإنترنت للمستخدمين وتخصيص باقات Bandwidth باستخدام خوارزمية Token Bucket.
*   **WireGuard VPN**: دمج آمن لشبكات الفروع والموظفين عن بعد (Site-to-Site & Remote Access).
*   **eBPF Acceleration (XDP)**: إسقاط الحزم الخبيثة في مستوى نواة النظام (Kernel) بسرعة هائلة جداً قبل وصولها لطبقة التطبيقات (User Space).

### 4. 🔄 التوافر العالي والتقارير (HA & Dashboard)
*   **Active-Passive Clustering**: دعم خادمين (Master و Backup). في حال سقوط الـ Master، يقوم الـ Backup بالاستلام فوراً بدون قطع الاتصالات.
*   **State Sync**: تزامن لحظي للملفات والـ Connections Database بين الخوادم.
*   **Modern Dashboard**: واجهة تحكم ولوحة بيانات متقدمة (Glassmorphism Dark Theme) تعرض الهجمات وتوقعات الذكاء الاصطناعي بالوقت الحقيقي.

---

## 📦 التثبيت (Installation)

1. **نسخ المستودع وتثبيت البيئة الوهمية:**
   ```bash
   git clone https://github.com/your-org/enterprise-ngfw.git
   cd enterprise-ngfw
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements/base.txt
   ```

2. **تهيئة قاعدة البيانات (Migrations):**
   ```bash
   alembic upgrade head
   ```

3. **إعدادات جدار الحماية:**
   قم بنسخ الإعدادات الافتراضية والتعديل عليها:
   ```bash
   mkdir -p /etc/ngfw/certs
   cp config/defaults/base.yaml /etc/ngfw/config.yaml
   ```

4. **توليد شهادة الجذر (CA) لفحص HTTPS:**
   ```bash
   python main.py --init-ca -c /etc/ngfw/config.yaml
   ```

---

## 🚀 التشغيل (Running the NGFW)

بمجرد الانتهاء من الإعداد، يمكنك تشغيل الجدار الناري كالتالي:

```bash
# تشغيل بوضع الـ Root (مطلوب لخصائص eBPF والعمل على المنافذ < 1024)
sudo python main.py -c /etc/ngfw/config.yaml
```

**ملاحظة:** تأكد من استخراج شهادة الـ Root CA وتثبيتها على أجهزة العملاء لضمان عمل الـ SSL Inspection بدون رسائل خطأ في المتصفح:
```bash
python main.py --export-ca /tmp/root-ca.crt -c /etc/ngfw/config.yaml
```

---

## 📖 الوثائق (Documentation)
للفهم الواسع لبنية النظام وطريقة تواصل مكوناته، راجع ملف معماريّة النظام المعمق:
👉 **[ARCHITECTURE.md](./ARCHITECTURE.md)**

---

**مطور النظام**: إنجاز حصري لفرق أمن المعلومات والمقرات المتقدمة.
