# 🛡️ AI-Powered WAF Module — Enterprise CyberNexus

نظام جدار حماية تطبيقات الويب (WAF) مدعوم بالذكاء الاصطناعي، مصمم لاكتشاف الهجمات المعقدة والبوتات وتجاوزات الـ WAF التقليدية.

## 🏗️ الهندسة المعمارية (10 لافحات دفاعية)

يعمل المحرك بنظام خط أنابيب (Pipeline) يمر عبر المستويات التالية:

1.  **Honeypot Layer**: كشف فوري للمسح (Scanning) عبر 40+ مسار وهمي.
2.  **Preprocessing Engine**: فك تشفير متعدد (URL, Base64, Hex, HTML, Unicode) لتجاوز تقنيات الـ Obfuscation.
3.  **Feature Extractor**: استخراج 10 مؤشرات رقمية (مثل Entropy و Keyword Density).
4.  **NLP Model**: نموذج 1D-CNN + BiLSTM لتحليل عميق للـ HTTP Payload واكتشاف هجمات الحقن.
5.  **Bot Detector**: نموذج XGBoost لتصنيف الزوار (بشر، Headless Browser، Scraper، Scanner).
6.  **GNN Model**: تحليل تسلسل الطلبات (Session) لاكتشاف التحركات المريبة (Lateral Movement).
7.  **Anomaly Detection**: تحليل إحصائي وسلوكي للطلبات غير الاعتيادية.
8.  **Threat Intelligence**: تكامل مع AbuseIPDB, Spamhaus, OTX, و Feodo Tracker.
9.  **Risk Scoring Engine**: تجميع نتائج جميع النماذج في درجة خطر موحدة (0.0 - 1.0).
10. **Policy Enforcer**: اتخاذ قرار الحجب (ALLOW, CHALLENGE, BLOCK) بناءً على الإعدادات.

---

## 📂 هيكل الملفات

```text
inspection/plugins/
├── waf_inspector.py          # المحرك الرئيسي (Orchestrator)
└── waf/
    ├── __init__.py           # تعريف المداخل (Exports)
    ├── settings.py           # مدير الإعدادات (YAML Loader)
    ├── preprocessor.py       # محرك تنظيف البيانات وصقلها
    ├── feature_extractor.py  # محرك استخراج الميزات للـ ML
    ├── honeypot.py           # الفخاخ والمصايد الرقمية
    └── risk_engine.py        # محرك اتخاذ القرار الرياضي
```

---

## ⚙️ الإعدادات (Configuration)

يتم التحكم في كل ميزة عبر ملفات YAML:
-   **الافتراضي**: `config/defaults/waf.yaml` (يحتوي على الأوزان والعتبات).
-   **المحلي**: `config/waf.local.yaml` (لوضع الـ API Keys والإعدادات الخاصة).

### تفعيل/تعطيل الميزات:
يمكنك إيقاف أي طبقة برمجياً أو عبر الإعدادات:
```yaml
waf:
  enabled: true
  nlp_model:
    enabled: true
  bot_detection:
    enabled: true
```

---

## 🚀 كيفية الاستخدام والتشغيل

### 1. تدريب النماذج
النماذج تأتي بدعم للبيانات الـ Synthetic للبدء الفوري:
```bash
# تدريب نموذج NLP
python -m ml.training.waf_nlp.train --epochs 20

# تدريب مستكشف البوتات
python -m ml.training.bot_detection.train
```

### 2. إضافة مفاتيح API
افتح `config/waf.local.yaml` وضع مفتاحك:
```yaml
waf:
  threat_intelligence:
    abuseipdb:
      api_key: "XXXXXX"
```

### 3. المراقبة (Shadow Mode)
إذا كنت لا تريد الحجب الفوري وتريد فقط تجربة النظام، غيّر الوضع إلى `monitor`:
```yaml
waf:
  mode: monitor
```

---

## 🛠️ التطوير والتحسين المستمر (Self-Learning)
يحتوي النظام على `Self-Learning Engine` يقوم بتسجيل الهجمات المحظورة في قاعدة بيانات `waf_training_data` مما يسمح بإعادة تدريب النماذج أسبوعياً لتحسين الدقة وتقليل الـ False Positives.
