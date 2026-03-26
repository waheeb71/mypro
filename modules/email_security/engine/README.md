# 📧 AI-Powered Email Security Module — Enterprise CyberNexus

نظام فحص أمان البريد الإلكتروني المدعوم بالذكاء الاصطناعي والاستخبارات المتقدمة. 
يراقب هذا النظام بروتوكولات البريد (SMTP, IMAP, POP3) ويحلل الرسائل لحظر التصيد (Phishing)، المرفقات الخبيثة، الروابط الخطرة، والـ Spam قبل وصولها للمستخدم.
---

## 🏗️ الهندسة المعمارية (7 طبقات دفاعية)

يعمل المحرك (`inspection/plugins/email_inspector.py`) عبر خط سير (Pipeline) من 7 طبقات:

1.  **Email Preprocessor**: فك تشفير البيانات (MIME, Base64)، استخراج الروابط، وتحليل المرفقات.
2.  **Phishing Detector**: كشف انتحال العلامات التجارية، واستخراج علامات "الاستعجال" (Urgency)، معدعم بنموذج ذكاء اصطناعي (1D-CNN + BiLSTM).
3.  **URL Scanner**: فحص الروابط وكشف نطاقات الاختصار المستترة والنطاقات ذات السمعة السيئة بالتكامل مع `ThreatIntelCache`.
4.  **Attachment Guard**: حظر المرفقات من خلال الامتداد والخوارزمية الرياضية لمعرفة العشوائية (Shannon Entropy) لكشف الـ Ransomware المشفر.
5.  **Sender Reputation**: التحقق من سجلات DNS للبريد الوارد (SPF, DKIM, DMARC) وسمعة الـ IP الوارد واكتشاف نطاقات البريد المؤقت (Disposable Email).
6.  **Spam Filter**: التصفية المعتمدة على كثافة الكلمات الإعلانية العربية والإنجليزية، والأحرف الكبيرة (ALL CAPS).
7.  **Risk Scoring Engine**: محرك القرار الذي يجمع كل الدرجات السابقة لاتخاذ قرار من ثلاثة (ALLOW, QUARANTINE, BLOCK).

---

## 📂 هيكل الملفات

```text
inspection/plugins/
├── email_inspector.py          # المحرك الرئيسي (Orchestrator) 
└── email/
    ├── __init__.py           
    ├── settings.py             # مدير الإعدادات الخاصة بالإيميل (YAML Loader)
    ├── preprocessor.py         # محرك فك الترميز وتقطيع الإيميل
    ├── phishing_detector.py    # كشف التصيد المدعوم بالـ AI 
    ├── url_scanner.py          # فاحص الروابط واستخراجها
    ├── attachment_guard.py     # درع المرفقات (فحص الحجم والامتداد والانتروبي)
    ├── sender_reputation.py    # التحقق من مصداقية المرسل (SPF, DKIM, DMARC)
    ├── spam_filter.py          # محرك اكتشاف الرسائل المزعجة
    └── risk_engine.py          # محرك القرار ووزن المخاطر (Weights)
```
بالإضافة لقسم التدريب:
```text
ml/training/
└── email_nlp/
    ├── datasets/               # ضع Enron CSV هنا
    ├── train.py                # ملف تدريب الذكاء الاصطناعي 
    └── email_phishing_model.pt # النموذج المحفوظ بعد التدريب
```

---

## ⚙️ الإعدادات (Configuration)

يتم التحكم في كل ميزة ونسب القرار عبر ملفات YAML، مما يسمح بتعديل سلوك النظام دون المساس بالكود:
-   **الافتراضي**: `config/defaults/email.yaml` (التحكم بالتشغيل والأوزان).
-   **المحلي**: `config/email.local.yaml` (وضع القوائم البيضاء والمفاتيح للمرور الداخلي).

### مثال تفعيل وضع المراقبة (Shadow Mode):
لاختبار النظام في بيئة الإنتاج دون منع إيميلات الموظفين، افتح `config/email.local.yaml`:
```yaml
email_security:
  mode: monitor
```
سيقوم النظام بتسجيل التحذيرات لكن سيسمح للإيميلات بالمرور.

---

## 🚀 كيفية تشغيل نموذج الـ AI

للحصول على دقة عالية في كشف التصيد (Phishing)، يجب عليك تدريب النموذج باستخدام قاعدة بيانات **Enron** (رسائل سليمة) ليقوم السكريبت بدمجها مع رسائل احتيالية مُولدة:

1.  **تحميل البيانات**: حمّل قاعدة بيانات [Enron من Kaggle](https://www.kaggle.com/datasets/wcukierski/enron-email-dataset) وفك الضغط لينتج ملف `emails.csv`.
2.  **نقل الملف**: ضع `emails.csv` داخل المجلد:
    `ml/training/email_nlp/datasets/emails.csv`
3.  **بدء التدريب**:
    ```bash
    python -m ml.training.email_nlp.train --epochs 10
    ```
4.  **تفعيل النموذج**: افتح `config/defaults/email.yaml` وعدّل الإعداد التالي:
    ```yaml
    phishing_detection:
      nlp_enabled: true
    ```
الآن، أي إيميل يصل سيتم تحويل نصه إلى مصفوفة (Tensors) وفحصه عبر الـ `WAFNLPModel` الخاص بالإيميلات!

---

## 🔑 مفاتيح API والحماية المشتركة (Threat Intelligence)

بما أننا أضفنا `threat_intel.py` مسبقاً للـ WAF، فإن محرك الإيميل سيستعمل نفس ذاكرة الكاش (Cache) للتأكد من سمعة نطاقات الإيميلات والروابط. لذلك، أي مفتاح OTX أو AbuseIPDB تضعه في `waf.local.yaml` سيعمل تلقائياً لخدمة الإيميلات هنا.
