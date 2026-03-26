npm install globe.gl d3 deck.gl "@deck.gl/layers" "@deck.gl/core" recharts "@tanstack/react-query" axios lucide-react framer-motion three

npm install react-router-dom zustand




# 🛡️ تقرير تقنيات واجهات Enterprise CyberNexus

> هدف واحد: واجهة تشبه مراكز العمليات الأمنية (SOC) الاحترافية — على غرار Palantir وDarktrace وCrowdStrike Falcon.

---

## 🗺️ ما تحتاجه وموضعه في المشروع

| القسم | التقنية | الغرض |
|---|---|---|
| خريطة الهجمات | Globe.gl + deck.gl | الكرة الأرضية الحية  |
| رسوم بيانية | D3.js | Network Graph, Timeline |
| مراقبة النظام | Grafana | CPU, Memory, Connections |
| تحليل السجلات | Kibana | البحث في logs |

---

## 1️⃣ Globe.gl — الأسهل والأبرز تأثيراً

**15 سطر تعطيك كرة أرضية احترافية: تعرض البيانات منين الي اين رايحة والعادي والهجوم**

```javascript
import Globe from 'globe.gl';

const globe = Globe()(document.getElementById('globe'));
globe
  .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
  .arcColor(() => '#ff4444')
  .arcsData(attacks)
  .arcStartLat(d => d.src_lat)
  .arcEndLat(d => d.dst_lat);
```

> لا تحتاج Three.js مباشرة — Globe.gl مبنية عليها.

---

## 2️⃣ deck.gl — عند كثرة البيانات

```javascript
import {ScatterplotLayer} from '@deck.gl/layers';

const layer = new ScatterplotLayer({
  data: blockedIPs,
  getPosition: d => [d.longitude, d.latitude],
  getFillColor: d => d.threat_level > 0.8 ? [255, 0, 0] : [255, 165, 0],
  getRadius: d => d.severity * 1000,
});
```

**متى تستخدمه:** صفحة Threat Intelligence عند عرض آلاف النقاط.

---

## 3️⃣ D3.js — الرسوم البيانية المتقدمة

```javascript
// Network Graph — يعرض العلاقة بين IPs
d3.forceSimulation(nodes)
  .force("link", d3.forceLink(links).id(d => d.id))
  .force("charge", d3.forceManyBody().strength(-200))
  .force("center", d3.forceCenter(width/2, height/2));
```

**متى تستخدمه:** صفحة Flow Analysis، Timeline الهجمات.

---

## 4️⃣ Grafana — المراقبة الحية

يتصل مباشرة بـ `/api/v1/metrics` في مشروعك.

```yaml
# docker-compose.yaml
grafana:
  image: grafana/grafana
  ports: ["3000:3000"]

prometheus:
  image: prom/prometheus
  volumes:
    - ./prometheus.yml:/etc/prometheus/prometheus.yml
```

**DataSource:** `http://CyberNexus-server:8000/metrics` (Type: Prometheus)

---

## 5️⃣ Kibana — تحليل السجلات

مشروعك يدعم إرسال السجلات لـ Elasticsearch عبر [core/events/unified_sink.py](file:///M:/%D9%86%D8%B3%D8%AE%20%D8%A7%D9%84%D9%85%D8%B4%D8%B1%D9%88%D8%B9/enterprise_CyberNexus/core/events/unified_sink.py).

```yaml
elasticsearch:
  image: elasticsearch:8.x
kibana:
  image: kibana:8.x
  ports: ["5601:5601"]
```

---

## 🗓️ خطة التنفيذ (5 أيام)

| اليوم | المهمة |
|---|---|
| 1 | Dashboard React + Globe.gl على الصفحة الرئيسية |
| 2 | ربط API + عرض الهجمات الحية على الكرة |
| 3 | D3.js للرسوم + صفحة Firewall Rules |
| 4 | Grafana + Prometheus عبر Docker |
| 5 | Kibana + Elasticsearch عبر Docker |

---

## ✅ مكتبات [package.json](file:///M:/%D9%86%D8%B3%D8%AE%20%D8%A7%D9%84%D9%85%D8%B4%D8%B1%D9%88%D8%B9/enterprise_CyberNexus/web-ui/package.json)

```json
{
  "dependencies": {
    "globe.gl": "^2.x",
    "deck.gl": "^8.x",
    "d3": "^7.x",
    "recharts": "^2.x",
    "react-query": "^5.x"
  }
}
```

