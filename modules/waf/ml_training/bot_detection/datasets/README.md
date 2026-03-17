# Datasets Directory — WAF NLP Training

Place your training datasets here before running `train.py`.

## Required Datasets

### 1. Kaggle Malicious URLs Dataset
- **File**: `malicious_urls.csv`
- **Download**: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
- **Columns**: `url` (str), `type` (benign/defacement/phishing/malware)
- **Size**: ~650,000 rows

### 2. CSIC 2010 HTTP Dataset
- **File**: `csic_http.csv`
- **Download**: http://www.isi.csic.es/dataset/
- **Columns**: `payload` (str), `label` (int 0-5)
- **Size**: ~36,000 rows
- **Labels**: 0=benign, 1=sqli, 2=xss, 3=lfi, 4=cmd_injection

## Training without datasets
If datasets are not yet available, `train.py` automatically generates
5,000 synthetic samples to bootstrap model training.

Run:
```
python -m ml.training.waf_nlp.train --epochs 10
```
