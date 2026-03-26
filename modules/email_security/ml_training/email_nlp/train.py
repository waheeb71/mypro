"""
Enterprise CyberNexus — Email Phishing NLP Training (Enron + Synthetic Spam)

Trains a 1D-CNN + BiLSTM model on email body text to detect phishing/spam.

Supported datasets:
- Enron Email Dataset (Kaggle: wcukierski/enron-email-dataset) — loaded as "clean"
- Synthetic spam generator — generated as "phishing"
"""

import os
import argparse
import random
import re
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset
from typing import List, Tuple

# Re-use the exact same model architecture built for WAF (1D-CNN + BiLSTM char-level)
# We just train it on different data and save it somewhere else.
try:
    from modules.waf.ml_training.waf_nlp.model import WAFNLPModel
except ImportError:
    print("Error: Could not import WAFNLPModel. Ensure Enterprise CyberNexus is in PYTHONPATH.")
    exit(1)

_DIR  = os.path.dirname(os.path.abspath(__file__))
_DATA = os.path.join(_DIR, "datasets")
_MODEL_OUTPUT = os.path.join(_DIR, "email_phishing_model.pt")
_CHECKPOINT_PATH = os.path.join(_DIR, "email_phishing_model_checkpoint.pt")


# ── Synthetic Spam Generator ────────────────────────

def generate_synthetic_spam(count: int) -> List[Tuple[str, int]]:
    """Generate synthetic spam emails to augment training."""
    patterns = [
        "Congratulations! You have won $1,000,000 in the {lottery}. Click here to claim your prize immediately.",
        "Your account at {bank} has been suspended due to unusual activity. Please verify your identity at {url}",
        "URGENT: Your {subs} subscription has expired. Renew now to avoid losing access: {url}",
        "Dear customer, your package from {delivery} could not be delivered. Pay shipping fees at {url}",
        "I am a prince from {country} and I need your help to transfer $50 million. Please reply with your bank details.",
        "Weight loss miracle! Lose 20 lbs in 1 week with {pill}. Buy now at {url}",
        "You've been selected for an exclusive offer. Act now before it expires! Link: {url}",
        "Final Warning: Your email password expires in 2 hours. Update it here: {url} or your account will be deleted.",
        "Invoice {num} is attached. Please review the payment details urgently.",
        "Earn $500/day working from home! No experience needed. Start today: {url}"
    ]
    
    banks = ["PayPal", "Bank of America", "Chase", "Wells Fargo", "Apple", "Microsoft"]
    lotteries = ["National Lottery", "Apple Promo", "Global Sweepstakes"]
    urls = ["http://bit.ly/xyz", "http://verify-account-update.com", "http://192.168.1.5/login"]
    subs = ["Netflix", "Amazon Prime", "McAfee Antivirus", "Norton"]
    delivery = ["DHL", "FedEx", "UPS", "USPS"]
    countries = ["Nigeria", "Dubai", "London", "South Africa"]
    pills = ["DietMax", "KetoBurn", "MiraclePill"]
    
    samples = []
    for _ in range(count):
        p = random.choice(patterns)
        text = p.format(
            bank=random.choice(banks), lottery=random.choice(lotteries),
            url=random.choice(urls), subs=random.choice(subs),
            delivery=random.choice(delivery), country=random.choice(countries),
            pill=random.choice(pills), num=random.randint(1000, 99999)
        )
        samples.append((text, 1)) # 1 = Phishing/Spam
    return samples


# ── Dataset Loaders ─────────────────────────────────

def load_enron_dataset(csv_path: str, max_samples: int = 20000) -> List[Tuple[str, int]]:
    """
    Extract body text from the Enron emails CSV ("message" column).
    Labels them as 0 (Clean).
    """
    print(f"Loading Enron dataset from {csv_path}...")
    try:
        df = pd.read_csv(csv_path)
        if "message" not in df.columns:
            print("Error: 'message' column not found in Enron dataset.")
            return []
            
        samples = []
        for msg in df["message"].dropna().head(max_samples):
            # Enron emails have headers included in the 'message' field.
            # We want to extract just the body to train the NLP model on content.
            parts = str(msg).split("\n\n", 1)
            body = parts[1] if len(parts) > 1 else parts[0]
            
            # Clean up body to remove excessive whitespace and signatures
            body = re.sub(r'\s+', ' ', body).strip()
            if len(body) > 20: # skip very, very short emails
                samples.append((body[:2000], 0)) # 0 = Clean
                
        print(f"Loaded {len(samples)} clean emails from Enron dataset.")
        return samples
    except Exception as e:
        print(f"Failed to load Enron dataset: {e}")
        return []

def load_malicious_phish(csv_path: str, max_samples: int = 50000) -> List[Tuple[str, int]]:
    """
    Extract URLs from the malicious_phish.csv dataset.
    Labels 'benign' as 0, and anything else ('phishing', 'malware', 'defacement') as 1.
    """
    print(f"Loading Malicious Phish dataset from {csv_path}...")
    try:
        df = pd.read_csv(csv_path)
        if "url" not in df.columns or "type" not in df.columns:
            print("Error: 'url' or 'type' column not found in Malicious Phish dataset.")
            return []
            
        samples = []
        for _, row in df.dropna().iterrows():
            url = str(row["url"]).strip()
            label_str = str(row["type"]).strip().lower()
            if not url:
                continue
                
            label = 0 if label_str == "benign" else 1
            if len(url) > 5:
                # Truncate extremely long URLs to fit within max_len to save memory
                samples.append((url[:2000], label))
                if len(samples) >= max_samples:
                    break
                
        print(f"Loaded {len(samples)} URLs from Malicious Phish dataset.")
        return samples
    except Exception as e:
        print(f"Failed to load Malicious Phish dataset: {e}")
        return []


class EmailDataset(Dataset):
    def __init__(self, data: List[Tuple[str, int]], max_len: int = 1000):
        self.data = data
        self.max_len = max_len
        # Valid chars used in WAFNLPModel
        self.vocab = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-,;.!?:'\"/\\|_@#$%^&*~`+-=<>()[]{} \n\r\t"
        self.char2idx = {c: i+1 for i, c in enumerate(self.vocab)}

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        text, label = self.data[idx]
        seq = [self.char2idx.get(c, 0) for c in text[:self.max_len]]
        if len(seq) < self.max_len:
            seq += [0] * (self.max_len - len(seq))
        return torch.tensor(seq, dtype=torch.long), torch.tensor(label, dtype=torch.float32)


# ── Training Loop ───────────────────────────────────

def train(epochs: int, batch_size: int, enron_path: str, resume: bool = False):
    os.makedirs(_DATA, exist_ok=True)
        
    print("=== Assembly Training Data ===")
    data = []
    
    # Load Enron (Clean)
    if os.path.exists(enron_path):
        enron_data = load_enron_dataset(enron_path, max_samples=25000)
        data.extend(enron_data)
    else:
        print(f"Warning: Enron dataset not found at {enron_path}.")
        print("Using synthetic clean data as fallback (not recommended for production).")
        data.extend([("Hey, are we still meeting tomorrow at 10 AM?", 0)] * 500)
        data.extend([("Please review the attached project proposal and let me know your thoughts.", 0)] * 500)
        data.extend([("The monthly report is ready for your approval.", 0)] * 500)
        
    # Load Malicious Phish URLs (Mixed Clean & Phishing)
    malicious_phish_path = os.path.join(_DATA, "malicious_phish.csv")
    if os.path.exists(malicious_phish_path):
        phish_data = load_malicious_phish(malicious_phish_path, max_samples=40000)
        data.extend(phish_data)
    else:
        print(f"Notice: Malicious Phish dataset not found at {malicious_phish_path}. Skipping.")
        
    # Generate Synthetic Phishing
    # To balance the dataset
    num_clean = len([x for x in data if x[1] == 0])
    num_phish = max(num_clean, 5000) # Match clean size or min 5000
    print(f"Generating {num_phish} synthetic phishing emails...")
    data.extend(generate_synthetic_spam(num_phish))
    
    random.shuffle(data)
    
    print(f"Total dataset size: {len(data)} emails")
    print("Class distribution:")
    print(f"  Clean (0)   : {sum(1 for _, l in data if l == 0)}")
    print(f"  Phishing (1): {sum(1 for _, l in data if l == 1)}")
    
    # Split train/val
    split_idx = int(len(data) * 0.8)
    train_data = data[:split_idx]
    val_data   = data[split_idx:]
    
    train_loader = DataLoader(EmailDataset(train_data), batch_size=batch_size, shuffle=True)
    val_loader   = DataLoader(EmailDataset(val_data), batch_size=batch_size)
    
    # Initialize Model (re-using WAF architecture)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Training on device: {device}")
    
    model = WAFNLPModel()
    
    # Overwrite the classifier head for binary classification (1 output logit)
    # The WAF model originally outputs 6 classes.
    model.classifier[-1] = nn.Linear(256, 1)
    
    model = model.to(device)
    criterion = nn.BCEWithLogitsLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    
    # --- Resume Logic ---
    start_epoch = 0
    if resume:
        if os.path.exists(_CHECKPOINT_PATH):
            print(f"--- Resuming from checkpoint: {_CHECKPOINT_PATH} ---")
            checkpoint = torch.load(_CHECKPOINT_PATH, map_location=device)
            model.load_state_dict(checkpoint)
        else:
            print(f"Warning: Checkpoint not found at {_CHECKPOINT_PATH}. Starting from scratch.")
    
    # Training Loop
    print("\n=== Starting Training ===")
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        correct = 0
        total = 0
        print(f"\n--- Epoch {epoch+1}/{epochs} ---")
        
        for i, (inputs, labels) in enumerate(train_loader):
            inputs, labels = inputs.to(device), labels.to(device)
            
            optimizer.zero_grad()
            outputs = model(inputs).squeeze(-1)
            loss = criterion(outputs, labels)
            
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            preds = (torch.sigmoid(outputs) > 0.5).float()
            correct += (preds == labels).sum().item()
            total += labels.size(0)
            
            if (i + 1) % 50 == 0 or (i + 1) == len(train_loader):
                batch_acc = correct / total
                print(f"  Batch {i+1:04d}/{len(train_loader)} | Loss: {loss.item():.4f} | Acc: {batch_acc*100:.2f}%")
            
            # --- Checkpointing Logic ---
            if (i + 1) % 250 == 0:
                print(f"  [Checkpoint] Saving periodic state to {_CHECKPOINT_PATH}...")
                torch.save(model.state_dict(), _CHECKPOINT_PATH)
                
        train_acc = correct / total
        
        # Validation
        print("  Evaluating Validation Set...")
        model.eval()
        val_loss = 0
        val_correct = 0
        val_total = 0
        
        with torch.no_grad():
            for i, (inputs, labels) in enumerate(val_loader):
                inputs, labels = inputs.to(device), labels.to(device)
                outputs = model(inputs).squeeze(-1)
                val_loss += criterion(outputs, labels).item()
                preds = (torch.sigmoid(outputs) > 0.5).float()
                val_correct += (preds == labels).sum().item()
                val_total += labels.size(0)
                
        val_acc = val_correct / val_total
        print(f"Epoch {epoch+1}/{epochs} - "
              f"Loss: {total_loss/len(train_loader):.4f} - Acc: {train_acc:.4f} - "
              f"Val Loss: {val_loss/len(val_loader):.4f} - Val Acc: {val_acc:.4f}")

    print(f"\nTraining Complete! Saving model to {_MODEL_OUTPUT}")
    torch.save(model.state_dict(), _MODEL_OUTPUT)
    print("Done. To enable NLP in Email Security, set 'phishing_detection.nlp_enabled: true' in config.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Email Phishing NLP Model")
    parser.add_argument("--epochs", type=int, default=10, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=64, help="Batch size")
    parser.add_argument("--enron-csv", type=str, default=os.path.join(_DATA, "emails.csv"), 
                        help="Path to Enron dataset CSV (kaggle: wcukierski/enron-email-dataset)")
    parser.add_argument("--resume", action="store_true", help="Resume training from last checkpoint")
    args = parser.parse_args()
    
    train(args.epochs, args.batch_size, args.enron_csv, args.resume)
