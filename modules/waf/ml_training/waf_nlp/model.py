"""
Enterprise CyberNexus — WAF NLP Model
Architecture: Char-level 1D-CNN + BiLSTM

Why char-level?
  Attackers obfuscate word boundaries (e.g., UN/**/ION, %55NION).
  Character-level tokenization sees past these tricks after Preprocessing.

Model pipeline:
  Input (char sequence) → Embedding → 1D-CNN → BiLSTM → Dense → Sigmoid

Classes:
  0 = benign
  1 = sqli
  2 = xss
  3 = lfi_path_traversal
  4 = command_injection
  5 = phishing_url

Dependencies:
  pip install torch  (or tensorflow — see comments)
"""

import os
import logging
from typing import Optional, List, Tuple

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  Tokenizer (Char-level)
# ──────────────────────────────────────────────

class CharTokenizer:
    """
    Character-level tokenizer.
    Maps each character to an integer index.
    Unknown chars map to index 1 (<UNK>).
    Padding index = 0.
    """

    PAD   = 0
    UNK   = 1
    VOCAB_SIZE = 256       # ASCII range (safe for HTTP payloads)
    MAX_LEN    = 512       # truncate/pad to this length

    def encode(self, text: str) -> List[int]:
        """Encode a string to a list of integer token IDs."""
        indices = [min(ord(c), 255) + 2 for c in text[:self.MAX_LEN]]
        # Pad to MAX_LEN
        indices += [self.PAD] * (self.MAX_LEN - len(indices))
        return indices

    def batch_encode(self, texts: List[str]) -> List[List[int]]:
        return [self.encode(t) for t in texts]


# ──────────────────────────────────────────────
#  PyTorch Model Definition
# ──────────────────────────────────────────────

try:
    import torch
    import torch.nn as nn

    class WAFNLPModel(nn.Module):
        """
        1D-CNN + BiLSTM classifier for HTTP payload attack detection.

        Input:  (batch, seq_len) — integer token IDs
        Output: (batch, num_classes) — logits
        """

        NUM_CLASSES    = 6      # benign + 5 attack types
        EMBED_DIM      = 64
        CNN_FILTERS    = 128
        CNN_KERNEL     = 3
        LSTM_HIDDEN    = 128
        LSTM_LAYERS    = 2
        DROPOUT        = 0.3

        def __init__(self, vocab_size: int = CharTokenizer.VOCAB_SIZE + 2):
            super().__init__()

            # ── Embedding ──────────────────────
            self.embedding = nn.Embedding(
                num_embeddings = vocab_size,
                embedding_dim  = self.EMBED_DIM,
                padding_idx    = CharTokenizer.PAD,
            )

            # ── 1D-CNN: extract local n-gram features ──
            self.cnn = nn.Sequential(
                nn.Conv1d(self.EMBED_DIM, self.CNN_FILTERS, self.CNN_KERNEL, padding=1),
                nn.ReLU(),
                nn.Conv1d(self.CNN_FILTERS, self.CNN_FILTERS, self.CNN_KERNEL, padding=1),
                nn.ReLU(),
                nn.MaxPool1d(kernel_size=2, stride=2),
                nn.Dropout(self.DROPOUT),
            )

            # ── BiLSTM: understand sequence context ──
            self.bilstm = nn.LSTM(
                input_size    = self.CNN_FILTERS,
                hidden_size   = self.LSTM_HIDDEN,
                num_layers    = self.LSTM_LAYERS,
                batch_first   = True,
                bidirectional = True,
                dropout       = self.DROPOUT if self.LSTM_LAYERS > 1 else 0.0,
            )

            # ── Classifier head ────────────────
            self.classifier = nn.Sequential(
                nn.Linear(self.LSTM_HIDDEN * 2, 256),   # * 2 for bi-directional
                nn.ReLU(),
                nn.Dropout(self.DROPOUT),
                nn.Linear(256, self.NUM_CLASSES),
            )

        def forward(self, x: 'torch.Tensor') -> 'torch.Tensor':
            # x: (batch, seq_len)
            emb = self.embedding(x)                  # (batch, seq, embed)
            emb = emb.permute(0, 2, 1)               # (batch, embed, seq) for Conv1d
            cnn_out = self.cnn(emb)                  # (batch, filters, seq/2)
            cnn_out = cnn_out.permute(0, 2, 1)       # (batch, seq/2, filters) for LSTM

            lstm_out, _ = self.bilstm(cnn_out)       # (batch, seq/2, hidden*2)
            # Global average pooling over time
            pooled = lstm_out.mean(dim=1)             # (batch, hidden*2)
            logits = self.classifier(pooled)          # (batch, num_classes)
            return logits

    TORCH_AVAILABLE = True

except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not installed — WAFNLPModel unavailable. Run: pip install torch")


# ──────────────────────────────────────────────
#  Inference wrapper
# ──────────────────────────────────────────────

ATTACK_LABELS = [
    "benign",
    "sqli",
    "xss",
    "lfi_path_traversal",
    "command_injection",
    "phishing_url",
]


class WAFNLPInference:
    """
    Inference wrapper for WAFNLPModel.

    Usage:
        model = WAFNLPInference(model_path="ml/models/waf/waf_nlp_model.pt")
        score, label = model.predict("UNION SELECT * FROM users")
    """

    def __init__(self, model_path: Optional[str] = None):
        self.tokenizer = CharTokenizer()
        self._model   = None
        self._device  = "cpu"

        if TORCH_AVAILABLE and model_path and os.path.exists(model_path):
            self._load(model_path)

    def _load(self, path: str) -> None:
        import torch
        self._model = WAFNLPModel()
        self._model.load_state_dict(torch.load(path, map_location=self._device))
        self._model.eval()
        logger.info("✅ WAFNLPModel loaded from %s", path)

    def predict(self, text: str) -> Tuple[float, str]:
        """
        Predict attack probability for a payload.

        Returns:
            (attack_score, label)
            attack_score: 0.0–1.0 (1 = definite attack)
            label: one of ATTACK_LABELS
        """
        if self._model is None:
            # Model not loaded — return neutral score
            logger.debug("WAFNLPInference: model not loaded, returning 0.0")
            return 0.0, "benign"

        import torch
        import torch.nn.functional as F

        tokens = torch.tensor([self.tokenizer.encode(text)], dtype=torch.long)
        with torch.no_grad():
            logits = self._model(tokens)              # (1, num_classes)
            probs  = F.softmax(logits, dim=-1)[0]     # (num_classes,)

        benign_prob = probs[0].item()
        attack_score = 1.0 - benign_prob
        best_class   = probs.argmax().item()
        label        = ATTACK_LABELS[best_class]

        return attack_score, label
