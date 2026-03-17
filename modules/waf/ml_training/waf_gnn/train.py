"""
Enterprise NGFW — GNN Training Script

Trains the Graph Attention Network (GAT) on synthetic session graphs.

Usage:
    python -m ml.training.waf_gnn.train \
        --logs  datasets/session_logs.csv \
        --epochs 30 \
        --output ml/models/waf/gnn_model.pt

Expected CSV columns (session log):
    session_id, src_ip, timestamp, path, method, response_code

The script builds SessionGraphs from the logs and trains the GAT model.
"""

import argparse
import logging
import os
import random
from typing import List, Tuple

logger = logging.getLogger(__name__)

from .session_graph import SessionGraphBuilder, HTTPRequest, SessionGraph


# ──────────────────────────────────────────────
#  Synthetic session generator
# ──────────────────────────────────────────────

import time as _time


def generate_synthetic_sessions(n_sessions: int = 500) -> List[Tuple[SessionGraph, int]]:
    """Generate synthetic normal and attack sessions for training."""
    sessions = []

    # Normal browsing sessions
    normal_paths = ["/", "/home", "/products", "/products/123", "/about",
                    "/contact", "/cart", "/checkout", "/account"]
    for i in range(n_sessions // 2):
        builder = SessionGraphBuilder(f"normal_{i}", f"10.0.{i%256}.{i%100}")
        t = _time.time()
        pages = random.sample(normal_paths, random.randint(2, 6))
        for page in pages:
            t += random.uniform(2, 30)   # realistic human timing
            builder.add_request(HTTPRequest(
                timestamp=t, src_ip=builder.src_ip, path=page,
                method="GET", response_code=200,
            ))
        sessions.append((builder.build(), 0))  # label=0 normal

    # Attack sessions (scanning / lateral movement)
    scan_paths = [f"/{word}" for word in [
        "admin", "login", ".env", "config.php", "api/users", "api/admin",
        "backup.sql", "phpmyadmin", "wp-login.php", "debug", "shell.php",
        "api/v1/users", "api/v1/admin", "api/v2/internal", "api/export",
    ]]
    for i in range(n_sessions // 2):
        builder = SessionGraphBuilder(f"attack_{i}", f"192.168.{i%256}.{i%100}")
        t = _time.time()
        # Rapid sequential scanning
        for path in random.sample(scan_paths, random.randint(5, 12)):
            t += random.uniform(0.05, 0.3)   # very fast — bot-like
            code = random.choice([200, 403, 404, 500])
            builder.add_request(HTTPRequest(
                timestamp=t, src_ip=builder.src_ip, path=path,
                method="GET", response_code=code,
            ))
        sessions.append((builder.build(), 1))  # label=1 attack

    random.shuffle(sessions)
    logger.info("Synthetic: %d sessions (%d normal, %d attack)",
                len(sessions), n_sessions // 2, n_sessions // 2)
    return sessions


# ──────────────────────────────────────────────
#  Training
# ──────────────────────────────────────────────

def train(
    sessions:    List[Tuple[SessionGraph, int]],
    output_path: str,
    epochs:      int = 30,
    lr:          float = 1e-3,
    val_split:   float = 0.1,
) -> None:
    try:
        import torch
        import torch.nn.functional as F
        from torch.optim import Adam
    except ImportError:
        logger.error("PyTorch required: pip install torch")
        return

    try:
        from torch_geometric.data import Data, DataLoader as GeoDataLoader
    except ImportError:
        logger.error("torch-geometric required: pip install torch-geometric")
        return

    from .model import WAFGNNModel, NODE_FEATURE_DIM

    # ── Convert SessionGraphs to PyG Data objects ──
    data_list = []
    for graph, label in sessions:
        if graph.num_nodes < 2:
            continue

        node_list = graph.node_ids
        node_idx  = {n: i for i, n in enumerate(node_list)}

        # Node feature matrix
        feat_rows = []
        for n in node_list:
            row = graph.node_features.get(n, [0.0] * NODE_FEATURE_DIM)
            # Ensure exact feature dim
            row = (row + [0.0] * NODE_FEATURE_DIM)[:NODE_FEATURE_DIM]
            feat_rows.append(row)
        x = torch.tensor(feat_rows, dtype=torch.float)

        # Edge index
        src_list, dst_list = [], []
        for (frm, to, *_) in graph.edges:
            if frm in node_idx and to in node_idx:
                src_list.append(node_idx[frm])
                dst_list.append(node_idx[to])
        if not src_list:
            continue
        edge_index = torch.tensor([src_list, dst_list], dtype=torch.long)

        data_list.append(Data(x=x, edge_index=edge_index,
                              y=torch.tensor([label], dtype=torch.long)))

    if not data_list:
        logger.error("No valid graphs to train on")
        return

    # ── Split ──────────────────────────────────
    n_val = max(1, int(len(data_list) * val_split))
    val_data   = data_list[:n_val]
    train_data = data_list[n_val:]

    train_loader = GeoDataLoader(train_data, batch_size=32, shuffle=True)
    val_loader   = GeoDataLoader(val_data,   batch_size=32)

    # ── Model ──────────────────────────────────
    model     = WAFGNNModel()
    optimizer = Adam(model.parameters(), lr=lr)
    criterion = torch.nn.CrossEntropyLoss()

    logger.info("Training WAFGNNModel for %d epochs on %d graphs…", epochs, len(train_data))

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        for batch in train_loader:
            optimizer.zero_grad()
            out  = model(batch.x, batch.edge_index, batch.batch)
            loss = criterion(out, batch.y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        # Validation
        model.eval()
        correct = total = 0
        with torch.no_grad():
            for batch in val_loader:
                preds   = model(batch.x, batch.edge_index, batch.batch).argmax(dim=-1)
                correct += (preds == batch.y).sum().item()
                total   += len(batch.y)

        logger.info("Epoch %3d/%d  loss=%.4f  val_acc=%.1f%%",
                    epoch, epochs, total_loss / len(train_loader),
                    correct / max(total, 1) * 100)

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    torch.save(model.state_dict(), output_path)
    logger.info("✅ GNN model saved → %s", output_path)


# ──────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    parser = argparse.ArgumentParser(description="Train WAF GNN Model")
    parser.add_argument('--logs',   default=None, help='Session logs CSV')
    parser.add_argument('--n',      type=int, default=500, help='Synthetic sessions')
    parser.add_argument('--epochs', type=int, default=30)
    parser.add_argument('--output', default='ml/models/waf/gnn_model.pt')
    args = parser.parse_args()

    sessions = generate_synthetic_sessions(args.n)
    train(sessions, args.output, epochs=args.epochs)


if __name__ == '__main__':
    main()
