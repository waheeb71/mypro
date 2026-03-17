"""
Enterprise NGFW — WAF Graph Neural Network Model

Uses Graph Attention Network (GAT) to analyze session navigation graphs
and detect multi-step attack patterns that signature-based systems miss.

Architecture:
    GAT Layer 1 → GAT Layer 2 → Global Mean Pool → MLP → Binary Classifier

Dependencies:
    pip install torch torch-geometric

What it detects:
    - Lateral movement across endpoints
    - Sequential directory traversal / enumeration
    - API abuse (all requests target same endpoint class)
    - Account takeover (login failures → sensitive API calls)
    - Distributed bot coordination (similar graph patterns from different IPs)
"""

import os
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  PyTorch Geometric model
# ──────────────────────────────────────────────

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F

    try:
        from torch_geometric.nn import GATConv, global_mean_pool
        _TORCH_GEO_AVAILABLE = True
    except ImportError:
        _TORCH_GEO_AVAILABLE = False
        logger.warning("torch-geometric not installed — pip install torch-geometric")

    _TORCH_AVAILABLE = True

except ImportError:
    _TORCH_AVAILABLE = False
    logger.warning("PyTorch not installed — WAFGNNModel unavailable")


NODE_FEATURE_DIM = 7   # [visit_count, avg_code, GET, POST, PUT, DELETE, depth]


class WAFGNNModel(nn.Module if _TORCH_AVAILABLE else object):
    """
    Graph Attention Network (GAT) for session graph classification.

    Input:
        x:          Node feature matrix (num_nodes, NODE_FEATURE_DIM)
        edge_index: Graph connectivity (2, num_edges) — COO format
        batch:      Batch vector assigning each node to a graph

    Output:
        (num_graphs, 2) logits — [P(normal), P(attack)]
    """

    HIDDEN_DIM  = 64
    HEADS       = 4
    DROPOUT     = 0.3
    NUM_CLASSES = 2   # 0=normal, 1=attack

    def __init__(self):
        if not _TORCH_AVAILABLE:
            return
        super().__init__()

        if not _TORCH_GEO_AVAILABLE:
            # Fallback: simple MLP on node-level features (no graph structure)
            self.use_gat = False
            self.mlp = nn.Sequential(
                nn.Linear(NODE_FEATURE_DIM, self.HIDDEN_DIM),
                nn.ReLU(),
                nn.Dropout(self.DROPOUT),
                nn.Linear(self.HIDDEN_DIM, self.NUM_CLASSES),
            )
        else:
            self.use_gat = True
            self.gat1 = GATConv(NODE_FEATURE_DIM, self.HIDDEN_DIM,
                                 heads=self.HEADS, dropout=self.DROPOUT)
            self.gat2 = GATConv(self.HIDDEN_DIM * self.HEADS, self.HIDDEN_DIM,
                                 heads=1, dropout=self.DROPOUT)
            self.classifier = nn.Sequential(
                nn.Linear(self.HIDDEN_DIM, 32),
                nn.ReLU(),
                nn.Dropout(self.DROPOUT),
                nn.Linear(32, self.NUM_CLASSES),
            )

    def forward(self, x, edge_index, batch):
        if not _TORCH_AVAILABLE:
            raise RuntimeError("PyTorch not installed")

        if not self.use_gat:
            # fallback: pool node features then classify
            pooled = global_mean_pool(self.mlp(x), batch)
            return pooled

        # GAT forward pass
        h = F.elu(self.gat1(x, edge_index))
        h = F.dropout(h, p=self.DROPOUT, training=self.training)
        h = self.gat2(h, edge_index)
        pooled = global_mean_pool(h, batch)           # graph-level embedding
        return self.classifier(pooled)


# ──────────────────────────────────────────────
#  Inference wrapper
# ──────────────────────────────────────────────

class WAFGNNInference:
    """
    Inference wrapper for WAFGNNModel.

    Converts a SessionGraph into the tensor format expected by the model.

    Usage:
        gnn = WAFGNNInference(model_path='ml/models/waf/gnn_model.pt')
        score = gnn.predict(session_graph)
    """

    def __init__(self, model_path: Optional[str] = None):
        self._model = None

        if _TORCH_AVAILABLE and model_path and os.path.exists(model_path):
            self._load(model_path)

    def _load(self, path: str) -> None:
        import torch
        self._model = WAFGNNModel()
        self._model.load_state_dict(torch.load(path, map_location='cpu'))
        self._model.eval()
        logger.info("✅ WAFGNNModel loaded from %s", path)

    def predict(self, session_graph) -> float:
        """
        Predict the attack probability for a SessionGraph.

        Returns:
            float [0.0, 1.0] — probability of attack
        """
        if self._model is None or not _TORCH_AVAILABLE:
            return 0.0

        try:
            import torch
            import torch.nn.functional as F

            from .session_graph import SessionGraph
            graph: SessionGraph = session_graph

            if graph.num_nodes == 0:
                return 0.0

            # Build node feature tensor
            node_list = graph.node_ids
            feat_list = [graph.node_features.get(n, [0.0] * NODE_FEATURE_DIM)
                         for n in node_list]
            x = torch.tensor(feat_list, dtype=torch.float)

            # Build edge index tensor
            node_idx = {n: i for i, n in enumerate(node_list)}
            src_list, dst_list = [], []
            for (frm, to, *_) in graph.edges:
                if frm in node_idx and to in node_idx:
                    src_list.append(node_idx[frm])
                    dst_list.append(node_idx[to])

            if src_list:
                edge_index = torch.tensor([src_list, dst_list], dtype=torch.long)
            else:
                edge_index = torch.zeros((2, 0), dtype=torch.long)

            batch = torch.zeros(graph.num_nodes, dtype=torch.long)

            with torch.no_grad():
                logits = self._model(x, edge_index, batch)     # (1, 2)
                probs  = F.softmax(logits, dim=-1)[0]
                attack_prob = probs[1].item()

            return float(attack_prob)

        except Exception as e:
            logger.error("WAFGNNInference.predict error: %s", e)
            return 0.0

    def is_loaded(self) -> bool:
        return self._model is not None
