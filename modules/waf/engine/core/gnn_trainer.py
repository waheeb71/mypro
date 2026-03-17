"""
Enterprise NGFW — GNN Background Training Job

Provides a thread-safe background training job for the WAF GNN model.
Runs without interrupting live traffic inspection.

Usage (via API):
    trainer = GNNTrainingJob(
        logs_path="datasets/session_logs.csv",
        output_dir="ml_training/waf_gnn",
        epochs=30,
    )
    trainer.start()
    status = trainer.status()
"""

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  State
# ──────────────────────────────────────────────

class TrainingState(str, Enum):
    IDLE      = "idle"
    RUNNING   = "running"
    SUCCESS   = "success"
    FAILED    = "failed"


@dataclass
class TrainingStatus:
    state:         TrainingState = TrainingState.IDLE
    progress_pct:  float         = 0.0        # 0-100
    current_epoch: int           = 0
    total_epochs:  int           = 0
    val_accuracy:  float         = 0.0
    model_path:    str           = ""
    started_at:    Optional[str] = None
    finished_at:   Optional[str] = None
    error:         Optional[str] = None
    log_records_used: int        = 0

    def to_dict(self) -> dict:
        return {
            "state":            self.state.value,
            "progress_pct":     round(self.progress_pct, 1),
            "current_epoch":    self.current_epoch,
            "total_epochs":     self.total_epochs,
            "val_accuracy_pct": round(self.val_accuracy * 100, 2),
            "model_path":       self.model_path,
            "started_at":       self.started_at,
            "finished_at":      self.finished_at,
            "error":            self.error,
            "log_records_used": self.log_records_used,
        }


# ──────────────────────────────────────────────
#  GNNTrainingJob
# ──────────────────────────────────────────────

class GNNTrainingJob:
    """
    Background GNN training job manager.

    Only one training job can run at a time (singleton guard).
    """

    _instance_lock = threading.Lock()
    _active_job: Optional['GNNTrainingJob'] = None

    def __init__(
        self,
        logs_path:  str,
        output_dir: str,
        epochs:     int   = 30,
        n_synthetic: int  = 500,    # synthetic sessions if no CSV
    ):
        self.logs_path   = logs_path
        self.output_dir  = output_dir
        self.epochs      = epochs
        self.n_synthetic = n_synthetic

        self._status = TrainingStatus(total_epochs=epochs)
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ── Public API ──────────────────────────────

    @classmethod
    def is_running(cls) -> bool:
        with cls._instance_lock:
            return cls._active_job is not None and \
                   cls._active_job._status.state == TrainingState.RUNNING

    def start(self) -> bool:
        """Start training in background. Returns False if already running."""
        with GNNTrainingJob._instance_lock:
            if GNNTrainingJob.is_running():
                logger.warning("GNN training already in progress — ignoring start request")
                return False
            GNNTrainingJob._active_job = self

        self._status.state      = TrainingState.RUNNING
        self._status.started_at = datetime.utcnow().isoformat()
        self._status.error      = None

        self._thread = threading.Thread(
            target=self._run,
            name="GNNTrainer",
            daemon=True,
        )
        self._thread.start()
        logger.info("GNN training job started (epochs=%d)", self.epochs)
        return True

    def status(self) -> TrainingStatus:
        return self._status

    def stop(self) -> None:
        """Request graceful stop."""
        self._stop_event.set()

    # ── Internal runner ─────────────────────────

    def _run(self) -> None:
        try:
            self._do_train()
        except Exception as e:
            logger.error("GNN training failed: %s", e, exc_info=True)
            self._status.state     = TrainingState.FAILED
            self._status.error     = str(e)
            self._status.finished_at = datetime.utcnow().isoformat()
        finally:
            with GNNTrainingJob._instance_lock:
                GNNTrainingJob._active_job = None

    def _do_train(self) -> None:
        import random
        from modules.waf.ml_training.waf_gnn.session_graph import (
            SessionGraphBuilder, HTTPRequest, SessionGraph
        )
        from modules.waf.ml_training.waf_gnn.train import train as gnn_train

        sessions = []

        # ── Load from real CSV if available ───────
        if os.path.exists(self.logs_path):
            sessions = self._load_sessions_from_csv(self.logs_path)
            self._status.log_records_used = len(sessions)
            logger.info("Loaded %d sessions from %s", len(sessions), self.logs_path)

        # ── Fall back or augment with synthetic ──
        if len(sessions) < 50:
            logger.info("Not enough real data (%d sessions) — generating synthetic", len(sessions))
            from modules.waf.ml_training.waf_gnn.train import generate_synthetic_sessions
            sessions += generate_synthetic_sessions(self.n_synthetic)

        # ── Timestamp the output model ─────────
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        model_filename = f"gnn_model_{ts}.pt"
        output_path = os.path.join(self.output_dir, model_filename)
        os.makedirs(self.output_dir, exist_ok=True)

        self._status.model_path = output_path

        # ── Wrap the existing train() with epoch progress ──
        self._patched_train(sessions, output_path)

    def _patched_train(self, sessions, output_path: str) -> None:
        """
        Calls the existing GNN train logic but intercepts epoch callbacks
        to update our progress status.
        """
        import torch
        import torch.nn.functional as F
        from torch.optim import Adam
        from modules.waf.ml_training.waf_gnn.model import WAFGNNModel, NODE_FEATURE_DIM

        try:
            from torch_geometric.data import Data, DataLoader as GeoDataLoader
        except ImportError:
            raise RuntimeError("torch-geometric required: pip install torch-geometric")

        data_list = self._sessions_to_pyg(sessions, NODE_FEATURE_DIM)
        if not data_list:
            raise RuntimeError("No valid graphs generated from session data")

        n_val = max(1, int(len(data_list) * 0.1))
        val_data   = data_list[:n_val]
        train_data = data_list[n_val:]

        train_loader = GeoDataLoader(train_data, batch_size=32, shuffle=True)
        val_loader   = GeoDataLoader(val_data,   batch_size=32)

        model     = WAFGNNModel()
        optimizer = Adam(model.parameters(), lr=1e-3)
        criterion = torch.nn.CrossEntropyLoss()

        for epoch in range(1, self.epochs + 1):
            if self._stop_event.is_set():
                logger.info("GNN training stopped by user at epoch %d", epoch)
                break

            model.train()
            total_loss = 0.0
            for batch in train_loader:
                optimizer.zero_grad()
                out  = model(batch.x, batch.edge_index, batch.batch)
                loss = criterion(out, batch.y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()

            model.eval()
            correct = total = 0
            with torch.no_grad():
                for batch in val_loader:
                    preds   = model(batch.x, batch.edge_index, batch.batch).argmax(dim=-1)
                    correct += (preds == batch.y).sum().item()
                    total   += len(batch.y)

            val_acc = correct / max(total, 1)
            self._status.current_epoch = epoch
            self._status.progress_pct  = (epoch / self.epochs) * 100
            self._status.val_accuracy  = val_acc

            logger.info("GNN Epoch %d/%d  val_acc=%.1f%%", epoch, self.epochs, val_acc * 100)

        torch.save(model.state_dict(), output_path)
        logger.info("GNN model saved → %s", output_path)

        self._status.state       = TrainingState.SUCCESS
        self._status.finished_at = __import__('datetime').datetime.utcnow().isoformat()

    def _sessions_to_pyg(self, sessions, node_dim: int) -> list:
        """Convert SessionGraph objects to PyG Data objects."""
        import torch
        try:
            from torch_geometric.data import Data
        except ImportError:
            return []

        data_list = []
        for graph, label in sessions:
            if graph.num_nodes < 2:
                continue

            node_list = graph.node_ids
            node_idx  = {n: i for i, n in enumerate(node_list)}

            feat_rows = []
            for n in node_list:
                row = graph.node_features.get(n, [0.0] * node_dim)
                row = (row + [0.0] * node_dim)[:node_dim]
                feat_rows.append(row)
            x = torch.tensor(feat_rows, dtype=torch.float)

            src_list, dst_list = [], []
            for (frm, to, *_) in graph.edges:
                if frm in node_idx and to in node_idx:
                    src_list.append(node_idx[frm])
                    dst_list.append(node_idx[to])
            if not src_list:
                continue

            edge_index = torch.tensor([src_list, dst_list], dtype=torch.long)
            data_list.append(Data(
                x=x, edge_index=edge_index,
                y=torch.tensor([label], dtype=torch.long)
            ))
        return data_list

    def _load_sessions_from_csv(self, csv_path: str) -> list:
        """
        Load a session_logs.csv and convert rows into (SessionGraph, label) tuples.
        Sessions are identified by session_id. Sessions touching honeypot/scan
        paths are automatically labeled as attacks.
        """
        import csv as csv_mod
        from modules.waf.ml_training.waf_gnn.session_graph import (
            SessionGraphBuilder, HTTPRequest
        )

        ATTACK_PATHS = {
            '/.env', '/admin', '/wp-admin', '/phpmyadmin', '/shell.php',
            '/backup.sql', '/config.php', '/.git', '/api/v0/internal',
        }

        sessions_raw: dict = {}   # session_id → list of rows
        try:
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv_mod.DictReader(f)
                for row in reader:
                    sid = row.get("session_id", row.get("src_ip", "unknown"))
                    sessions_raw.setdefault(sid, []).append(row)
        except Exception as e:
            logger.error("Failed to read session_logs.csv: %s", e)
            return []

        result = []
        for sid, rows in sessions_raw.items():
            if not rows:
                continue
            src_ip = rows[0].get("src_ip", "0.0.0.0")
            builder = SessionGraphBuilder(sid, src_ip)
            has_attack_path = False

            for row in rows:
                path = row.get("path", "/")
                if any(a in path for a in ATTACK_PATHS):
                    has_attack_path = True
                try:
                    builder.add_request(HTTPRequest(
                        timestamp=float(row.get("timestamp", 0)),
                        src_ip=src_ip,
                        path=path,
                        method=row.get("method", "GET"),
                        response_code=int(row.get("response_code", 200)),
                    ))
                except Exception:
                    continue

            graph = builder.build()
            if graph.num_nodes >= 2:
                label = 1 if has_attack_path else 0
                result.append((graph, label))

        return result
