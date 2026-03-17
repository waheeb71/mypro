"""
Enterprise NGFW — Session Graph Builder

Converts a sequence of HTTP requests from a single session (IP/session-id)
into a directed graph representation for GNN analysis.

Graph structure:
    Nodes: each unique URL endpoint accessed
    Edges: directional transitions (page A → page B)
    Node features: [visit_count, avg_response_code, method_flags, depth]
    Edge features: [transition_count, time_delta]

The resulting graph is consumed by the WAFGNNModel.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import time


# ──────────────────────────────────────────────
#  Data structures
# ──────────────────────────────────────────────

@dataclass
class HTTPRequest:
    """Represents a single HTTP request in a session."""
    timestamp:     float
    src_ip:        str
    path:          str
    method:        str        # GET, POST, PUT, DELETE, …
    response_code: int        # 200, 403, 404, 500, …
    payload_length: int = 0


@dataclass
class SessionGraph:
    """
    A directed graph representing one IP session's navigation pattern.

    node_ids: unique path strings
    node_features: dict of path → [visit_count, avg_code, method_flags, depth]
    edges: list of (from_path, to_path, transition_count, mean_time_delta)
    labels: optional ground truth (0=normal, 1=attack)
    """
    session_id:     str
    src_ip:         str
    node_ids:       List[str]             = field(default_factory=list)
    node_features:  Dict[str, List[float]] = field(default_factory=dict)
    edges:          List[Tuple]           = field(default_factory=list)
    label:          Optional[int]         = None

    @property
    def num_nodes(self) -> int:
        return len(self.node_ids)

    @property
    def num_edges(self) -> int:
        return len(self.edges)


# ──────────────────────────────────────────────
#  SessionGraphBuilder
# ──────────────────────────────────────────────

class SessionGraphBuilder:
    """
    Builds a SessionGraph from a list of HTTPRequest objects.

    Usage:
        builder = SessionGraphBuilder()
        builder.add_request(req)
        graph = builder.build()
    """

    def __init__(self, session_id: str, src_ip: str):
        self.session_id = session_id
        self.src_ip     = src_ip

        self._requests: List[HTTPRequest] = []

        # Internal: node stats
        self._node_visits:   Dict[str, int]          = {}
        self._node_codes:    Dict[str, List[int]]     = {}
        self._node_methods:  Dict[str, set]           = {}

        # Internal: edge stats
        # key=(from,to), value=list of time deltas
        self._edge_deltas:   Dict[Tuple, List[float]] = {}

    def add_request(self, req: HTTPRequest) -> None:
        """Add a new HTTP request to the session."""
        self._requests.append(req)

        path = req.path.split('?')[0]   # strip query string for node identity

        # Update node stats
        self._node_visits[path]   = self._node_visits.get(path, 0) + 1
        self._node_codes.setdefault(path, []).append(req.response_code)
        self._node_methods.setdefault(path, set()).add(req.method)

        # Update edge stats (transition from previous → current)
        if len(self._requests) > 1:
            prev = self._requests[-2].path.split('?')[0]
            key  = (prev, path)
            delta = req.timestamp - self._requests[-2].timestamp
            self._edge_deltas.setdefault(key, []).append(delta)

    def build(self) -> SessionGraph:
        """Materialise the session into a SessionGraph."""
        graph = SessionGraph(session_id=self.session_id, src_ip=self.src_ip)

        # ── Nodes ──
        graph.node_ids = list(self._node_visits.keys())

        for path in graph.node_ids:
            visit_count = self._node_visits[path]
            codes       = self._node_codes.get(path, [200])
            avg_code    = sum(codes) / len(codes)
            methods     = self._node_methods.get(path, {'GET'})
            # Method flags: [has_GET, has_POST, has_PUT, has_DELETE]
            method_vec  = [
                1.0 if 'GET'    in methods else 0.0,
                1.0 if 'POST'   in methods else 0.0,
                1.0 if 'PUT'    in methods else 0.0,
                1.0 if 'DELETE' in methods else 0.0,
            ]
            depth = float(path.count('/'))
            graph.node_features[path] = [
                float(visit_count),
                avg_code / 500.0,    # normalize 200-500 → 0.4-1.0
                *method_vec,
                depth,
            ]

        # ── Edges ──
        for (from_path, to_path), deltas in self._edge_deltas.items():
            count      = len(deltas)
            mean_delta = sum(deltas) / count
            graph.edges.append((from_path, to_path, float(count), float(mean_delta)))

        return graph
