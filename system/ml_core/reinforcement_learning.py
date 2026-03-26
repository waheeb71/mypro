#!/usr/bin/env python3
"""
Enterprise CyberNexus - Reinforcement Learning Policy Optimizer

DQN-based adaptive policy optimization:
- State: traffic features + current policy parameters
- Actions: policy parameter adjustments
- Reward: security score + performance score
- Experience replay buffer
- Online/offline learning modes
"""

import logging
import random
import numpy as np
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import deque
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class PolicyAdjustment(Enum):
    """Available policy adjustments"""
    INCREASE_SENSITIVITY = "increase_sensitivity"
    DECREASE_SENSITIVITY = "decrease_sensitivity"
    TIGHTEN_RATE_LIMIT = "tighten_rate_limit"
    RELAX_RATE_LIMIT = "relax_rate_limit"
    ENABLE_DEEP_INSPECTION = "enable_deep_inspection"
    DISABLE_DEEP_INSPECTION = "disable_deep_inspection"
    NO_CHANGE = "no_change"


@dataclass
class RLState:
    """RL environment state"""
    anomaly_rate: float
    block_rate: float
    false_positive_rate: float
    throughput_pps: float
    avg_latency_ms: float
    active_threats: int
    current_sensitivity: float
    current_rate_limit: float

    def to_array(self) -> np.ndarray:
        return np.array([
            self.anomaly_rate,
            self.block_rate,
            self.false_positive_rate,
            self.throughput_pps / 100000,  # normalize
            self.avg_latency_ms / 100,
            self.active_threats / 10,
            self.current_sensitivity,
            self.current_rate_limit / 10000,
        ], dtype=np.float32)


@dataclass
class Experience:
    """Experience tuple for replay buffer"""
    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray
    done: bool


class ReplayBuffer:
    """Experience replay buffer"""

    def __init__(self, capacity: int = 10000):
        self.buffer = deque(maxlen=capacity)

    def push(self, exp: Experience):
        self.buffer.append(exp)

    def sample(self, batch_size: int) -> List[Experience]:
        return random.sample(self.buffer, min(batch_size, len(self.buffer)))

    def __len__(self):
        return len(self.buffer)


class SimpleQNetwork:
    """
    Simple Q-network using numpy (no torch/tf dependency)

    Two-layer MLP for Q-value estimation.
    Can be replaced with PyTorch/TF for production.
    """

    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = 64):
        self.state_dim = state_dim
        self.action_dim = action_dim

        # Xavier initialization
        scale1 = np.sqrt(2.0 / (state_dim + hidden_dim))
        scale2 = np.sqrt(2.0 / (hidden_dim + action_dim))

        self.W1 = np.random.randn(state_dim, hidden_dim).astype(np.float32) * scale1
        self.b1 = np.zeros(hidden_dim, dtype=np.float32)
        self.W2 = np.random.randn(hidden_dim, action_dim).astype(np.float32) * scale2
        self.b2 = np.zeros(action_dim, dtype=np.float32)

    def forward(self, state: np.ndarray) -> np.ndarray:
        """Forward pass"""
        h = np.maximum(0, state @ self.W1 + self.b1)  # ReLU
        return h @ self.W2 + self.b2

    def predict_action(self, state: np.ndarray) -> int:
        """Get best action for state"""
        q_values = self.forward(state)
        return int(np.argmax(q_values))

    def update(self, state, action, target, lr=0.001):
        """Single-step gradient update"""
        # Forward
        h = np.maximum(0, state @ self.W1 + self.b1)
        q_values = h @ self.W2 + self.b2

        # Backward (simplified)
        dq = np.zeros_like(q_values)
        dq[action] = q_values[action] - target

        # Layer 2
        dW2 = np.outer(h, dq)
        db2 = dq

        # Layer 1
        dh = dq @ self.W2.T
        dh[h <= 0] = 0  # ReLU grad

        dW1 = np.outer(state, dh)
        db1 = dh

        # Update
        self.W1 -= lr * dW1
        self.b1 -= lr * db1
        self.W2 -= lr * dW2
        self.b2 -= lr * db2

    def copy_from(self, other: 'SimpleQNetwork'):
        """Copy weights from another network"""
        self.W1 = other.W1.copy()
        self.b1 = other.b1.copy()
        self.W2 = other.W2.copy()
        self.b2 = other.b2.copy()


class RLPolicyOptimizer:
    """
    DQN-based Adaptive Policy Optimizer

    Uses reinforcement learning to automatically tune firewall
    policy parameters (sensitivity, rate limits, inspection depth)
    to balance security effectiveness with performance.
    """

    ACTIONS = list(PolicyAdjustment)

    def __init__(
        self,
        learning_rate: float = 0.001,
        gamma: float = 0.95,
        epsilon: float = 1.0,
        epsilon_decay: float = 0.995,
        epsilon_min: float = 0.05,
        batch_size: int = 32,
        target_update_freq: int = 100,
    ):
        self.lr = learning_rate
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        self.batch_size = batch_size
        self.target_update_freq = target_update_freq

        state_dim = 8  # RLState fields
        action_dim = len(self.ACTIONS)

        self.q_network = SimpleQNetwork(state_dim, action_dim)
        self.target_network = SimpleQNetwork(state_dim, action_dim)
        self.target_network.copy_from(self.q_network)

        self.replay_buffer = ReplayBuffer(capacity=10000)
        self.step_count = 0
        self.episode_rewards: List[float] = []
        self._current_episode_reward = 0.0

        # Current policy parameters
        self.policy_params = {
            'sensitivity': 0.5,
            'rate_limit': 5000,
            'deep_inspection': True,
        }

        self.stats = {
            'total_steps': 0,
            'total_updates': 0,
            'avg_reward': 0.0,
            'epsilon': self.epsilon,
        }

        logger.info("RLPolicyOptimizer initialized")

    def select_action(self, state: RLState) -> PolicyAdjustment:
        """Select action using epsilon-greedy policy"""
        self.step_count += 1

        if random.random() < self.epsilon:
            action_idx = random.randint(0, len(self.ACTIONS) - 1)
        else:
            state_array = state.to_array()
            action_idx = self.q_network.predict_action(state_array)

        return self.ACTIONS[action_idx]

    def compute_reward(
        self,
        threats_blocked: int,
        false_positives: int,
        throughput_ratio: float,
        latency_ratio: float
    ) -> float:
        """
        Compute reward signal

        Args:
            threats_blocked: number of real threats blocked
            false_positives: number of false positive blocks
            throughput_ratio: current/baseline throughput (1.0 = no degradation)
            latency_ratio: current/baseline latency (1.0 = no increase)

        Returns:
            Reward value
        """
        security_score = threats_blocked * 1.0 - false_positives * 2.0
        performance_score = throughput_ratio * 0.5 - max(latency_ratio - 1.0, 0) * 1.0

        return security_score + performance_score

    def apply_action(self, action: PolicyAdjustment) -> Dict:
        """Apply policy adjustment and return new params"""
        if action == PolicyAdjustment.INCREASE_SENSITIVITY:
            self.policy_params['sensitivity'] = min(
                self.policy_params['sensitivity'] + 0.05, 1.0
            )
        elif action == PolicyAdjustment.DECREASE_SENSITIVITY:
            self.policy_params['sensitivity'] = max(
                self.policy_params['sensitivity'] - 0.05, 0.1
            )
        elif action == PolicyAdjustment.TIGHTEN_RATE_LIMIT:
            self.policy_params['rate_limit'] = max(
                self.policy_params['rate_limit'] - 500, 100
            )
        elif action == PolicyAdjustment.RELAX_RATE_LIMIT:
            self.policy_params['rate_limit'] = min(
                self.policy_params['rate_limit'] + 500, 50000
            )
        elif action == PolicyAdjustment.ENABLE_DEEP_INSPECTION:
            self.policy_params['deep_inspection'] = True
        elif action == PolicyAdjustment.DISABLE_DEEP_INSPECTION:
            self.policy_params['deep_inspection'] = False

        return self.policy_params.copy()

    def step(
        self,
        state: RLState,
        action: PolicyAdjustment,
        reward: float,
        next_state: RLState,
        done: bool = False
    ):
        """Store experience and train"""
        action_idx = self.ACTIONS.index(action)

        exp = Experience(
            state=state.to_array(),
            action=action_idx,
            reward=reward,
            next_state=next_state.to_array(),
            done=done
        )
        self.replay_buffer.push(exp)

        self._current_episode_reward += reward
        if done:
            self.episode_rewards.append(self._current_episode_reward)
            self._current_episode_reward = 0.0

        # Train
        if len(self.replay_buffer) >= self.batch_size:
            self._train_step()

        # Update target network
        if self.step_count % self.target_update_freq == 0:
            self.target_network.copy_from(self.q_network)

        # Decay epsilon
        self.epsilon = max(self.epsilon * self.epsilon_decay, self.epsilon_min)

        # Update stats
        self.stats['total_steps'] = self.step_count
        self.stats['epsilon'] = self.epsilon
        self.stats['avg_reward'] = (
            np.mean(self.episode_rewards[-100:]) if self.episode_rewards else 0.0
        )

    def _train_step(self):
        """Train Q-network on a batch"""
        batch = self.replay_buffer.sample(self.batch_size)

        for exp in batch:
            if exp.done:
                target = exp.reward
            else:
                next_q = self.target_network.forward(exp.next_state)
                target = exp.reward + self.gamma * np.max(next_q)

            self.q_network.update(exp.state, exp.action, target, lr=self.lr)

        self.stats['total_updates'] += 1

    def get_metrics(self) -> Dict:
        """Get optimizer metrics"""
        return {
            **self.stats,
            'policy_params': self.policy_params.copy(),
            'buffer_size': len(self.replay_buffer),
            'episodes': len(self.episode_rewards),
        }

    def get_policy_params(self) -> Dict:
        """Get current policy parameters"""
        return self.policy_params.copy()
