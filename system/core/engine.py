import asyncio
import logging
import signal
import sys
import yaml
import logging.handlers
from pathlib import Path
from typing import Optional
import argparse
# Core components
from system.core.router import TrafficRouter, RoutingDecision, ProxyMode
from system.core.flow_tracker import FlowTracker
from modules.ssl_inspection.engine.ca_pool import CAPoolManager
from modules.ssl_inspection.engine.inspector import SSLInspector
from modules.ssl_inspection.engine.policy_engine import SSLPolicyEngine
from modules.proxy.engine.proxy_modes import TransparentProxy, ForwardProxy, ReverseProxy

# Acceleration
from acceleration.ebpf.xdp_engine import create_xdp_engine

from system.ml_core import (
    TrafficProfiler, TrafficPattern,
    AdaptivePolicyEngine, PolicyAction,
    DeepTrafficClassifier,
    RLPolicyOptimizer, RLState, PolicyAdjustment
)
from modules.ids_ips.engine.anomaly_detector import AnomalyDetector

# Advanced AI Layers
from modules.predictive_ai.engine.predictive import AttackForecaster
from modules.predictive_ai.engine.vulnerability_scorer import VulnerabilityPredictor
from modules.uba.engine.user_behavior import UserBehaviorAnalytics
from system.response import MitigationOrchestrator, RecoveryManager, MitigationAction, HealthStatus

# Events & Health
from system.telemetry.events import UnifiedEventSink, SinkConfig
from system.telemetry.events.unified_sink import create_unified_sink
from system.telemetry.health import HealthChecker

# Integrations
from modules.vpn.engine.wireguard import WireGuardManager, PeerConfig
from system.ha import HAManager, NodeState
from system.ha.state_sync import StateSynchronizer
from system.database.database import DatabaseManager
from system.networking.transparent_proxy import TransparentProxyManager

# Plugins
from system.inspection_core.framework.pipeline import InspectionPipeline
from modules.predictive_ai.engine.ai_inspector import AIInspector
from system.core.module_manager import ModuleManager

logger = logging.getLogger(__name__)

class NGFWApplication:
    """
    Main NGFW Application Controller
    
    Manages lifecycle of all components.
    """
    
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.config: Optional[dict] = None
        
        # Core components
        self.traffic_router: Optional[TrafficRouter] = None
        self.flow_tracker: Optional[FlowTracker] = None
        self.ca_manager: Optional[CAPoolManager] = None
        self.ssl_inspector: Optional[SSLInspector] = None
        self.ssl_policy_engine: Optional[SSLPolicyEngine] = None
        self.xdp_engine = None
        
        self.event_sink: Optional[UnifiedEventSink] = None
        self.health_checker: Optional[HealthChecker] = None
        
        # ML Components
        self.anomaly_detector: Optional[AnomalyDetector] = None
        self.traffic_profiler: Optional[TrafficProfiler] = None
        self.policy_engine: Optional[AdaptivePolicyEngine] = None
        self.deep_classifier: Optional[DeepTrafficClassifier] = None
        self.rl_optimizer: Optional[RLPolicyOptimizer] = None
        
        self.attack_forecaster: Optional[AttackForecaster] = None
        self.vulnerability_predictor: Optional[VulnerabilityPredictor] = None
        self.uba: Optional[UserBehaviorAnalytics] = None
        self.orchestrator: Optional[MitigationOrchestrator] = None
        self.recovery_manager: Optional[RecoveryManager] = None
        
        # Integrations
        self.vpn_manager: Optional[WireGuardManager] = None
        self.vpn_enabled: bool = False
        self.ha_manager: Optional[HAManager] = None
        self.state_sync: Optional[StateSynchronizer] = None
        self.is_ha_master: bool = True
        
        # Database
        db_path = self.config_path.parent / 'ngfw.db'
        self.db = DatabaseManager(f"sqlite:///{db_path}")
        
        # Proxy modes
        self.transparent_proxy: Optional[TransparentProxy] = None
        self.forward_proxy: Optional[ForwardProxy] = None
        self.reverse_proxy: Optional[ReverseProxy] = None
        
        self.transparent_networking: Optional[TransparentProxyManager] = None
        
        self.running = False
        self.engine_running = False
        self._engine_tasks = []
        self.shutdown_event = asyncio.Event()
    
    def load_config(self):
        logger.info(f"Loading configuration from {self.config_path}")
        try:
            with open(self.config_path, 'r', encoding='utf-8', errors='replace') as f:
                self.config = yaml.safe_load(f)
            
            logger.info("✅ Configuration loaded successfully")
            
            required_sections = ['proxy', 'tls', 'logging']
            for section in required_sections:
                if section not in self.config:
                    logger.error(f"Missing required configuration section: {section}")
                    sys.exit(1)
            
            proxy_mode = self.config.get('proxy', {}).get('mode', 'transparent')
            logger.info(f"🔥 Proxy mode: {proxy_mode}")
            
            self.setup_file_logging()
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)
            
    def setup_file_logging(self):
        """Setup rolling file logging based on configuration"""
        log_config = self.config.get('logging', {})
        log_file = Path(log_config.get('file', 'logs/ngfw.log'))
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Check if already has file handlers to prevent duplication on reload
        root_logger = logging.getLogger()
        for handler in root_logger.handlers:
            if isinstance(handler, logging.handlers.RotatingFileHandler):
                return
                
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=log_config.get('max_bytes', 104857600),
            backupCount=log_config.get('backup_count', 10),
            encoding='utf-8'
        )
        file_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s [%(levelname)8s] %(name)s: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        )
        root_logger.addHandler(file_handler)
        logger.info(f"✅ Rolling Log File configured: {log_file}")
            
    def reload_config(self):
        logger.info("Hot-reloading config.")
        self.load_config()
    
    def get_uptime(self):
        # Mock uptime for API compatibility pending real timer
        return 3600.0

    async def initialize_components(self):
        logger.info("Initializing components...")
        self.db.initialize()
        import os
        admin_pass = os.getenv("NGFW_ADMIN_PASSWORD", "admin123")
        op_pass = os.getenv("NGFW_OPERATOR_PASSWORD", "operator123")
        from api.rest.auth import _hash_password
        self.db.add_default_users(_hash_password(admin_pass), _hash_password(op_pass))
        logger.info("✅ Database initialized")
        
        try:
            logger.info("Initializing Core Engines...")
            self.ca_manager = CAPoolManager(self.config)
            self.ssl_inspector = SSLInspector(self.ca_manager, self.config)
            self.ssl_policy_engine = SSLPolicyEngine(self.config)
            self.traffic_router = TrafficRouter(self.config)
            
            self.event_sink = create_unified_sink(self.config)
            await self.event_sink.start()
            
            self.flow_tracker = FlowTracker(self.config)
            self.xdp_engine = create_xdp_engine(self.config, self.event_sink)
            
            # ⚡ Wire XDP Engine into FlowTracker for AI-driven immediate blocking
            self.flow_tracker.set_xdp_engine(self.xdp_engine)
            
            self.health_checker = HealthChecker(self)

            
            logger.info("Initializing Inspection Pipeline...")
            self.inspection_pipeline = InspectionPipeline()
            
            logger.info("Loading Dynamic Modules...")
            module_manager = ModuleManager(self.config, self.inspection_pipeline)
            module_manager.load_plugins()
            
            ml_config = self.config.get('ml', {})
            if ml_config.get('enabled', True):
                logger.info("Initializing ML components...")
                self.anomaly_detector = AnomalyDetector(contamination=ml_config.get('anomaly_contamination', 0.1))
                self.traffic_profiler = TrafficProfiler(time_window=ml_config.get('profiler_time_window', 300))
                self.policy_engine = AdaptivePolicyEngine(learning_rate=ml_config.get('policy_learning_rate', 0.1))
                self.deep_classifier = DeepTrafficClassifier(model_path=ml_config.get('deep_model_path'))
                self.rl_optimizer = RLPolicyOptimizer()
                
                # 🤖 Link RL Optimizer to Adaptive Policy Engine if enabled in config
                if ml_config.get('rl_policy_sync', {}).get('enabled', False):
                    if hasattr(self.policy_engine, 'set_rl_optimizer'):
                        self.policy_engine.set_rl_optimizer(self.rl_optimizer)

                self.attack_forecaster = AttackForecaster()

                self.vulnerability_predictor = VulnerabilityPredictor()
                self.uba = UserBehaviorAnalytics(self.db)
                self.orchestrator = MitigationOrchestrator()
                self.recovery_manager = RecoveryManager()
                
                if self.flow_tracker:
                    self.flow_tracker.set_analytics(self.uba, self.vulnerability_predictor)
                
                if self.traffic_router:
                    self.traffic_router.set_orchestrator(self.orchestrator)
                
                if self.deep_classifier:
                    ai_plugin = AIInspector(self.deep_classifier, flow_tracker=self.flow_tracker)
                    self.inspection_pipeline.register_plugin(ai_plugin)
            
            vpn_config = self.config.get('vpn', {})
            self.vpn_enabled = vpn_config.get('enabled', False)
            if self.vpn_enabled:
                logger.info("Initializing WireGuard VPN...")
                interface_name = vpn_config.get('interface', 'wg0')
                self.vpn_manager = WireGuardManager(interface=interface_name, logger=logger)
                vpn_ip = vpn_config.get('ip_address', '10.8.0.1/24')
                vpn_port = vpn_config.get('listen_port', 51820)
                if self.vpn_manager.setup_interface(ip_address=vpn_ip, port=vpn_port):
                    logger.info(f"✅ WireGuard VPN initialized on {interface_name} ({vpn_ip})")
                    self._save_vpn_config_to_db(interface_name, vpn_ip, vpn_port)
                    self._load_vpn_peers_from_db()
            
            ha_config = self.config.get('ha', {})
            if ha_config.get('enabled', False):
                logger.info("Initializing HA...")
                node_id = ha_config.get('node_id', 'node_1')
                priority = ha_config.get('priority', 100)
                peer_ip = ha_config.get('peer_ip', '127.0.0.1')
                self.ha_manager = HAManager(node_id, priority, peer_ip=peer_ip, logger=logger)
                self.state_sync = StateSynchronizer(peer_ip=peer_ip, logger=logger)
                
                def on_ha_state_change(new_state: NodeState):
                    self.is_ha_master = (new_state == NodeState.MASTER)
                    if self.state_sync:
                        self.state_sync.on_state_change(self.is_ha_master)
                    logger.info(f"HA State changed! Currently Master: {self.is_ha_master}")
                    
                self.ha_manager.set_state_change_callback(on_ha_state_change)
                await self.ha_manager.start()
                self.is_ha_master = (self.ha_manager.state == NodeState.MASTER)
                await self.state_sync.start(self.is_ha_master)
            else:
                self.is_ha_master = True
                
            proxy_mode = self.config.get('proxy', {}).get('mode', 'transparent')
            
            if proxy_mode in ('none', 'disabled', 'off'):
                logger.info("🔕 Proxy disabled — running in packet-filter only mode (XDP/eBPF)")
            else:
                if proxy_mode in ('transparent', 'all'):
                    # Wire up Linux Networking IPTables dynamically
                    self.transparent_networking = TransparentProxyManager(self.config)
                    self.transparent_proxy = TransparentProxy(
                        self.config, self.ca_manager, self.xdp_engine, self.event_sink, inspection_pipeline=self.inspection_pipeline)
                if proxy_mode in ('forward', 'all'):
                    self.forward_proxy = ForwardProxy(self.config, self.ca_manager, self.flow_tracker, self.event_sink)
                if proxy_mode in ('reverse', 'all'):
                    self.reverse_proxy = ReverseProxy(self.config, self.ca_manager, self.flow_tracker, self.event_sink)
                if self.transparent_proxy is None and self.forward_proxy is None and self.reverse_proxy is None:
                    logger.warning(f"⚠️ Unknown proxy mode '{proxy_mode}' — no proxy started. Valid values: transparent, forward, reverse, all, none")

            
            logger.info("✅ All components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}", exc_info=True)
            raise
    
    async def start_firewall_components(self):
        if self.engine_running: return
        logger.info("Starting firewall data plane components...")
        self.engine_running = True
        self._engine_tasks = []
        
        if getattr(self, 'flow_tracker', None): await self.flow_tracker.start()
        if getattr(self, 'xdp_engine', None): await self.xdp_engine.start()
            
        if self.transparent_proxy:
            # First, set up IPTables routing
            if self.transparent_networking:
                self.transparent_networking.enable_ip_forwarding()
                self.transparent_networking.clear_existing_rules()
                self.transparent_networking.setup_transparent_rules()
            # Second, start the python proxy server
            self._engine_tasks.append(asyncio.create_task(self.transparent_proxy.start()))
            
        if self.forward_proxy: self._engine_tasks.append(asyncio.create_task(self.forward_proxy.start()))
        if self.reverse_proxy: self._engine_tasks.append(asyncio.create_task(self.reverse_proxy.start()))
        
        if self.config.get('ml', {}).get('enabled', True):
            self._engine_tasks.append(asyncio.create_task(self._ml_maintenance_loop()))
            
        logger.info("✅ Firewall engine native loop started.")
        
    async def stop_firewall_components(self):
        if not self.engine_running: return
        logger.warning("Stopping firewall data plane components natively...")
        self.engine_running = False
        
        for task in self._engine_tasks: task.cancel()
        self._engine_tasks.clear()
        
        if getattr(self, 'transparent_proxy', None): await self.transparent_proxy.stop()
        if getattr(self, 'transparent_networking', None): self.transparent_networking.teardown()
            
        if getattr(self, 'forward_proxy', None): await self.forward_proxy.stop()
        if getattr(self, 'reverse_proxy', None): await self.reverse_proxy.stop()
        if getattr(self, 'flow_tracker', None): await self.flow_tracker.stop()
        if getattr(self, 'xdp_engine', None): await self.xdp_engine.stop()
        logger.info("🛑 Firewall engine natively stopped.")
    
    async def stop(self):
        if not self.running: return
        logger.info("🛑 Stopping Enterprise NGFW")
        await self.stop_firewall_components()
        if self.vpn_manager and self.vpn_enabled: self.vpn_manager.teardown()
        if self.ha_manager: await self.ha_manager.stop()
        if self.state_sync: await self.state_sync.stop()
        self.shutdown_event.set()
        
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}")
            asyncio.create_task(self.stop())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        logger.info("✅ Signal handlers installed")

    async def run_forever(self):
        """Run until shutdown signal received"""
        self._setup_signal_handlers()
        await self.shutdown_event.wait()
    
    async def _ml_maintenance_loop(self):
        logger.info("ML maintenance loop started")
        while self.running:
            try:
                await asyncio.sleep(60)
                if self.traffic_profiler and self.policy_engine and self.rl_optimizer:
                    # Mock RL state for background training
                    active_threats = self.anomaly_detector.get_stats()['anomalies_detected'] if self.anomaly_detector else 0
                    current_state = RLState(
                        anomaly_rate=0.05, block_rate=0.1, false_positive_rate=0.01,
                        throughput_pps=15000.0, avg_latency_ms=45.0, active_threats=active_threats,
                        current_sensitivity=self.rl_optimizer.policy_params['sensitivity'],
                        current_rate_limit=self.rl_optimizer.policy_params['rate_limit']
                    )
                    action = self.rl_optimizer.select_action(current_state)
                    if action != PolicyAdjustment.NO_CHANGE:
                        new_params = self.rl_optimizer.apply_action(action)
                        logger.info(f"🤖 RL Optimizer applied action: {action.name}")
                    
                    if self.attack_forecaster:
                        forecast = self.attack_forecaster.forecast(current_state.throughput_pps)
                        if forecast.risk_level in ["HIGH", "CRITICAL"]:
                            logger.warning(f"🔮 Forecast Risk: {forecast.risk_level}")
                        
                    if self.recovery_manager:
                        recovered = self.recovery_manager.check_recoveries()
                        if recovered: logger.info(f"🔄 Automated recoveries executed for: {recovered}")
            except Exception as e:
                logger.error(f"Error in ML maintenance: {e}")

    def _save_vpn_config_to_db(self, interface: str, ip: str, port: int):
        """Save current VPN interface configuration to DB"""
        from system.database.database import VPNConfig
        with self.db.session() as session:
            config = session.query(VPNConfig).filter_by(interface=interface).first()
            if not config:
                config = VPNConfig(interface=interface)
                session.add(config)
            
            config.server_ip = ip
            config.listen_port = port
            config.enabled = True
            if self.vpn_manager:
                config.public_key = self.vpn_manager.public_key or ""
                # Note: private_key should be handled with care
            
            session.commit()
            logger.debug(f"VPN configuration for {interface} saved to DB")

    def _load_vpn_peers_from_db(self):
        """Restore WireGuard peers from database"""
        if not self.vpn_manager:
            return
            
        from system.database.database import VPNPeer
        from modules.vpn.engine.wireguard import PeerConfig
        
        with self.db.session() as session:
            db_peers = session.query(VPNPeer).filter_by(enabled=True).all()
            for dbp in db_peers:
                peer = PeerConfig(
                    public_key=dbp.public_key,
                    allowed_ips=dbp.allowed_ips or [],
                    endpoint=dbp.endpoint or None,
                    preshared_key=dbp.preshared_key or None,
                    persistent_keepalive=dbp.persistent_keepalive
                )
                self.vpn_manager.add_peer(peer)
            
            logger.info(f"✅ Restored {len(db_peers)} VPN peers from database")
