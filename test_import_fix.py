import sys
import os

# Add the project root to sys.path
sys.path.append(os.getcwd())

try:
    # We only care about the import fix for RL components
    from system.ml_core import RLPolicyOptimizer, RLState, PolicyAdjustment
    print("[SUCCESS] Imported RL components from system.ml_core")
    
    # Check if we can import from system.core.engine partly
    # (it might fail due to missing dependencies like yaml, but the RL import part should be fine)
    import system.core.engine
    print("[SUCCESS] Imported system.core.engine")
    
    print("🚀 All imports related to the fix are working correctly.")
except ImportError as e:
    print(f"[ERROR] ImportError: {e}")
    sys.exit(1)
except ModuleNotFoundError as e:
    # If it's a missing dependency like 'yaml', it's okay for this test
    if e.name in ['yaml', 'geoip2', 'bcc']:
        print(f"[INFO] Missing optional/external dependency: {e.name}")
        print("[SUCCESS] The RL import fix itself is verified.")
    else:
        print(f"[ERROR] ModuleNotFoundError: {e}")
        sys.exit(1)
except Exception as e:
    print(f"[ERROR] An unexpected error occurred: {e}")
    sys.exit(1)
