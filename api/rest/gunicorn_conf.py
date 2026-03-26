import multiprocessing
import os

# Gunicorn Configuration

# Binding
bind = "0.0.0.0:8000"

# Workers
# For CPU bound tasks (like ML), (2 * CPU) + 1 is a good starting point.
# However, for an async app like FastAPI, we use Uvicorn workers.
workers = int(os.getenv("CyberNexus_WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = "uvicorn.workers.UvicornWorker"

# Threads (only for standard workers, not Uvicorn)
# threads = 2

# Timeout
timeout = 120
keepalive = 5

# Logging
loglevel = os.getenv("CyberNexus_LOG_LEVEL", "info").lower()
accesslog = "-"  # stdout
errorlog = "-"   # stderr

# Process Name
proc_name = "CyberNexus-api"

# Reload (development only)
reload = os.getenv("CyberNexus_ENV", "production") == "development"
