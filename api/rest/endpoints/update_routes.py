"""
Enterprise CyberNexus - OTA Update & System Management Endpoints  (Admin only)
GET  /api/v1/system/update/check    — Check GitHub for available updates
POST /api/v1/system/update/apply    — Apply update from GitHub + restart
GET  /api/v1/system/update/history  — Tail the latest update log
"""
import os
import logging
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field

from api.rest.auth import require_admin

router = APIRouter(prefix="/api/v1/system/update", tags=["OTA Updates"])
logger = logging.getLogger(__name__)

REPO_URL = os.getenv("CyberNexus_REPO_URL", "https://github.com/waheeb71/enterprise-CyberNexus")
INSTALL_DIR = os.getenv("CyberNexus_HOME", "/opt/enterprise_CyberNexus")
UPDATE_LOG_DIR = Path("/var/log/CyberNexus")


# ── Schemas ───────────────────────────────────────────────────────────────────

class ApplyUpdateRequest(BaseModel):
    branch: str = Field("main", description="Branch / tag to pull")
    run_migrations: bool = Field(True, description="Run Alembic migrations after pull")
    restart_service: bool = Field(True, description="Restart CyberNexus systemd service after update")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_git_repo() -> bool:
    return os.path.exists(os.path.join(INSTALL_DIR, ".git"))


def _git(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", INSTALL_DIR] + list(args),
        capture_output=True, text=True, timeout=60
    )


def _current_version() -> dict:
    result = _git("log", "-1", "--pretty=format:%H|%s|%ad", "--date=short")
    if result.returncode != 0:
        return {"commit": "unknown", "message": "N/A", "date": "N/A"}
    parts = result.stdout.split("|", 2)
    return {
        "commit": parts[0] if len(parts) > 0 else "unknown",
        "message": parts[1] if len(parts) > 1 else "N/A",
        "date": parts[2] if len(parts) > 2 else "N/A",
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/check")
async def check_for_updates(token: dict = Depends(require_admin)):
    """
    Compare local HEAD with remote origin to detect available updates.
    Returns current version, latest remote commit, and whether an update is available.
    Admin only.
    """
    if not _is_git_repo():
        return {
            "update_available": False,
            "note": f"Installation at '{INSTALL_DIR}' is not a git repository. Manual update required.",
            "repo_url": REPO_URL,
        }

    try:
        # Fetch remote metadata (no merge)
        fetch = _git("fetch", "--dry-run")
        local = _git("rev-parse", "HEAD")
        remote = _git("rev-parse", "@{u}")
        base = _git("merge-base", "HEAD", "@{u}")

        local_sha = local.stdout.strip()
        remote_sha = remote.stdout.strip()
        base_sha = base.stdout.strip()

        if local_sha == remote_sha:
            behind = 0
            update_available = False
        else:
            # Count commits behind
            count_result = _git("rev-list", "--count", f"HEAD..@{{u}}")
            behind = int(count_result.stdout.strip()) if count_result.returncode == 0 else -1
            update_available = True

        current = _current_version()
        return {
            "update_available": update_available,
            "commits_behind": behind,
            "current": current,
            "repo_url": REPO_URL,
            "checked_at": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Update check failed: {e}")


@router.post("/apply")
async def apply_update(
    request: Request,
    payload: ApplyUpdateRequest,
    token: dict = Depends(require_admin)
):
    """
    Pull latest code from GitHub, update dependencies, run migrations, restart service.
    Replaces the old update.sh script.
    Admin only.
    """
    if not _is_git_repo():
        raise HTTPException(
            status_code=400,
            detail=f"Not a git repository: {INSTALL_DIR}. Cannot auto-update."
        )

    update_log_path = UPDATE_LOG_DIR / f"update-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.log"

    def _run_update():
        log_lines = []

        def log(msg):
            logger.info(msg)
            log_lines.append(msg)

        try:
            UPDATE_LOG_DIR.mkdir(parents=True, exist_ok=True)

            log(f"[{datetime.utcnow().isoformat()}] Starting OTA update — branch: {payload.branch}")

            # Reset local changes
            log("▶ Resetting local changes...")
            subprocess.run(["git", "-C", INSTALL_DIR, "reset", "--hard", "HEAD"], check=True, capture_output=True)

            # Checkout target branch
            subprocess.run(["git", "-C", INSTALL_DIR, "checkout", payload.branch], check=True, capture_output=True)
            log(f"▶ Checked out branch: {payload.branch}")

            # Pull latest
            result = subprocess.run(["git", "-C", INSTALL_DIR, "pull"], capture_output=True, text=True)
            log(result.stdout.strip())
            if result.returncode != 0:
                log(f"ERROR: git pull failed: {result.stderr}")
                return

            # Install dependencies
            venv_bin = os.path.join(INSTALL_DIR, "venv", "bin")
            pip_exe = os.path.join(venv_bin, "pip") if os.path.exists(venv_bin) else "pip"
            req_files = ["requirements.txt", "requirements/base.txt", "requirements/production.txt"]
            for req in req_files:
                full_path = os.path.join(INSTALL_DIR, req)
                if os.path.exists(full_path):
                    subprocess.run([pip_exe, "install", "-q", "-r", full_path], check=True, capture_output=True)
                    log(f"✅ Dependencies updated from {req}")
                    break

            # Run migrations
            if payload.run_migrations:
                alembic_exe = os.path.join(venv_bin, "alembic") if os.path.exists(venv_bin) else "alembic"
                if os.path.exists(os.path.join(INSTALL_DIR, "alembic.ini")):
                    subprocess.run([alembic_exe, "upgrade", "head"], cwd=INSTALL_DIR, capture_output=True)
                    log("✅ Database migrations applied")

            # Restart service
            if payload.restart_service:
                log("🔄 Restarting CyberNexus service...")
                import time
                time.sleep(2)
                subprocess.run(["systemctl", "restart", "CyberNexus"])

            log("🎉 OTA update completed successfully.")

        except Exception as e:
            log(f"[ERROR] Update failed: {e}")

        finally:
            try:
                with open(update_log_path, "w") as f:
                    f.write("\n".join(log_lines))
            except Exception:
                pass

    # Fire on background thread — response returns immediately
    threading.Thread(target=_run_update, daemon=True).start()

    return {
        "status": "initiated",
        "message": f"Update from branch '{payload.branch}' started in background.",
        "log_file": str(update_log_path),
        "restart_service": payload.restart_service,
    }


@router.get("/history")
async def update_history(lines: int = 50, token: dict = Depends(require_admin)):
    """Return the last N lines from the most recent update log. Admin only."""
    try:
        log_files = sorted(UPDATE_LOG_DIR.glob("update-*.log"), reverse=True)
        if not log_files:
            return {"log": None, "message": "No update logs found."}
        latest = log_files[0]
        with open(latest, "r") as f:
            content = f.readlines()
        return {
            "log_file": str(latest),
            "lines": content[-lines:]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
