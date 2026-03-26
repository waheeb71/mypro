"""
Enterprise CyberNexus - REST API Entry Point
=========================================
This is the ONLY file that assembles the application.
All actual endpoints live in api/rest/endpoints/.
Adding a new endpoint group = create a new file in endpoints/ and register it here.
"""
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
import importlib
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
# ── Core App Routers ──────────────────────────────────────────────────────────
from api.rest.endpoints.auth_routes import router as auth_router
from api.rest.endpoints.status_routes import router as status_router
from api.rest.endpoints.config_routes import router as config_router
from api.rest.endpoints.users_routes import router as users_router
from api.rest.endpoints.networking_routes import router as networking_router
from api.rest.endpoints.update_routes import router as update_router

logger = logging.getLogger(__name__)

# ── Rate Limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


# ── Default-user seeding ──────────────────────────────────────────────────────

def _seed_default_users(app: FastAPI) -> None:
    """
    Called once at startup.
    If the 'users' table is empty, create admin (and operator) accounts
    using passwords taken from environment variables:
        CyberNexus_ADMIN_PASSWORD    (default: Admin@1234)
        CyberNexus_OPERATOR_PASSWORD (default: Operator@1234)
    Has no effect if users already exist.
    """
    try:
        CyberNexus = getattr(app.state, "CyberNexus", None)
        if CyberNexus is None or not hasattr(CyberNexus, "db"):
            logger.warning("⚠️  CyberNexus state not ready – skipping user seeding.")
            return

        from api.rest.auth import _hash_password
        from system.database.database import User

        admin_pw   = os.getenv("CyberNexus_ADMIN_PASSWORD",    "Admin@1234")
        operator_pw = os.getenv("CyberNexus_OPERATOR_PASSWORD", "Operator@1234")

        db = CyberNexus.db
        with db.session() as session:
            user_count = session.query(User).count()

        if user_count == 0:
            db.add_default_users(
                admin_hash=_hash_password(admin_pw),
                operator_hash=_hash_password(operator_pw),
            )
            logger.info("═" * 65)
            logger.info("  ✅ First-run detected — default users created:")
            logger.info(f"     👤 admin    / password: {admin_pw}")
            logger.info(f"     👤 operator / password: {operator_pw}")
            logger.info("  ⚠️  Change these passwords immediately via the Users page!")
            logger.info("═" * 65)
        else:
            logger.info(f"✔  Users already seeded ({user_count} accounts found) — skipping.")

    except Exception as exc:
        logger.error(f"❌ Failed to seed default users: {exc}", exc_info=True)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Enterprise CyberNexus API starting…")
    _seed_default_users(app)
    yield
    logger.info("🛑 Enterprise CyberNexus API shut down.")

# ── Application Factory ───────────────────────────────────────────────────────
def create_app() -> FastAPI:
    application = FastAPI(
        title="Enterprise CyberNexus API",
        description=(
            "Next-Generation Firewall — Production REST API.\n\n"
            "**Authentication:** Bearer JWT (obtain via `/api/v1/auth/login`).\n\n"
            "**Roles:**\n"
            "- `admin` — full access to all endpoints.\n"
            "- `operator` — read access + module/rule management.\n"
            "- `viewer` — status and health only.\n\n"
            "**Resource rules:** Non-admin users need an explicit resource rule set by an admin "
            "to access module-specific endpoints (firewall, vpn, waf, qos …)."
        ),
        version="2.0.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # Rate limiting
    application.state.limiter = limiter
    application.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # CORS
    application.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"^http://(localhost|127\.0\.0\.1)(:\d+)?$",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Register Core Routers ─────────────────────────────────────────────────
    application.include_router(auth_router)
    application.include_router(status_router)
    application.include_router(config_router)
    application.include_router(users_router)
    application.include_router(networking_router)
    application.include_router(update_router)

    # ── Register Dynamic Module Routers ───────────────────────────────────────
    # Each module in modules/ or system/ can expose its own router at
    # <module>/api/router.py  →  router: APIRouter
    _load_module_routers(application)

    # ── Exception Handlers ────────────────────────────────────────────────────
    @application.exception_handler(HTTPException)
    async def http_exc_handler(request: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail, "timestamp": datetime.utcnow().isoformat() + "Z"},
        )

    @application.exception_handler(Exception)
    async def general_exc_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error", "timestamp": datetime.utcnow().isoformat() + "Z"},
        )

    return application


def _load_module_routers(app: FastAPI):
    """
    Auto-discover <module>/api/router.py files inside modules/ and system/.
    Each router is expected to export a `router: APIRouter` object.
    To add a new module endpoint: create modules/<name>/api/router.py, done.
    """
    base_dir = Path(__file__).parent.parent.parent
    for search_dir in ("modules", "system"):
        dir_path = base_dir / search_dir
        if not dir_path.exists():
            continue
        for component_dir in sorted(dir_path.iterdir()):
            if component_dir.is_dir() and not component_dir.name.startswith("__"):
                router_file = component_dir / "api" / "router.py"
                if router_file.exists():
                    module_path = f"{search_dir}.{component_dir.name}.api.router"
                    try:
                        mod = importlib.import_module(module_path)
                        if hasattr(mod, "router"):
                            app.include_router(mod.router)
                            logger.info(f"  ✅ Module router loaded: {module_path}")
                    except Exception as exc:
                        logger.error(f"  ❌ Failed to load router {module_path}: {exc}")


# ── Singleton App Instance ────────────────────────────────────────────────────
app = create_app()


# ── Dev Server ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    uvicorn.run(
        "api.rest.main:app",
        host="0.0.0.0",
        port=8000,
        reload=os.getenv("CyberNexus_ENV", "production") == "development",
        log_level="info",
    )