import structlog
from fastapi import FastAPI

from app.api.alerts import router as alerts_router
from app.api.ingest import router as ingest_router


structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)

app = FastAPI(title="SOC Copilot", version="0.1.0")
app.include_router(ingest_router, prefix="/api/v1", tags=["ingest"])
app.include_router(alerts_router, prefix="/api/v1", tags=["alerts"])


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/")
async def root():
    return {"name": "SOC Copilot", "docs": "/docs"}
