from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.devices import router as devices_router
from api.telemetry import router as telemetry_router
from api.dashboard import router as dashboard_router
from api.alerts import router as alerts_router
from api.incidents import router as incidents_router
from api.audit_logs import router as audit_logs_router
from api.threat_detection import router as threat_detection_router
from api.commands import router as commands_router


app = FastAPI(
    title="TRINETRA API",
    description=(
        "AI-powered Cyber Resilience Platform "
        "for Critical Infrastructure"
    ),
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)

# -----------------------------
# API Routes
# -----------------------------

app.include_router(
    devices_router,
    prefix="/devices",
    tags=["Devices"]
)

app.include_router(
    telemetry_router,
    prefix="/telemetry",
    tags=["Telemetry"]
)

app.include_router(
    dashboard_router,
    prefix="/dashboard",
    tags=["Dashboard"]
)

app.include_router(
    alerts_router,
    prefix="/alerts",
    tags=["Alerts"]
)

app.include_router(
    incidents_router,
    prefix="/incidents",
    tags=["Incidents"]
)

app.include_router(
    audit_logs_router,
    prefix="/audit-logs",
    tags=["Audit Logs"]
)

app.include_router(
    threat_detection_router,
    prefix="/threat-detection",
    tags=["Threat Detection"]
)

app.include_router(
    commands_router,
    prefix="/commands",
    tags=["Commands"]
)

# -----------------------------
# Root Endpoint
# -----------------------------

@app.get("/")
def root():
    return {
        "project": "TRINETRA",
        "version": "1.0.0",
        "status": "running",
        "message": "TRINETRA backend is operational"
    }


# -----------------------------
# Health Check
# -----------------------------

@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }