from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.devices import router as devices_router

app = FastAPI(
    title="TRINETRA API",
    description="AI-powered cyber resilience platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)

app.include_router(
    devices_router,
    prefix="/devices",
    tags=["Devices"]
)


@app.get("/")
def root():
    return {
        "project": "TRINETRA",
        "status": "running",
        "message": "TRINETRA backend is operational"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }
