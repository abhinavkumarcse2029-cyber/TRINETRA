
from fastapi import FastAPI

app = FastAPI(
    title="TRINETRA API",
    description="AI-powered cyber resilience backend",
    version="1.0.0",
)


@app.get("/")
def root():
    return {
        "project": "TRINETRA",
        "status": "running",
        "message": "Backend is working successfully",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
    }
