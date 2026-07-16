from fastapi import FastAPI, HTTPException

from services.database import supabase

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
    return {"status": "healthy"}


@app.get("/devices")
def get_devices():
    try:
        response = supabase.table("devices").select("*").execute()
        return {"devices": response.data}
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))
