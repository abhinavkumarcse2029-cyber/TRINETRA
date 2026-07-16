from fastapi import FastAPI

app = FastAPI(
    title="TRINETRA AI",
    version="1.0.0"
)


@app.get("/")
def home():
    return {
        "project": "TRINETRA AI",
        "status": "Backend Running"
    }
