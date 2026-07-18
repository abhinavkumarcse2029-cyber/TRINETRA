from pydantic import BaseModel, Field


class TelemetryCreate(BaseModel):
    device_id: str = Field(min_length=1)
    source_type: str = "simulator"
    message_rate: int = Field(default=0, ge=0)
    payload_size: int = Field(default=0, ge=0)
    failed_auth: int = Field(default=0, ge=0)
    command: str = "HEARTBEAT"
    destination: str | None = None
    cpu_usage: float = Field(default=0, ge=0, le=100)
    memory_usage: float = Field(default=0, ge=0, le=100)