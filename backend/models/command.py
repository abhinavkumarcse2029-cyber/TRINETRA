from typing import Any

from pydantic import BaseModel, Field


class CommandCreate(BaseModel):
    device_id: str = Field(
        ...,
        min_length=1
    )

    command: str = Field(
        ...,
        min_length=1
    )

    issued_by: str = "TRINETRA_DASHBOARD"


class CommandComplete(BaseModel):
    status: str = Field(
        ...,
        pattern="^(completed|failed)$"
    )

    response: dict[str, Any] = {}