"""Contract of POST /api/v1/channel/recommend (JSON in camelCase, like the rest of the service)."""
from pydantic import Field

from app.schemas import CamelModel, InputModel


class ChannelCount(InputModel):
    """How many neighbouring access points (not counting the user's own network) the agent saw on one channel."""
    channel: int = Field(ge=1, le=233)
    networks: int = Field(ge=0, le=500)


class ChannelRequest(InputModel):
    """What the WiFiSense agent saw around the user's router. Without channel counts there is nothing to compare."""
    band: str | None = Field(default=None, pattern=r"^(2\.4|5|6)$", description="GHz band of the connection")
    channel: int | None = Field(default=None, ge=1, le=233, description="Channel the router uses now")
    channel_counts: list[ChannelCount] = Field(default_factory=list, max_length=60)


class ChannelOption(CamelModel):
    channel: int
    networks: int = Field(ge=0, description="Neighbouring access points on exactly this channel")
    load: float = Field(ge=0, description="Interference: neighbours on this channel plus the overlapping ones")


class ChannelResponse(CamelModel):
    band: str | None
    current_channel: int | None
    current_load: float | None
    recommended_channel: int | None
    recommended_load: float | None
    should_change: bool
    summary: str
    action: str | None
    options: list[ChannelOption]
    model_version: str
