"""Contract of POST /api/v1/nearby/analyze: the access points one scan of the nearby Wi-Fi networks saw (no BSSID:
the backend only sends the maker, when known). Unknown values stay null and are never filled in."""
from pydantic import Field

from app.schemas import InputModel


class AccessPoint(InputModel):
    ssid: str | None = Field(default=None, max_length=64)
    hidden: bool = False
    authentication: str | None = Field(default=None, pattern=r"^(OPEN|WEP|WPA|WPA2|WPA3|UNKNOWN)$")
    cipher: str | None = Field(default=None, max_length=20)
    channel: int | None = Field(default=None, ge=1, le=233)
    band: str | None = Field(default=None, pattern=r"^(2\.4|5|6)$")
    signal_percent: int | None = Field(default=None, ge=0, le=100)
    signal_dbm: int | None = Field(default=None, ge=-120, le=0)
    connected: bool = False
    vendor: str | None = Field(default=None, max_length=60)


class NearbyRequest(InputModel):
    access_points: list[AccessPoint] = Field(default_factory=list, max_length=300)
