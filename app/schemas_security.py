"""Contract of POST /api/v1/security/assess (JSON in camelCase, like the rest of the service)."""
from enum import Enum

from pydantic import Field, field_validator

from app.schemas import CamelModel, InputModel


class Authentication(str, Enum):
    OPEN = "OPEN"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA3 = "WPA3"
    UNKNOWN = "UNKNOWN"


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class SecurityGrade(str, Enum):
    SECURE = "SECURE"
    ACCEPTABLE = "ACCEPTABLE"
    AT_RISK = "AT_RISK"
    CRITICAL = "CRITICAL"


class SecurityRequest(InputModel):
    """What the WiFiSense agent saw on the user's network. Every field is optional: the agent reports what it could read."""
    authentication: Authentication = Authentication.UNKNOWN
    cipher: str | None = Field(default=None, max_length=20, description="CCMP, GCMP, TKIP...")
    open_ports: list[int] = Field(default_factory=list, max_length=64,
                                  description="TCP ports that answered on the router (gateway)")
    device_count: int | None = Field(default=None, ge=0, le=1024)
    new_device_count: int | None = Field(default=None, ge=0, le=1024)
    band: str | None = Field(default=None, pattern=r"^(2\.4|5|6)$", description="GHz band of the connection")
    channel: int | None = Field(default=None, ge=1, le=233)
    neighbors_same_channel: int | None = Field(default=None, ge=0, le=500)

    @field_validator("open_ports")
    @classmethod
    def valid_ports(cls, ports: list[int]) -> list[int]:
        if any(not 1 <= port <= 65535 for port in ports):
            raise ValueError("ports must be between 1 and 65535")
        return sorted(set(ports))


class SecurityFinding(CamelModel):
    code: str
    severity: FindingSeverity
    title: str
    detail: str
    action: str
    penalty: int = Field(ge=0, le=100)


class SecurityResponse(CamelModel):
    score: int = Field(ge=0, le=100)
    grade: SecurityGrade
    grade_label: str
    summary: str
    findings: list[SecurityFinding]
    model_version: str
