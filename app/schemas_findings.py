"""What the AI answers about a capture or a scan: facts (measured) apart from inferences (possible explanations, each
with its confidence), plus how uncertain the whole reading is. The backend stores them apart and never shows an
inference as a fact; it refuses an inference without a confidence and never lets one be CRITICAL."""
from enum import Enum

from pydantic import Field, field_validator

from app.schemas import CamelModel

CODE = r"^[A-Z][A-Z0-9_]{2,31}$"


class Level(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class Fact(CamelModel):
    """Something counted in the data (no guessing). CRITICAL is kept for facts."""
    code: str = Field(pattern=CODE)
    severity: Level = Level.INFO
    title: str = Field(min_length=1, max_length=120)
    evidence: str = Field(min_length=1, max_length=300, description="The numbers that show it")
    recommendation: str | None = Field(default=None, max_length=300)


class Inference(CamelModel):
    """A possible explanation of the facts, never a certainty: never CRITICAL, never "this device is malicious"."""
    code: str = Field(pattern=CODE)
    severity: Level = Level.INFO
    title: str = Field(min_length=1, max_length=120)
    evidence: str = Field(min_length=1, max_length=300)
    recommendation: str | None = Field(default=None, max_length=300, description="A defensive, verifiable action")
    confidence: float = Field(ge=0, le=1)

    @field_validator("severity")
    @classmethod
    def never_critical(cls, value: Level) -> Level:
        return Level.WARNING if value == Level.CRITICAL else value


class FindingsResponse(CamelModel):
    facts: list[Fact]
    inferences: list[Inference]
    uncertainty: str = Field(description="What limits the whole reading (sample size, what the tool cannot see)")
    model_version: str
