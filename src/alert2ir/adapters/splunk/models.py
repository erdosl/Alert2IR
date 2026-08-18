"""Bounded, versioned input values for the Splunk source boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import re
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    field_validator,
    model_validator,
)

from alert2ir.core.models import CanonicalAlert


SPLUNK_FINDING_SCHEMA = "alert2ir.splunk-finding.v1"

RULE_TITLE_MAX_LENGTH = 256
HOSTNAME_MAX_LENGTH = 255
CHANNEL_MAX_LENGTH = 128
SOURCE_MAX_LENGTH = 512
SOURCETYPE_MAX_LENGTH = 128
PROCESS_GUID_MAX_LENGTH = 128
IMAGE_MAX_LENGTH = 1024
PARENT_IMAGE_MAX_LENGTH = 1024
TARGET_FILENAME_MAX_LENGTH = 1024
TIMESTAMP_STRING_MAX_LENGTH = 64
EVIDENCE_REFERENCE_MAX_LENGTH = 1024

EVENT_CODE_MAXIMUM = 65_535
RECORD_ID_MAXIMUM = 2**63 - 1


RuleTitle = Annotated[
    StrictStr, Field(min_length=1, max_length=RULE_TITLE_MAX_LENGTH)
]
Hostname = Annotated[
    StrictStr, Field(min_length=1, max_length=HOSTNAME_MAX_LENGTH)
]
Channel = Annotated[StrictStr, Field(min_length=1, max_length=CHANNEL_MAX_LENGTH)]
SplunkSource = Annotated[
    StrictStr, Field(min_length=1, max_length=SOURCE_MAX_LENGTH)
]
SplunkSourcetype = Annotated[
    StrictStr, Field(min_length=1, max_length=SOURCETYPE_MAX_LENGTH)
]
ProcessGuid = Annotated[
    StrictStr, Field(min_length=1, max_length=PROCESS_GUID_MAX_LENGTH)
]
ImagePath = Annotated[
    StrictStr, Field(min_length=1, max_length=IMAGE_MAX_LENGTH)
]
ParentImagePath = Annotated[
    StrictStr, Field(min_length=1, max_length=PARENT_IMAGE_MAX_LENGTH)
]
TargetFilename = Annotated[
    StrictStr, Field(min_length=1, max_length=TARGET_FILENAME_MAX_LENGTH)
]


class SigmaLevel(StrEnum):
    """The complete Sigma level vocabulary accepted by mapping version 1."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _require_nonblank(value: str, field_name: str) -> str:
    if not value.strip():
        raise ValueError(f"{field_name} must be non-empty")
    return value


def _parse_positive_integer(
    value: object,
    *,
    field_name: str,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{field_name} must be a decimal integer")
    if isinstance(value, str):
        if re.fullmatch(r"[0-9]+", value) is None:
            raise ValueError(f"{field_name} must be a decimal integer")
        parsed = int(value)
    else:
        parsed = value
    if parsed < 1 or parsed > maximum:
        raise ValueError(f"{field_name} is outside the supported range")
    return parsed


class SplunkDetectionMetadata(BaseModel):
    """Reviewed Sigma metadata; it is not sourced from an event row."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    rule_title: RuleTitle
    sigma_level: SigmaLevel

    @field_validator("rule_id", mode="before")
    @classmethod
    def validate_rule_id(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("rule_id must be a UUID string")
        try:
            return str(UUID(value))
        except (ValueError, AttributeError) as error:
            raise ValueError("rule_id must be a valid UUID") from error

    @field_validator("rule_title")
    @classmethod
    def validate_rule_title(cls, value: str) -> str:
        return _require_nonblank(value, "rule_title")

    @field_validator("sigma_level", mode="before")
    @classmethod
    def validate_sigma_level(cls, value: object) -> object:
        if not isinstance(value, str):
            raise ValueError("sigma_level must be a string")
        return value


TimestampInput = str | int | float | datetime


class SplunkEvent(BaseModel):
    """A bounded subset of a Splunk Windows event search result.

    Splunk searches commonly add result-table columns. Version 1 intentionally
    ignores event-level extras while the outer envelope and reviewed detection
    metadata forbid extras. Ignored values are neither stored nor forwarded.
    """

    model_config = ConfigDict(
        extra="ignore",
        frozen=True,
        populate_by_name=True,
    )

    detected_at: TimestampInput = Field(alias="_time")
    computer: Hostname | None = Field(default=None, alias="Computer")
    host: Hostname | None = None
    channel: Channel
    source: SplunkSource | None = None
    sourcetype: SplunkSourcetype | None = None
    event_code: int = Field(alias="EventCode", ge=1, le=EVENT_CODE_MAXIMUM)
    record_id: int = Field(alias="RecordID", ge=1, le=RECORD_ID_MAXIMUM)
    process_guid: ProcessGuid | None = Field(default=None, alias="ProcessGuid")
    image: ImagePath | None = Field(default=None, alias="Image")
    parent_image: ParentImagePath | None = Field(default=None, alias="ParentImage")
    target_filename: TargetFilename | None = Field(
        default=None,
        alias="TargetFilename",
    )

    @field_validator("detected_at", mode="before")
    @classmethod
    def validate_detected_at_shape(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(
            value,
            (str, int, float, datetime),
        ):
            raise ValueError("_time must be an RFC3339 string or Unix epoch")
        if isinstance(value, str) and len(value) > TIMESTAMP_STRING_MAX_LENGTH:
            raise ValueError("_time exceeds the supported length")
        return value

    @field_validator("event_code", mode="before")
    @classmethod
    def validate_event_code(cls, value: object) -> int:
        return _parse_positive_integer(
            value,
            field_name="EventCode",
            maximum=EVENT_CODE_MAXIMUM,
        )

    @field_validator("record_id", mode="before")
    @classmethod
    def validate_record_id(cls, value: object) -> int:
        return _parse_positive_integer(
            value,
            field_name="RecordID",
            maximum=RECORD_ID_MAXIMUM,
        )

    @field_validator(
        "computer",
        "host",
        "channel",
        "source",
        "sourcetype",
        "process_guid",
        "image",
        "parent_image",
        "target_filename",
    )
    @classmethod
    def validate_nonblank_strings(cls, value: str | None) -> str | None:
        if value is not None:
            _require_nonblank(value, "event value")
        return value

    @field_validator("channel")
    @classmethod
    def validate_channel(cls, value: str) -> str:
        if value != value.strip() or not value.isascii() or not value.isprintable():
            raise ValueError("channel must be an unpadded printable ASCII value")
        return value

    @model_validator(mode="after")
    def validate_hostname_present(self) -> SplunkEvent:
        if self.computer is None and self.host is None:
            raise ValueError("Computer or host is required")
        return self


class SplunkFinding(BaseModel):
    """Versioned Splunk finding envelope accepted by the pure mapper."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["alert2ir.splunk-finding.v1"] = Field(alias="schema")
    detection: SplunkDetectionMetadata
    event: SplunkEvent


@dataclass(frozen=True, slots=True)
class NormalizedSplunkFinding:
    """All source values after deterministic version-1 normalization."""

    rule_id: str
    rule_title: str
    sigma_level: SigmaLevel
    detected_at: datetime
    computer: str
    channel: str
    event_code: int
    record_id: int
    source: str | None
    sourcetype: str | None
    process_guid: str | None
    image: str | None
    parent_image: str | None
    target_filename: str | None


@dataclass(frozen=True, slots=True)
class CanonicalizedSplunkFinding:
    """The transport-independent output needed by a future delivery layer."""

    alert: CanonicalAlert
    idempotency_key: str
