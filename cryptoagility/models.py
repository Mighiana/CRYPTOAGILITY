"""Stable evidence contracts shared by discovery, policy and lab modules."""

from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = "1.0"


@dataclass
class Asset:
    asset_id: str
    asset_type: str
    source: str
    algorithm_family: str = "unknown"
    algorithm: str = "unknown"
    key_size: int | None = None
    parameter_set: str | None = None
    signature_algorithm: str | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    negotiated_group: str | None = None
    certificate_subject: str | None = None
    issuer: str | None = None
    expiry: str | None = None
    sans: list[str] = field(default_factory=list)
    chain_length: int | None = None
    migration_status: str = "UNKNOWN"
    policy_result: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Inventory:
    assets: list[Asset] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Inventory":
        if data.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("Unsupported inventory schema version")
        assets = [Asset(**asset) for asset in data["assets"]]
        return cls(assets=assets, errors=data.get("errors", []))
