
# data_hypha.py
"""
Implementation of the Data Hypha for the Cloud Myco system.

Defines Pydantic models and helper functions to construct, sign,
and validate a Data Hypha.  A Data Hypha represents raw
environmental observations together with consent, provenance,
and jurisdictional metadata required for EU‑Article‑6 compliance.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ValidationError

# ---------------------------------------------------------------------------
# Shared models (re‑used by other hyphae)
# ---------------------------------------------------------------------------

class Signature(BaseModel):
    """Detached JWS signature."""
    type: str = Field(default="JwsSignature2020", alias="type")
    verificationMethod: str
    proofPurpose: str = Field(default="assertionMethod")
    jws: str

    class Config:
        allow_population_by_field_name = True


class Integrity(BaseModel):
    """Integrity metadata for a hypha."""
    hash: str
    cid: str
    signature: Signature


class Consent(BaseModel):
    """Consent and data‑use metadata."""
    lawfulBasis: str
    purpose: List[str]
    retention: str
    dataMinimization: bool


class Provenance(BaseModel):
    """Provenance metadata for a hypha."""
    wasGeneratedBy: str
    sourceRepo: str
    lineage: List[str]


class Status(BaseModel):
    """Status metadata for a hypha."""
    state: str
    revoked: bool
    reason: Optional[str] = None


class Observation(BaseModel):
    """A single environmental observation."""
    variable: str
    value: float
    unit: str
    u95: Optional[float] = None
    method: str
    timestamp: str
    location: Dict[str, Any]
    instrument: Dict[str, Any]
    operator: Dict[str, Any]


class Attachment(BaseModel):
    """Reference to an external attachment (e.g., raw file)."""
    role: str
    mediaType: str
    cid: str


class DataHypha(BaseModel):
    """Full representation of a Data Hypha."""
    context: List[str] = Field(alias="@context")
    id: str
    type: List[str]
    createdAt: str
    producer: Dict[str, Any]
    jurisdiction: str
    consent: Consent
    provenance: Provenance
    integrity: Integrity
    status: Status
    observations: List[Observation]
    attachments: Optional[List[Attachment]] = None

    class Config:
        allow_population_by_field_name = True


# ---------------------------------------------------------------------------
# Helper utilities (canonical JSON, ULID, signing)
# ---------------------------------------------------------------------------

def now_iso() -> str:
    """Current UTC time in ISO‑8601 with trailing ‘Z’."""
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_envelope(
    producer_id: str,
    jurisdiction: str,
    lawful_basis: str,
    purpose: List[str],
    retention: str,
    lineage: Optional[List[str]] = None,
    gen_by: str = "hypha-builder@0.1.0",
    source_repo: str = "gh:cloudmyco/hypha-builder",
) -> Dict[str, Any]:
    """
    Build the shared envelope for a Data Hypha.
    The ``id`` field is a placeholder (all zeros); it will be replaced
    by the real SHA‑256 hash after the payload is assembled.
    """
    placeholder_id = "0" * 64
    envelope = {
        "@context": ["https://cloudmyco.example/context.jsonld"],
        "id": placeholder_id,
        "type": ["DataHypha"],
        "createdAt": now_iso(),
        "producer": {"id": producer_id},
        "jurisdiction": jurisdiction,
        "consent": {
            "lawfulBasis": lawful_basis,
            "purpose": purpose,
            "retention": retention,
            "dataMinimization": True,
        },
        "provenance": {
            "wasGeneratedBy": gen_by,
            "sourceRepo": source_repo,
            "lineage": lineage or [],
        },
    }
    return envelope


def create_data_hypha(
    observations: List[Dict[str, Any]],
    attachments: Optional[List[Dict[str, Any]]] = None,
    *,
    producer_id: str = "did:key:example",
    jurisdiction: str = "EU",
    lawful_basis: str = "research-public-interest",
    purpose: Optional[List[str]] = None,
    retention: str = "P3Y",
    signer: Optional["Signer"] = None,
    verification_method: Optional[str] = None,
    lineage: Optional[List[str]] = None,
) -> DataHypha:
    """
    Construct, sign and return a Data Hypha.
    """
    if purpose is None:
        purpose = ["MRV", "market-verification"]

    # 1️⃣ Build envelope (with placeholder id)
    envelope = build_envelope(
        producer_id=producer_id,
        jurisdiction=jurisdiction,
        lawful_basis=lawful_basis,
        purpose=purpose,
        retention=retention,
        lineage=lineage,
    )

    # 2️⃣ Assemble payload (observations + optional attachments)
    spore_dict = dict(envelope)
    spore_dict["observations"] = observations
    if attachments:
        spore_dict["attachments"] = attachments

    # 3️⃣ Compute hash & CID over the *current* payload
    payload_bytes = canonical_json(spore_dict).encode("utf-8")
    h = hashlib.sha256(payload_bytes).hexdigest()
    cid = f"cid-{h}"

    # 4️⃣ Replace placeholder id with the real hash (now conforms to schema)
    spore_dict["id"] = h

    # 5️⃣ Prepare signer (create one if none supplied)
    if signer is None:
        from spore_sdk import Signer  # local import to avoid circular deps
        signer = Signer()

    # 6️⃣ Determine verification method (defaults to producer#key‑1)
    if verification_method is None:
        verification_method = f"{producer_id}#key-1"

    # 7️⃣ Sign the *final* payload (includes the real id)
    final_payload = canonical_json(spore_dict).encode("utf-8")
    sig = signer.sign(final_payload)
    jws = base64.urlsafe_b64encode(sig).decode().rstrip("=")

    # 8️⃣ Populate integrity and status blocks
    spore_dict["integrity"] = {
        "hash": f"sha256-{h}",
        "cid": cid,
        "signature": {
            "type": "JwsSignature2020",
            "verificationMethod": verification_method,
            "proofPurpose": "assertionMethod",
            "jws": jws,
        },
    }
    spore_dict["status"] = {
        "state": "active",
        "revoked": False,
        "reason": None,
    }

    # 9️⃣ Return a validated DataHypha instance
    return DataHypha(**spore_dict)


def validate_data_hypha(hypha: DataHypha) -> List[str]:
    """
    Additional domain‑specific checks beyond Pydantic validation.
    Returns a list of issue codes; an empty list means “all good”.
    """
    issues: List[str] = []

    for i, obs in enumerate(hypha.observations):
        # ISO‑8601 timestamp?
        try:
            dt.datetime.fromisoformat(obs.timestamp.replace("Z", "+00:00"))
        except Exception:
            issues.append(f"obs[{i}]:timestamp_not_iso")

        # Non‑negative uncertainty?
        if obs.u95 is not None and obs.u95 < 0:
            issues.append(f"obs[{i}]:u95_negative")

        # Unit must be present
        if not obs.unit:
            issues.append(f"obs[{i}]:unit_empty")

        # Mandatory fields
        mandatory = ["variable", "value", "method", "location", "instrument", "operator"]
        for field in mandatory:
            if getattr(obs, field) is None:
                issues.append(f"obs[{i}]:missing_{field}")

    # Data‑minimisation flag must be true
    if not hypha.consent.dataMinimization:
        issues.append("consent:data_minimization_false")

    return issues
