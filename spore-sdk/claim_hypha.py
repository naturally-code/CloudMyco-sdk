 # claim_hypha.py
"""
Implementation of the Claim Hypha for the Cloud Myco system.

Transforms one or more Data Hyphae into a verifiable claim,
capturing impact (e.g., carbon removal) together with supporting
evidence.  The module follows the same envelope / integrity pattern
as the Data Hypha.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ValidationError

# Re‑use the shared models from data_hypha.py
from data_hypha import Consent, Provenance, Integrity, Status, Signature

# ---------------------------------------------------------------------------
# Claim‑specific models
# ---------------------------------------------------------------------------

class Evidence(BaseModel):
    """Reference to supporting material (e.g., notebook, PDF)."""
    kind: str
    cid: str
    hash: str


class ClaimHypha(BaseModel):
    """Full representation of a Claim Hypha."""
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
    derivedFrom: List[str]
    assertion: str
    # NOTE: The official schema does NOT include a free‑form `statement`
    # field.  If you need extra description, store it in `metadata`
    # or embed it in `assertion`.
    value: float
    unit: str
    confidence: float
    verifier: Dict[str, Any]
    evidence: Optional[List[Evidence]] = None
    parameters: Optional[Dict[str, Any]] = None

    class Config:
        allow_population_by_field_name = True


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def now_iso() -> str:
    """Current UTC time in ISO‑8601 with trailing ‘Z’."""
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_claim_envelope(
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
    Build the shared envelope for a Claim Hypha.
    The ``id`` is a placeholder that will be replaced by the real hash.
    """
    placeholder_id = "0" * 64
    envelope = {
        "@context": ["https://cloudmyco.example/context.jsonld"],
        "id": placeholder_id,
        "type": ["ClaimHypha"],
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


def create_claim_hypha(
    *,
    derived_from: List[str],
    assertion: str,
    value: float,
    unit: str,
    confidence: float,
    verifier_id: str,
    verifier_method: str,
    evidence: Optional[List[Dict[str, Any]]] = None,
    parameters: Optional[Dict[str, Any]] = None,
    producer_id: str = "did:key:example",
    jurisdiction: str = "EU",
    lawful_basis: str = "research-public-interest",
    purpose: Optional[List[str]] = None,
    retention: str = "P3Y",
    signer: Optional["Signer"] = None,
    verification_method: Optional[str] = None,
    lineage: Optional[List[str]] = None,
) -> ClaimHypha:
    """
    Construct, sign and return a Claim Hypha.
    """
    if purpose is None:
        purpose = ["MRV", "market-verification"]

    if not derived_from:
        raise ValueError("derived_from list cannot be empty")
    if not (0.0 <= confidence <= 1.0):
        raise ValueError("confidence must be between 0 and 1")

    # 1️⃣ Build envelope (placeholder id)
    envelope = build_claim_envelope(
        producer_id=producer_id,
        jurisdiction=jurisdiction,
        lawful_basis=lawful_basis,
        purpose=purpose,
        retention=retention,
        lineage=lineage,
    )

    # 2️⃣ Assemble payload
    spore_dict = dict(envelope)
    spore_dict["derivedFrom"] = derived_from
    spore_dict["assertion"] = assertion
    spore_dict["value"] = value
    spore_dict["unit"] = unit
    spore_dict["confidence"] = confidence
    spore_dict["verifier"] = {"id": verifier_id, "method": verifier_method}
    if evidence:
        spore_dict["evidence"] = evidence
    if parameters:
        spore_dict["parameters"] = parameters

    # 3️⃣ Compute hash & CID over current payload
    payload_bytes = canonical_json(spore_dict).encode("utf-8")
    h = hashlib.sha256(payload_bytes).hexdigest()
    cid = f"cid-{h}"

    # 4️⃣ Replace placeholder id with real hash
    spore_dict["id"] = h

    # 5️⃣ Prepare signer
    if signer is None:
        from spore_sdk import Signer
        signer = Signer()

    # 6️⃣ Verification method (default to producer#key‑1)
    if verification_method is None:
        verification_method = f"{producer_id}#key-1"

    # 7️⃣ Sign the final payload (includes real id)
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

    # 9️⃣ Return a validated ClaimHypha instance
    return ClaimHypha(**spore_dict)


def validate_claim_hypha(hypha: ClaimHypha) -> List[str]:
    """
    Domain‑specific validation for a Claim Hypha.
    Returns a list of issue codes; empty list → no issues.
    """
    issues: List[str] = []

    if not hypha.derivedFrom:
        issues.append("derivedFrom_empty")
    if not (0.0 <= hypha.confidence <= 1.0):
        issues.append("confidence_out_of_range")
    if not hypha.unit:
        issues.append("unit_empty")

    if hypha.evidence:
        for i, ev in enumerate(hypha.evidence):
            if not ev.kind:
                issues.append(f"evidence[{i}]:kind_empty")
            if not ev.cid:
                issues.append(f"evidence[{i}]:cid_empty")
            if not ev.hash:
                issues.append(f"evidence[{i}]:hash_empty")

    return issues
