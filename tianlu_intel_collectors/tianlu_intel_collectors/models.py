from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class NormalizedCVE(BaseModel):
    cve_id: str

    title: Optional[str] = None
    description: Optional[str] = None

    severity: Optional[str] = None  # "LOW" / "MEDIUM" / "HIGH" / "CRITICAL" / None
    cvss_v2_score: Optional[float] = None
    cvss_v3_score: Optional[float] = None

    publish_date: Optional[datetime] = None
    update_date: Optional[datetime] = None

    vendors: List[str] = Field(default_factory=list)
    products: List[str] = Field(default_factory=list)

    references: List[str] = Field(default_factory=list)

    # v0.2 fields
    cwe_ids: Optional[List[str]] = None
    attack_vector: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    is_in_kev: Optional[bool] = None
    exploit_exists: Optional[bool] = None

    # v0.5 fields
    poc_sources: Optional[List[str]] = None
    poc_repo_count: Optional[int] = None
    poc_risk_label: Optional[str] = None
    feed_version: Optional[str] = None

    # Source specific extra data
    extra: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
