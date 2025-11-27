from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
import re

class NormalizedCVE(BaseModel):
    cve_id: str

    @field_validator('cve_id')
    @classmethod
    def validate_cve_id(cls, v: str) -> str:
        if not re.match(r'^CVE-\d{4}-\d{4,}$', v):
            raise ValueError(f"Invalid CVE ID format: {v}")
        return v

    title: Optional[str] = None
    description: Optional[str] = None

    severity: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    cvss_v3_score: Optional[float] = None

    publish_date: Optional[datetime] = None
    update_date: Optional[datetime] = None

    vendors: List[str] = Field(default_factory=list)
    products: List[str] = Field(default_factory=list)

    references: List[str] = Field(default_factory=list)

    cwe_ids: Optional[List[str]] = None
    attack_vector: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    is_in_kev: Optional[bool] = None
    exploit_exists: Optional[bool] = None

    poc_sources: Optional[List[str]] = None
    poc_repo_count: Optional[int] = None
    poc_risk_label: Optional[str] = None
    feed_version: Optional[str] = None

    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None

    extra: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
