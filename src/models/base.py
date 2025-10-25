"""Base models for CTI dataset."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class ConfidenceLevel(str, Enum):
    """Confidence levels for CTI data."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class DataSource(str, Enum):
    """Supported CTI data sources."""

    MITRE_ATTACK = "mitre-attack"
    ALIENVAULT_OTX = "alienvault-otx"
    MISP = "misp"
    ABUSE_CH = "abuse-ch"
    GITHUB_CTI = "github-cti"
    VIRUSTOTAL = "virustotal"
    MANUAL = "manual"
    SECURITY_REPORTS = "security-reports"
    SECURITY_BLOGS = "security-blogs"


class CTICategory(str, Enum):
    """CTI data categories."""

    MALWARE_ANALYSIS = "malware-analysis"
    IOC_INTELLIGENCE = "ioc-intelligence"
    THREAT_ACTOR_PROFILING = "threat-actor-profiling"
    ATTACK_PATTERN_RECOGNITION = "attack-pattern-recognition"
    VULNERABILITY_INTELLIGENCE = "vulnerability-intelligence"
    CAMPAIGN_ANALYSIS = "campaign-analysis"
    RELATIONSHIP_ANALYSIS = "relationship-analysis"
    KILL_CHAIN_MAPPING = "kill-chain-mapping"
    INDICATOR_ENRICHMENT = "indicator-enrichment"
    COMPARATIVE_ANALYSIS = "comparative-analysis"
    REPORT_ANALYSIS = "report-analysis"
    BLOG_ANALYSIS = "blog-analysis"


class InstructionExample(BaseModel):
    """Single instruction-tuning example."""

    instruction: str = Field(..., description="The task instruction")
    input: str = Field(..., description="The input context")
    output: str = Field(..., description="The expected output")
    metadata: "ExampleMetadata" = Field(..., description="Example metadata")

    class Config:
        json_schema_extra = {
            "example": {
                "instruction": "Analyze this malware hash and provide threat intelligence details.",
                "input": "Hash: MD5:5d41402abc4b2a76b9719d911017c592",
                "output": "This hash is associated with Poison Ivy, a remote access trojan...",
                "metadata": {
                    "source": "mitre-attack",
                    "category": "malware-analysis",
                    "confidence": "high",
                    "timestamp": "2025-01-01T00:00:00Z",
                },
            }
        }


class ExampleMetadata(BaseModel):
    """Metadata for instruction examples."""

    source: DataSource = Field(..., description="Data source")
    category: CTICategory = Field(..., description="Category")
    confidence: ConfidenceLevel = Field(..., description="Confidence level")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    tags: List[str] = Field(default_factory=list, description="Tags")
    mitre_attack_ids: List[str] = Field(default_factory=list, description="MITRE ATT&CK IDs")
    threat_actor: Optional[str] = Field(None, description="Associated threat actor")
    malware_family: Optional[str] = Field(None, description="Malware family")
    campaign: Optional[str] = Field(None, description="Campaign name")
    sector: Optional[str] = Field(None, description="Targeted sector")
    region: Optional[str] = Field(None, description="Targeted region")
    first_seen: Optional[datetime] = Field(None, description="First observation date")
    last_seen: Optional[datetime] = Field(None, description="Last observation date")
    raw_data_id: Optional[str] = Field(None, description="Reference to raw data")

    @field_validator("tags")
    @classmethod
    def lowercase_tags(cls, v: List[str]) -> List[str]:
        """Convert tags to lowercase."""
        return [tag.lower() for tag in v]


class RawCTIData(BaseModel):
    """Raw CTI data from source."""

    id: str = Field(..., description="Unique identifier")
    source: DataSource = Field(..., description="Data source")
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    data_type: str = Field(..., description="Type of CTI data")
    content: Dict[str, Any] = Field(..., description="Raw content")
    original_format: str = Field(..., description="Original format (stix, json, csv)")


class ProcessedCTIData(BaseModel):
    """Processed and normalized CTI data."""

    id: str = Field(..., description="Unique identifier")
    source: DataSource = Field(..., description="Data source")
    category: CTICategory = Field(..., description="Category")
    processed_at: datetime = Field(default_factory=datetime.utcnow)
    confidence: ConfidenceLevel = Field(..., description="Confidence level")
    entities: Dict[str, Any] = Field(..., description="Extracted entities")
    relationships: List[Dict[str, Any]] = Field(default_factory=list)
    raw_data_id: str = Field(..., description="Reference to raw data")


class DatasetStatistics(BaseModel):
    """Statistics for the dataset."""

    total_examples: int = 0
    by_category: Dict[CTICategory, int] = Field(default_factory=dict)
    by_source: Dict[DataSource, int] = Field(default_factory=dict)
    by_confidence: Dict[ConfidenceLevel, int] = Field(default_factory=dict)
    unique_threat_actors: int = 0
    unique_malware_families: int = 0
    unique_campaigns: int = 0
    date_range: Optional[Dict[str, datetime]] = None
    quality_metrics: Dict[str, float] = Field(default_factory=dict)
