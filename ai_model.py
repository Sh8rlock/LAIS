"""
LAIS - Linux AI Security Toolkit
Data models for AI assets, findings, risk scores, and assessment results.
Author: Larry Odeyemi
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum
from datetime import datetime
import json


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class FindingStatus(Enum):
    VULNERABLE = "vulnerable"
    WARNING = "warning"
    PASS = "pass"
    NOT_APPLICABLE = "n/a"


class AIAssetType(Enum):
    LLM_CHATBOT = "llm_chatbot"
    LLM_AGENT = "llm_agent"
    ML_MODEL = "ml_model"
    AI_ASSISTANT = "ai_assistant"
    PREDICTIVE_MAINTENANCE = "predictive_maintenance"
    ANOMALY_DETECTION = "anomaly_detection"


class OWASPCategory(Enum):
    LLM01 = "LLM01: Prompt Injection"
    LLM02 = "LLM02: Sensitive Information Disclosure"
    LLM03 = "LLM03: Supply Chain"
    LLM04 = "LLM04: Data and Model Poisoning"
    LLM05 = "LLM05: Improper Output Handling"
    LLM06 = "LLM06: Excessive Agency"
    LLM07 = "LLM07: System Prompt Leakage"
    LLM08 = "LLM08: Vector and Embedding Weaknesses"
    LLM09 = "LLM09: Misinformation"
    LLM10 = "LLM10: Unbounded Consumption"


class NISTFunction(Enum):
    GOVERN = "govern"
    MAP = "map"
    MEASURE = "measure"
    MANAGE = "manage"


@dataclass
class AIAsset:
    """An AI/ML system being assessed."""
    id: str
    name: str
    asset_type: AIAssetType
    description: str
    model_provider: str = ""
    deployment_env: str = "enterprise"
    has_tool_access: bool = False
    has_data_access: bool = False
    has_internet_access: bool = False
    is_customer_facing: bool = False
    is_safety_critical: bool = False
    integrations: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    access_controls: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "asset_type": self.asset_type.value,
            "description": self.description,
            "model_provider": self.model_provider,
            "deployment_env": self.deployment_env,
            "has_tool_access": self.has_tool_access,
            "has_data_access": self.has_data_access,
            "has_internet_access": self.has_internet_access,
            "is_customer_facing": self.is_customer_facing,
            "is_safety_critical": self.is_safety_critical,
            "integrations": self.integrations,
            "data_sources": self.data_sources,
        }


@dataclass
class PromptAttackResult:
    """Result of a single prompt injection test."""
    attack_id: str
    attack_name: str
    category: str
    owasp_id: str
    severity: Severity
    payload: str
    simulated_response: str
    success: bool
    risk_score: int  # 0-100
    details: str = ""
    mitigations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "attack_id": self.attack_id,
            "attack_name": self.attack_name,
            "category": self.category,
            "owasp_id": self.owasp_id,
            "severity": self.severity.value,
            "payload_preview": self.payload[:120] + "..." if len(self.payload) > 120 else self.payload,
            "success": self.success,
            "risk_score": self.risk_score,
            "details": self.details,
            "mitigations": self.mitigations,
        }


@dataclass
class ShadowAIFinding:
    """A detected shadow AI usage instance."""
    id: str
    finding_type: str
    service_name: str
    severity: Severity
    data_exposure_risk: str
    description: str
    evidence: str
    source_ip: str = ""
    user: str = ""
    risk_score: int = 0
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "finding_type": self.finding_type,
            "service_name": self.service_name,
            "severity": self.severity.value,
            "data_exposure_risk": self.data_exposure_risk,
            "description": self.description,
            "evidence": self.evidence,
            "source_ip": self.source_ip,
            "user": self.user,
            "risk_score": self.risk_score,
            "recommendation": self.recommendation,
        }


@dataclass
class OWASPFinding:
    """Assessment finding for one OWASP Top 10 for LLMs category."""
    category: OWASPCategory
    status: FindingStatus
    severity: Severity
    risk_score: int  # 0-100
    description: str
    evidence: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    sub_findings: List[Dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "status": self.status.value,
            "severity": self.severity.value,
            "risk_score": self.risk_score,
            "description": self.description,
            "evidence": self.evidence,
            "mitigations": self.mitigations,
            "sub_findings": self.sub_findings,
        }

    @property
    def status_icon(self) -> str:
        icons = {
            FindingStatus.VULNERABLE: "\u274c",
            FindingStatus.WARNING: "\u26a0\ufe0f",
            FindingStatus.PASS: "\u2705",
            FindingStatus.NOT_APPLICABLE: "\u2796",
        }
        return icons.get(self.status, "?")


@dataclass
class NISTControl:
    """Assessment of a single NIST AI RMF control."""
    id: str
    function: NISTFunction
    name: str
    description: str
    status: FindingStatus
    maturity_level: int  # 0-4
    evidence: str = ""
    gap: str = ""
    recommendation: str = ""
    is_ot_specific: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "function": self.function.value,
            "name": self.name,
            "status": self.status.value,
            "maturity_level": self.maturity_level,
            "evidence": self.evidence,
            "gap": self.gap,
            "recommendation": self.recommendation,
            "is_ot_specific": self.is_ot_specific,
        }


@dataclass
class NISTAssessment:
    """NIST AI RMF assessment results per function."""
    function: NISTFunction
    controls: List[NISTControl] = field(default_factory=list)
    score: float = 0.0
    maturity: str = ""

    def calculate_score(self):
        if not self.controls:
            self.score = 0.0
            self.maturity = "Not Assessed"
            return
        total = sum(c.maturity_level for c in self.controls)
        max_total = len(self.controls) * 4
        self.score = round((total / max_total) * 100, 1) if max_total > 0 else 0.0
        if self.score >= 80:
            self.maturity = "Optimized"
        elif self.score >= 60:
            self.maturity = "Managed"
        elif self.score >= 40:
            self.maturity = "Defined"
        elif self.score >= 20:
            self.maturity = "Initial"
        else:
            self.maturity = "Ad Hoc"

    def to_dict(self) -> dict:
        return {
            "function": self.function.value,
            "score": self.score,
            "maturity": self.maturity,
            "controls": [c.to_dict() for c in self.controls],
        }


@dataclass
class AIEnvironment:
    """A complete AI deployment environment to assess."""
    id: str
    name: str
    description: str
    organization: str
    environment_type: str  # "enterprise", "soc", "ot_ics"
    assets: List[AIAsset] = field(default_factory=list)
    governance_policies: Dict = field(default_factory=dict)
    shadow_ai_indicators: List[Dict] = field(default_factory=list)
    network_traffic: List[Dict] = field(default_factory=list)
    nist_controls: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "organization": self.organization,
            "environment_type": self.environment_type,
            "assets": [a.to_dict() for a in self.assets],
            "asset_count": len(self.assets),
        }


@dataclass
class AssessmentReport:
    """Complete LAIS assessment report."""
    title: str
    environment: Optional[AIEnvironment] = None
    generated_at: str = ""
    prompt_attack_results: List[PromptAttackResult] = field(default_factory=list)
    shadow_ai_findings: List[ShadowAIFinding] = field(default_factory=list)
    owasp_findings: List[OWASPFinding] = field(default_factory=list)
    nist_assessments: List[NISTAssessment] = field(default_factory=list)
    overall_risk_score: float = 0.0
    overall_grade: str = ""
    ot_ics_findings: List[Dict] = field(default_factory=list)

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def calculate_overall(self):
        scores = []
        if self.prompt_attack_results:
            vuln_count = sum(1 for r in self.prompt_attack_results if r.success)
            total = len(self.prompt_attack_results)
            scores.append(max(0, 100 - (vuln_count / total * 100)) if total else 100)
        if self.owasp_findings:
            vuln_count = sum(1 for f in self.owasp_findings if f.status == FindingStatus.VULNERABLE)
            total = sum(1 for f in self.owasp_findings if f.status != FindingStatus.NOT_APPLICABLE)
            scores.append(max(0, 100 - (vuln_count / total * 100)) if total else 100)
        if self.nist_assessments:
            nist_avg = sum(a.score for a in self.nist_assessments) / len(self.nist_assessments)
            scores.append(nist_avg)
        if self.shadow_ai_findings:
            critical_count = sum(1 for f in self.shadow_ai_findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
            penalty = min(30, critical_count * 10)
            scores.append(max(0, 100 - penalty))

        self.overall_risk_score = round(sum(scores) / len(scores), 1) if scores else 0.0

        if self.overall_risk_score >= 85:
            self.overall_grade = "A"
        elif self.overall_risk_score >= 70:
            self.overall_grade = "B"
        elif self.overall_risk_score >= 55:
            self.overall_grade = "C"
        elif self.overall_risk_score >= 40:
            self.overall_grade = "D"
        else:
            self.overall_grade = "F"

    @property
    def grade_label(self) -> str:
        labels = {"A": "Strong", "B": "Adequate", "C": "Needs Improvement", "D": "Weak", "F": "Critical Risk"}
        return labels.get(self.overall_grade, "Unknown")

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "generated_at": self.generated_at,
            "environment": self.environment.to_dict() if self.environment else None,
            "overall_risk_score": self.overall_risk_score,
            "overall_grade": self.overall_grade,
            "grade_label": self.grade_label,
            "prompt_attacks": [r.to_dict() for r in self.prompt_attack_results],
            "shadow_ai": [f.to_dict() for f in self.shadow_ai_findings],
            "owasp": [f.to_dict() for f in self.owasp_findings],
            "nist": [a.to_dict() for a in self.nist_assessments],
            "ot_ics_findings": self.ot_ics_findings,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
