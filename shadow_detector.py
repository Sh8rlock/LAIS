"""
LAIS - Linux AI Security Toolkit
Shadow AI Detector: Detects unauthorized AI/LLM usage across the organization.
Author: Larry Odeyemi

Scans network traffic patterns, endpoint processes, and data flows to identify
shadow AI services employees are using without IT/security approval.
"""

from typing import List, Dict
from ai_model import (
    AIEnvironment, ShadowAIFinding, Severity
)


class ShadowAIDetector:
    """Detects unauthorized AI service usage in the environment."""

    def __init__(self):
        self.known_ai_services = self._build_service_signatures()

    def scan(self, environment: AIEnvironment, verbose: bool = False) -> List[ShadowAIFinding]:
        """Scan an environment for shadow AI usage."""
        findings = []
        counter = 0

        # Check network traffic indicators
        for indicator in environment.shadow_ai_indicators:
            matches = self._match_indicator(indicator)
            for match in matches:
                counter += 1
                finding = ShadowAIFinding(
                    id="SAI-{:03d}".format(counter),
                    finding_type=match["type"],
                    service_name=match["service"],
                    severity=match["severity"],
                    data_exposure_risk=match["data_risk"],
                    description=match["description"],
                    evidence=indicator.get("evidence", "Network traffic analysis"),
                    source_ip=indicator.get("source_ip", ""),
                    user=indicator.get("user", ""),
                    risk_score=match["risk_score"],
                    recommendation=match["recommendation"],
                )
                findings.append(finding)

                if verbose:
                    print("      [SHADOW] {} | {} | {} | risk={}".format(
                        finding.id, finding.service_name, finding.severity.value, finding.risk_score
                    ))

        # Check for missing governance controls that enable shadow AI
        governance = environment.governance_policies
        if not governance.get("ai_acceptable_use_policy", False):
            counter += 1
            findings.append(ShadowAIFinding(
                id="SAI-{:03d}".format(counter),
                finding_type="governance_gap",
                service_name="Policy Gap",
                severity=Severity.HIGH,
                data_exposure_risk="high",
                description="No AI Acceptable Use Policy defined - employees have no guidance on approved AI tools",
                evidence="Governance policy review",
                risk_score=75,
                recommendation="Create and publish an AI Acceptable Use Policy that lists approved AI tools, prohibited uses, and data handling requirements.",
            ))

        if not governance.get("ai_inventory", False):
            counter += 1
            findings.append(ShadowAIFinding(
                id="SAI-{:03d}".format(counter),
                finding_type="governance_gap",
                service_name="Inventory Gap",
                severity=Severity.MEDIUM,
                data_exposure_risk="medium",
                description="No AI asset inventory maintained - organization cannot track which AI tools are in use",
                evidence="Governance policy review",
                risk_score=60,
                recommendation="Establish an AI asset inventory that tracks all approved and discovered AI tools, their data access, and risk classification.",
            ))

        if not governance.get("ai_data_classification", False):
            counter += 1
            findings.append(ShadowAIFinding(
                id="SAI-{:03d}".format(counter),
                finding_type="governance_gap",
                service_name="Data Classification Gap",
                severity=Severity.HIGH,
                data_exposure_risk="high",
                description="No AI-specific data classification policy - sensitive data may be sent to external AI services without controls",
                evidence="Governance policy review",
                risk_score=70,
                recommendation="Define data classification rules for AI: which data categories can be processed by AI tools, and which are prohibited (PII, trade secrets, ITAR, etc.).",
            ))

        return findings

    def _match_indicator(self, indicator: Dict) -> List[Dict]:
        """Match a network/endpoint indicator against known AI service signatures."""
        matches = []
        indicator_type = indicator.get("type", "")
        target = indicator.get("target", "").lower()
        details = indicator.get("details", "").lower()

        for service in self.known_ai_services:
            for signature in service["signatures"]:
                if signature.lower() in target or signature.lower() in details:
                    matches.append({
                        "service": service["name"],
                        "type": indicator_type,
                        "severity": service["severity"],
                        "data_risk": service["data_risk"],
                        "risk_score": service["risk_score"],
                        "description": indicator.get("description", "Detected {} usage".format(service["name"])),
                        "recommendation": service["recommendation"],
                    })
                    break  # One match per service per indicator

        return matches

    def _build_service_signatures(self) -> List[Dict]:
        """Build signatures for known AI services."""
        return [
            {
                "name": "ChatGPT (OpenAI)",
                "signatures": ["api.openai.com", "chat.openai.com", "chatgpt.com"],
                "severity": Severity.HIGH,
                "data_risk": "high",
                "risk_score": 80,
                "recommendation": "Block or monitor OpenAI API access. If business-approved, route through a corporate proxy with DLP inspection.",
            },
            {
                "name": "Claude (Anthropic)",
                "signatures": ["api.anthropic.com", "claude.ai"],
                "severity": Severity.HIGH,
                "data_risk": "high",
                "risk_score": 78,
                "recommendation": "Monitor Anthropic API usage. Ensure corporate data is not being sent to external AI without approval.",
            },
            {
                "name": "Google Gemini",
                "signatures": ["generativelanguage.googleapis.com", "gemini.google.com"],
                "severity": Severity.HIGH,
                "data_risk": "high",
                "risk_score": 76,
                "recommendation": "Monitor Google AI API usage. Consider using Google Workspace AI features with enterprise data controls instead.",
            },
            {
                "name": "GitHub Copilot",
                "signatures": ["copilot.github.com", "api.githubcopilot.com", "copilot-proxy"],
                "severity": Severity.MEDIUM,
                "data_risk": "medium",
                "risk_score": 55,
                "recommendation": "If Copilot is approved, ensure the enterprise plan is used with telemetry disabled. Monitor for source code exfiltration.",
            },
            {
                "name": "Hugging Face",
                "signatures": ["huggingface.co", "api-inference.huggingface.co"],
                "severity": Severity.MEDIUM,
                "data_risk": "medium",
                "risk_score": 60,
                "recommendation": "Monitor for model downloads and API usage. Verify models are from trusted sources with known provenance.",
            },
            {
                "name": "Perplexity AI",
                "signatures": ["api.perplexity.ai", "perplexity.ai"],
                "severity": Severity.MEDIUM,
                "data_risk": "medium",
                "risk_score": 55,
                "recommendation": "Monitor for corporate data being submitted as search queries. Sensitive topics may leak through AI search.",
            },
            {
                "name": "Midjourney / Image AI",
                "signatures": ["midjourney.com", "api.stability.ai", "dall-e"],
                "severity": Severity.LOW,
                "data_risk": "low",
                "risk_score": 30,
                "recommendation": "Low data risk for image generation, but monitor for proprietary design or confidential content in prompts.",
            },
            {
                "name": "Custom/Self-Hosted LLM",
                "signatures": ["ollama", "llama.cpp", "text-generation-webui", "localai"],
                "severity": Severity.MEDIUM,
                "data_risk": "medium",
                "risk_score": 65,
                "recommendation": "Self-hosted models reduce data leakage but may introduce supply chain risks. Verify model provenance and scan for backdoors.",
            },
            {
                "name": "AI Browser Extension",
                "signatures": ["ai-assistant-extension", "gpt-browser", "ai-copilot-ext", "chatgpt-extension"],
                "severity": Severity.HIGH,
                "data_risk": "high",
                "risk_score": 82,
                "recommendation": "Browser AI extensions can access page content including authenticated sessions. Block unauthorized extensions via endpoint policy.",
            },
        ]
