"""
LAIS - Linux AI Security Toolkit
NIST AI RMF Assessor: Evaluates AI deployments against the NIST AI Risk Management Framework.
Author: Larry Odeyemi

Assesses all 4 core functions (Govern, Map, Measure, Manage) plus
OT/ICS-specific AI risk checks for critical infrastructure environments.
"""

from typing import List, Dict
from ai_model import (
    AIEnvironment, NISTControl, NISTAssessment, NISTFunction,
    FindingStatus, Severity
)


class NISTAIRMFAssessor:
    """Evaluates AI deployments against NIST AI Risk Management Framework."""

    def assess(self, environment: AIEnvironment, verbose: bool = False) -> List[NISTAssessment]:
        """Run full NIST AI RMF assessment across all 4 functions."""
        assessments = []

        functions = [
            (NISTFunction.GOVERN, self._assess_govern),
            (NISTFunction.MAP, self._assess_map),
            (NISTFunction.MEASURE, self._assess_measure),
            (NISTFunction.MANAGE, self._assess_manage),
        ]

        for func, assessor in functions:
            controls = assessor(environment)
            assessment = NISTAssessment(function=func, controls=controls)
            assessment.calculate_score()
            assessments.append(assessment)

            if verbose:
                print("      [NIST] {} | {:.1f}% | {}".format(
                    func.value.upper(), assessment.score, assessment.maturity
                ))

        return assessments

    def assess_ot_ai_risks(self, environment: AIEnvironment, verbose: bool = False) -> List[Dict]:
        """Assess OT/ICS-specific AI risks."""
        findings = []
        governance = environment.governance_policies

        ot_checks = [
            {
                "id": "OT-AI-001",
                "name": "AI Predictive Maintenance Security",
                "description": "ML-based predictive maintenance models on industrial equipment must have data validation pipelines to prevent adversarial inputs.",
                "check_key": "ot_ai_predictive_maintenance_security",
                "severity": "critical",
                "risk": "Adversarial sensor data could cause the model to miss equipment failures, leading to unplanned shutdowns or safety incidents.",
                "recommendation": "Implement input validation with statistical anomaly detection on sensor data. Maintain independent manual inspection schedules.",
            },
            {
                "id": "OT-AI-002",
                "name": "ML Anomaly Detection System Integrity",
                "description": "AI-based anomaly detection in OT networks must have integrity verification to prevent model tampering.",
                "check_key": "ot_ai_anomaly_detection_integrity",
                "severity": "critical",
                "risk": "A compromised anomaly detection model could be blind to attacker activity, allowing undetected OT intrusions.",
                "recommendation": "Hash-verify ML models at load time. Implement out-of-band monitoring that doesn't rely on the AI system.",
            },
            {
                "id": "OT-AI-003",
                "name": "AI Agent Access to Safety-Critical Systems",
                "description": "AI agents and LLMs must NEVER have write access to PLCs, Safety Instrumented Systems (SIS), or DCS controllers.",
                "check_key": "ot_ai_no_write_access_plc",
                "severity": "critical",
                "risk": "An AI agent with PLC write access could be manipulated via prompt injection to send dangerous commands to industrial controllers.",
                "recommendation": "Enforce read-only access for ALL AI systems in OT environments. Safety system modifications must require physical key switches and human authorization.",
            },
            {
                "id": "OT-AI-004",
                "name": "LLM Integration with SCADA/DCS/HMI",
                "description": "LLM-based operator assistants connected to SCADA/DCS systems must have strict output validation and action boundaries.",
                "check_key": "ot_ai_llm_scada_controls",
                "severity": "critical",
                "risk": "An LLM operator assistant could be prompt-injected into providing incorrect operating procedures or recommending dangerous parameter changes.",
                "recommendation": "Implement response grounding against verified procedure databases. Add disclaimers to all AI-generated operating guidance. Require human verification for any parameter changes.",
            },
            {
                "id": "OT-AI-005",
                "name": "Autonomous Decision-Making in Safety Systems",
                "description": "AI systems must not make autonomous decisions that affect safety-critical processes without human approval.",
                "check_key": "ot_ai_no_autonomous_safety_decisions",
                "severity": "critical",
                "risk": "Autonomous AI decisions in safety contexts could bypass safety interlocks, leading to equipment damage, environmental release, or personnel injury.",
                "recommendation": "Implement mandatory human-in-the-loop for ALL AI-influenced decisions that affect safety systems. Use AI for advisory/monitoring only, never for autonomous control of safety-critical processes.",
            },
            {
                "id": "OT-AI-006",
                "name": "AI Training Data from OT Environments",
                "description": "Training data extracted from OT historian and SCADA systems must be classified and protected.",
                "check_key": "ot_ai_training_data_protection",
                "severity": "high",
                "risk": "OT process data used for AI training may contain sensitive operational information (recipes, setpoints, production schedules) that could be leaked through model extraction attacks.",
                "recommendation": "Classify OT training data as confidential. Apply differential privacy to training datasets. Monitor for training data extraction attempts.",
            },
            {
                "id": "OT-AI-007",
                "name": "AI System Network Segmentation",
                "description": "AI systems processing OT data must be segmented from both the IT network and the OT control network.",
                "check_key": "ot_ai_network_segmentation",
                "severity": "high",
                "risk": "An AI system bridging IT and OT networks creates a potential pivot point for attackers to cross the IT/OT boundary.",
                "recommendation": "Deploy AI systems in a dedicated DMZ between IT and OT. Implement unidirectional data flows (OT -> AI, never AI -> OT control). Use data diodes where possible.",
            },
        ]

        for check in ot_checks:
            has_control = governance.get(check["check_key"], False)

            if has_control:
                status = "pass"
                maturity = 3
            else:
                status = "fail"
                maturity = 0

            finding = {
                "id": check["id"],
                "name": check["name"],
                "description": check["description"],
                "severity": check["severity"],
                "status": status,
                "maturity": maturity,
                "risk": check["risk"],
                "recommendation": check["recommendation"],
            }
            findings.append(finding)

            if verbose:
                icon = "PASS" if has_control else "FAIL"
                print("      [OT-AI] {} {} | {}".format(icon, check["id"], check["name"][:45]))

        return findings

    def _assess_govern(self, env: AIEnvironment) -> List[NISTControl]:
        """GOVERN: AI governance policies, roles, and risk tolerance."""
        governance = env.governance_policies
        controls = []

        checks = [
            {
                "id": "GV-1",
                "name": "AI Governance Policy",
                "description": "Organization has a documented AI governance policy that defines acceptable use, risk tolerance, and oversight responsibilities.",
                "key": "ai_governance_policy",
                "gap": "No AI governance policy exists. AI systems are deployed without formal oversight or risk acceptance.",
                "rec": "Develop and publish an AI governance policy covering acceptable use, risk tolerance, approval workflows, and accountability.",
            },
            {
                "id": "GV-2",
                "name": "AI Risk Ownership",
                "description": "Clear ownership and accountability for AI risks is assigned to specific roles.",
                "key": "ai_risk_ownership",
                "gap": "No designated AI risk owner. AI risks are not assigned to any specific role or team.",
                "rec": "Assign AI risk ownership to a specific role (e.g., Chief AI Officer, CISO) with clear accountability.",
            },
            {
                "id": "GV-3",
                "name": "AI Acceptable Use Policy",
                "description": "Employees have clear guidance on approved AI tools and prohibited uses.",
                "key": "ai_acceptable_use_policy",
                "gap": "No AI acceptable use policy. Employees have no guidance on what AI tools are approved or prohibited.",
                "rec": "Create an AI acceptable use policy listing approved tools, prohibited uses, and data handling requirements.",
            },
            {
                "id": "GV-4",
                "name": "AI Incident Response Plan",
                "description": "AI-specific incident response procedures are documented and tested.",
                "key": "ai_incident_response",
                "gap": "No AI-specific incident response plan. AI failures or security incidents have no defined response procedure.",
                "rec": "Develop AI incident response procedures covering prompt injection, data leakage, model failure, and shadow AI discovery.",
            },
            {
                "id": "GV-5",
                "name": "AI Ethics and Fairness Review",
                "description": "AI systems undergo ethics and fairness review before deployment.",
                "key": "ai_ethics_review",
                "gap": "No ethics or fairness review process for AI systems.",
                "rec": "Establish an AI ethics review board or process that evaluates bias, fairness, and societal impact before deployment.",
            },
        ]

        for check in checks:
            has_control = governance.get(check["key"], False)
            maturity = 3 if has_control else 0
            status = FindingStatus.PASS if has_control else FindingStatus.VULNERABLE

            controls.append(NISTControl(
                id=check["id"],
                function=NISTFunction.GOVERN,
                name=check["name"],
                description=check["description"],
                status=status,
                maturity_level=maturity,
                evidence="Control implemented" if has_control else "Control not found",
                gap="" if has_control else check["gap"],
                recommendation="" if has_control else check["rec"],
            ))

        return controls

    def _assess_map(self, env: AIEnvironment) -> List[NISTControl]:
        """MAP: AI system context, data lineage, and stakeholder identification."""
        governance = env.governance_policies
        controls = []

        checks = [
            {
                "id": "MP-1",
                "name": "AI Asset Inventory",
                "description": "All AI systems are inventoried with their purpose, data access, and risk classification.",
                "key": "ai_inventory",
                "gap": "No AI asset inventory. The organization cannot track which AI systems are deployed or their risk profiles.",
                "rec": "Create an AI asset inventory tracking all deployed models, their data sources, access levels, and risk classifications.",
            },
            {
                "id": "MP-2",
                "name": "Data Lineage Tracking",
                "description": "Training and inference data sources are documented with provenance tracking.",
                "key": "data_lineage_tracking",
                "gap": "No data lineage tracking for AI systems.",
                "rec": "Implement data lineage tracking for all AI training and inference data sources.",
            },
            {
                "id": "MP-3",
                "name": "Stakeholder Identification",
                "description": "Stakeholders affected by AI systems are identified and their concerns documented.",
                "key": "stakeholder_mapping",
                "gap": "No stakeholder mapping for AI systems.",
                "rec": "Identify and document all stakeholders affected by AI systems, including customers, employees, and regulators.",
            },
            {
                "id": "MP-4",
                "name": "AI Data Classification",
                "description": "Data processed by AI systems is classified with handling requirements.",
                "key": "ai_data_classification",
                "gap": "No AI-specific data classification. Sensitive data may be processed by AI without appropriate controls.",
                "rec": "Define data classification rules for AI: which categories can be processed, which are prohibited, and handling requirements.",
            },
        ]

        for check in checks:
            has_control = governance.get(check["key"], False)
            maturity = 3 if has_control else 0
            status = FindingStatus.PASS if has_control else FindingStatus.VULNERABLE

            controls.append(NISTControl(
                id=check["id"],
                function=NISTFunction.MAP,
                name=check["name"],
                description=check["description"],
                status=status,
                maturity_level=maturity,
                evidence="Control implemented" if has_control else "Control not found",
                gap="" if has_control else check["gap"],
                recommendation="" if has_control else check["rec"],
            ))

        return controls

    def _assess_measure(self, env: AIEnvironment) -> List[NISTControl]:
        """MEASURE: Performance monitoring, bias testing, and trustworthiness metrics."""
        governance = env.governance_policies
        controls = []

        checks = [
            {
                "id": "MS-1",
                "name": "Model Performance Monitoring",
                "description": "AI model performance is continuously monitored for degradation and drift.",
                "key": "model_performance_monitoring",
                "gap": "No model performance monitoring. AI systems could degrade without detection.",
                "rec": "Implement continuous model performance monitoring with alerting for accuracy degradation and data drift.",
            },
            {
                "id": "MS-2",
                "name": "Bias and Fairness Testing",
                "description": "AI systems are tested for bias across protected characteristics.",
                "key": "bias_testing",
                "gap": "No bias testing for AI systems.",
                "rec": "Implement bias testing across protected characteristics before deployment and during operation.",
            },
            {
                "id": "MS-3",
                "name": "AI Security Testing",
                "description": "AI systems undergo regular security testing including prompt injection and adversarial attacks.",
                "key": "ai_security_testing",
                "gap": "No AI-specific security testing. Prompt injection, jailbreak, and adversarial attacks are not tested.",
                "rec": "Conduct regular AI red teaming covering prompt injection, jailbreak attempts, data extraction, and adversarial inputs.",
            },
            {
                "id": "MS-4",
                "name": "Output Quality Metrics",
                "description": "AI output quality is measured with defined accuracy, precision, and recall metrics.",
                "key": "output_quality_metrics",
                "gap": "No output quality metrics defined for AI systems.",
                "rec": "Define and track output quality metrics (accuracy, precision, recall, hallucination rate) for all AI systems.",
            },
            {
                "id": "MS-5",
                "name": "Trustworthiness Assessment",
                "description": "AI systems are assessed for trustworthiness attributes: valid, reliable, safe, secure, accountable, transparent, explainable, privacy-enhanced, and fair.",
                "key": "trustworthiness_assessment",
                "gap": "No trustworthiness assessment framework for AI systems.",
                "rec": "Implement the NIST AI RMF trustworthiness assessment covering all 7 attributes for each AI system.",
            },
        ]

        for check in checks:
            has_control = governance.get(check["key"], False)
            maturity = 3 if has_control else 0
            status = FindingStatus.PASS if has_control else FindingStatus.VULNERABLE

            controls.append(NISTControl(
                id=check["id"],
                function=NISTFunction.MEASURE,
                name=check["name"],
                description=check["description"],
                status=status,
                maturity_level=maturity,
                evidence="Control implemented" if has_control else "Control not found",
                gap="" if has_control else check["gap"],
                recommendation="" if has_control else check["rec"],
            ))

        return controls

    def _assess_manage(self, env: AIEnvironment) -> List[NISTControl]:
        """MANAGE: Risk mitigation, incident response, and continuous monitoring."""
        governance = env.governance_policies
        controls = []

        checks = [
            {
                "id": "MG-1",
                "name": "AI Risk Mitigation Controls",
                "description": "Risk mitigation controls are implemented for identified AI risks.",
                "key": "ai_risk_mitigation",
                "gap": "No AI-specific risk mitigation controls. Identified risks have no treatment plans.",
                "rec": "Develop risk treatment plans for all identified AI risks with specific controls, owners, and timelines.",
            },
            {
                "id": "MG-2",
                "name": "AI Continuous Monitoring",
                "description": "AI systems are continuously monitored for security events and anomalies.",
                "key": "ai_continuous_monitoring",
                "gap": "No continuous monitoring of AI system behavior.",
                "rec": "Implement logging and monitoring for AI systems: track inputs, outputs, errors, and security events.",
            },
            {
                "id": "MG-3",
                "name": "AI Model Lifecycle Management",
                "description": "AI models have defined lifecycle management including versioning, retirement, and rollback procedures.",
                "key": "model_lifecycle_management",
                "gap": "No model lifecycle management. Models have no versioning, retirement, or rollback procedures.",
                "rec": "Implement model lifecycle management with version control, retirement criteria, and rollback procedures.",
            },
            {
                "id": "MG-4",
                "name": "Third-Party AI Risk Management",
                "description": "Risks from third-party AI services and APIs are assessed and managed.",
                "key": "third_party_ai_risk",
                "gap": "No third-party AI risk management. External AI service risks are not assessed.",
                "rec": "Assess and manage risks from all third-party AI services including data handling, availability, and vendor lock-in.",
            },
        ]

        for check in checks:
            has_control = governance.get(check["key"], False)
            maturity = 3 if has_control else 0
            status = FindingStatus.PASS if has_control else FindingStatus.VULNERABLE

            controls.append(NISTControl(
                id=check["id"],
                function=NISTFunction.MANAGE,
                name=check["name"],
                description=check["description"],
                status=status,
                maturity_level=maturity,
                evidence="Control implemented" if has_control else "Control not found",
                gap="" if has_control else check["gap"],
                recommendation="" if has_control else check["rec"],
            ))

        return controls
