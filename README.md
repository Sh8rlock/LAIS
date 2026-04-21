# LAIS — Linux AI Security Toolkit

**AI Security Assessment & LLM Red Teaming for Enterprise and OT/ICS**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![OWASP Top 10 LLM](https://img.shields.io/badge/OWASP-Top%2010%20LLM-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![NIST AI RMF](https://img.shields.io/badge/NIST-AI%20RMF%201.0-green.svg)](https://www.nist.gov/artificial-intelligence/risk-management-framework)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What It Does

LAIS is a Python toolkit that assesses AI/LLM deployments across five security dimensions:

1. **Prompt Injection Red Teaming** — 15 attack types mapped to OWASP LLM01, LLM02, LLM06, LLM07 including 3 OT/ICS-specific attacks
2. **Shadow AI Detection** — Discovers 9 AI service families and governance gaps
3. **OWASP Top 10 for LLMs** — Scores all 10 categories with remediation guidance
4. **NIST AI Risk Management Framework** — Evaluates Govern / Map / Measure / Manage maturity
5. **OT/ICS AI Risk Assessment** — 7 critical infrastructure-specific AI risk checks (unique to LAIS)

It generates professional HTML and JSON reports with heatmaps, bar charts, and remediation recommendations.

---

## Architecture

```
run_lais.py              CLI entry point (--demo, --scenario, --dark, --verbose)
├── ai_model.py          Data classes: AIAsset, PromptAttackResult, OWASPCategory, NISTFunction, etc.
├── prompt_attack.py     15 attack types × per-asset evaluation engine
├── shadow_detector.py   Shadow AI discovery + governance gap analysis
├── owasp_scanner.py     All 10 OWASP LLM Top 10 categories
├── nist_ai_rmf.py       4 NIST AI RMF functions + 7 OT/ICS AI risk checks
├── demo_environments.py 3 pre-built environments with realistic AI asset configurations
└── report_generator.py  HTML + JSON report generation with charts
```

---

## Demo Scenarios

LAIS ships with 3 realistic environments that run without any external dependencies:

### 1. Enterprise AI Chatbot — "Startup Inc."

A startup with zero AI governance, a customer-facing chatbot, and an internal HR assistant — both wide open.

| Metric | Result |
|--------|--------|
| Overall Score | 27.8% |
| Grade | F — Critical Risk |
| Prompt Attacks | 26 tested, 24 vulnerable |
| Shadow AI | 7 instances found |
| OWASP Top 10 | 6 vulnerable, 2 warnings |
| NIST AI RMF | 0.0% maturity |

### 2. AI-Powered SOC — "SecureCorp"

A security operations center using an AI-powered alert triage system and a threat intel assistant. Partial controls in place.

| Metric | Result |
|--------|--------|
| Overall Score | 70.4% |
| Grade | B — Adequate |
| Prompt Attacks | 30 tested, 11 vulnerable |
| Shadow AI | 1 instance found |
| OWASP Top 10 | 2 vulnerable, 3 warnings |
| NIST AI RMF | 38.4% maturity |

### 3. AI in OT/ICS Critical Infrastructure — "ChemPlant Corp"

A chemical plant with AI-driven predictive maintenance, an ML anomaly detection system, and an LLM operator assistant connected to SCADA — maximum risk.

| Metric | Result |
|--------|--------|
| Overall Score | 20.3% |
| Grade | F — Critical Risk |
| Prompt Attacks | 17 tested, 17 vulnerable |
| Shadow AI | 5 instances found |
| OWASP Top 10 | 8 vulnerable, 1 warnings |
| NIST AI RMF | 0.0% maturity |
| OT/ICS AI Risks | 7 identified (5 CRITICAL, 2 HIGH) |

---

## Prompt Attack Types

| # | Attack | OWASP Category |
|---|--------|----------------|
| 1 | Direct Injection: Role Override | LLM01 |
| 2 | Direct Injection: Instruction Hijacking | LLM01 |
| 3 | Indirect Injection: Hidden Instructions | LLM01 |
| 4 | Jailbreak: DAN-Style Persona Switch | LLM01 |
| 5 | Jailbreak: Encoding Evasion (Base64) | LLM01 |
| 6 | Jailbreak: Multi-Turn Escalation | LLM01 |
| 7 | PII Leakage: User Data Extraction | LLM02 |
| 8 | Training Data Extraction: Memorization | LLM02 |
| 9 | System Prompt Extraction: Direct Request | LLM07 |
| 10 | System Prompt Extraction: Boundary Testing | LLM07 |
| 11 | Excessive Agency: Unauthorized Tool Use | LLM06 |
| 12 | Excessive Agency: Privilege Escalation | LLM06 |
| 13 | Context Window Flooding | LLM01 |
| 14 | **OT/ICS: AI Operator Assistant Manipulation** | LLM06 |
| 15 | **OT/ICS: LLM Agent with PLC Write Access** | LLM06 |

*Bold = OT/ICS-specific attacks unique to LAIS*

An additional attack — **OT/ICS: Adversarial Input to Predictive Maintenance** (LLM04) — is triggered when predictive maintenance AI assets are present.

---

## OWASP Top 10 for LLMs Coverage

| Code | Category | Assessment Method |
|------|----------|-------------------|
| LLM01 | Prompt Injection | Input validation, output filtering, system prompt protection |
| LLM02 | Sensitive Information Disclosure | PII handling, data classification, access controls |
| LLM03 | Supply Chain | Model provenance, dependency scanning, SBOM |
| LLM04 | Data and Model Poisoning | Training pipeline integrity, data validation |
| LLM05 | Improper Output Handling | Output sanitization, encoding, content filtering |
| LLM06 | Excessive Agency | Tool permissions, privilege boundaries, human-in-the-loop |
| LLM07 | System Prompt Leakage | Prompt protection, boundary enforcement |
| LLM08 | Vector and Embedding Weaknesses | RAG security, embedding integrity |
| LLM09 | Misinformation | Grounding, fact-checking, hallucination detection |
| LLM10 | Unbounded Consumption | Rate limiting, token budgets, resource controls |

---

## NIST AI RMF Functions

| Function | What LAIS Checks |
|----------|------------------|
| **GOVERN** | AI policy, roles, risk tolerance, compliance mapping |
| **MAP** | AI asset inventory, data flows, third-party dependencies, context of use |
| **MEASURE** | Monitoring, metrics, bias testing, performance benchmarks |
| **MANAGE** | Incident response, model lifecycle, decommissioning, continuous improvement |

### OT/ICS AI-Specific Risk Checks (Phase 5)

| # | Risk Area | Severity |
|---|-----------|----------|
| 1 | AI Predictive Maintenance Security | CRITICAL |
| 2 | ML Anomaly Detection System Integrity | CRITICAL |
| 3 | AI Agent Access to Safety-Critical Systems | CRITICAL |
| 4 | LLM Integration with SCADA/DCS/HMI | CRITICAL |
| 5 | Autonomous Decision-Making in Safety Systems | CRITICAL |
| 6 | AI Training Data from OT Environments | HIGH |
| 7 | AI System Network Segmentation | HIGH |

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Sh8rlock/LAIS.git
cd LAIS

# Install dependencies
pip install -r requirements.txt

# Run all 3 scenarios
python run_lais.py --demo

# Run a specific scenario
python run_lais.py --demo --scenario enterprise   # Startup Inc.
python run_lais.py --demo --scenario soc           # SecureCorp SOC
python run_lais.py --demo --scenario ot            # ChemPlant Corp OT/ICS

# Dark mode reports
python run_lais.py --demo --dark

# Verbose output
python run_lais.py --demo --verbose
```

### Output

Reports are saved to `./output/`:
- `lais_report.html` — Interactive report with OWASP heatmap, NIST bar charts, prompt attack results, shadow AI findings, and OT/ICS risk section
- `lais_report.json` — Machine-readable full assessment data

---

## Why This Exists

AI is being deployed into critical infrastructure without security assessment frameworks designed for it. LAIS demonstrates:

- **Prompt injection isn't just a chatbot problem** — when an LLM has write access to a PLC, a jailbreak becomes a safety incident
- **Shadow AI is everywhere** — employees use personal AI accounts to process sensitive data with zero visibility
- **OWASP + NIST aren't optional** — the 2025 OWASP Top 10 for LLMs and NIST AI RMF provide actionable frameworks that most organizations haven't adopted
- **OT/ICS + AI = maximum risk** — predictive maintenance ML, anomaly detection, and LLM operator assistants create attack surfaces that traditional OT security doesn't cover

---

## Portfolio

LAIS is part of a 9-tool security portfolio:

| Tool | Category | Focus |
|------|----------|-------|
| [LPAT](https://github.com/Sh8rlock/LPAT) | Purple Team | ATT&CK simulation + detection validation |
| **LAIS** | AI Security | LLM red teaming + AI governance assessment |
| [LNPS](https://github.com/Sh8rlock/LNPS) | Network Security | Packet capture + threat detection |
| [LTHT](https://github.com/Sh8rlock/LTHT) | Threat Hunting | Log analysis + MITRE ATT&CK mapping |
| [OTSAT](https://github.com/Sh8rlock/OTSAT) | OT Security | NIST 800-82 compliance assessment |
| [LNDG](https://github.com/Sh8rlock/LNDG) | Network Mapping | Auto-generated topology diagrams |

---

## Author

**Larry Odeyemi**
- LinkedIn: [linkedin.com/in/larryodeyemi](https://linkedin.com/in/larryodeyemi)
- GitHub: [github.com/Sh8rlock](https://github.com/Sh8rlock)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
