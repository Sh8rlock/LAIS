"""
LAIS - Linux AI Security Toolkit
Report Generator: Produces HTML and JSON assessment reports.
Author: Larry Odeyemi

Generates professional reports with OWASP Top 10 heatmaps, NIST AI RMF scorecards,
prompt injection results, shadow AI findings, and OT/ICS AI risk assessments.
"""

import json
import os
from typing import List, Dict
from datetime import datetime

from ai_model import (
    AssessmentReport, OWASPFinding, FindingStatus, Severity, NISTAssessment
)


def _severity_color(severity):
    if isinstance(severity, str):
        s = severity
    else:
        s = severity.value
    colors = {
        "critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04",
        "low": "#16a34a", "informational": "#6b7280"
    }
    return colors.get(s, "#6b7280")


def _status_color(status):
    if isinstance(status, str):
        s = status
    else:
        s = status.value
    colors = {
        "vulnerable": "#dc2626", "warning": "#ca8a04",
        "pass": "#16a34a", "n/a": "#6b7280", "fail": "#dc2626"
    }
    return colors.get(s, "#6b7280")


def _grade_color(grade):
    colors = {"A": "#16a34a", "B": "#22c55e", "C": "#ca8a04", "D": "#ea580c", "F": "#dc2626"}
    return colors.get(grade, "#6b7280")


def _build_css(dark_mode=False):
    if dark_mode:
        bg = "#0f172a"; card_bg = "#1e293b"; text = "#e2e8f0"
        text_muted = "#94a3b8"; border = "#334155"
        table_header = "#334155"; table_stripe = "#1e293b"
    else:
        bg = "#f8fafc"; card_bg = "#ffffff"; text = "#1e293b"
        text_muted = "#64748b"; border = "#e2e8f0"
        table_header = "#f1f5f9"; table_stripe = "#f8fafc"

    return """
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        background: {bg}; color: {text}; line-height: 1.6; padding: 0;
    }}
    .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}
    .header {{
        background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%);
        color: #f1f5f9; padding: 48px 32px; text-align: center;
        border-bottom: 4px solid #8b5cf6;
    }}
    .header h1 {{ font-size: 2.2em; font-weight: 700; margin-bottom: 8px; letter-spacing: -0.5px; }}
    .header .subtitle {{ font-size: 1.1em; color: #a5b4fc; }}
    .header .meta {{ margin-top: 16px; font-size: 0.9em; color: #64748b; }}
    .score-banner {{
        display: flex; justify-content: center; align-items: center; gap: 48px;
        padding: 32px; margin: 24px 0; background: {card_bg};
        border: 1px solid {border}; border-radius: 12px;
    }}
    .score-item {{ text-align: center; }}
    .score-item .value {{ font-size: 2.8em; font-weight: 800; line-height: 1; }}
    .score-item .label {{ font-size: 0.85em; color: {text_muted}; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }}
    .card {{
        background: {card_bg}; border: 1px solid {border};
        border-radius: 12px; padding: 24px; margin: 20px 0;
    }}
    .card h2 {{
        font-size: 1.3em; font-weight: 700; margin-bottom: 16px;
        padding-bottom: 8px; border-bottom: 2px solid {border};
    }}
    .card h3 {{ font-size: 1.1em; font-weight: 600; margin: 16px 0 8px 0; }}
    table {{
        width: 100%; border-collapse: collapse; font-size: 0.9em; margin: 12px 0;
    }}
    th {{
        background: {table_header}; text-align: left; padding: 10px 12px;
        font-weight: 600; border-bottom: 2px solid {border}; font-size: 0.85em;
        text-transform: uppercase; letter-spacing: 0.5px; color: {text_muted};
    }}
    td {{ padding: 10px 12px; border-bottom: 1px solid {border}; vertical-align: top; }}
    tr:nth-child(even) td {{ background: {table_stripe}; }}
    .status-badge {{
        display: inline-block; padding: 2px 10px; border-radius: 12px;
        font-size: 0.8em; font-weight: 600; text-transform: uppercase;
    }}
    .status-vulnerable {{ background: #fecaca; color: #991b1b; }}
    .status-warning {{ background: #fef9c3; color: #854d0e; }}
    .status-pass {{ background: #dcfce7; color: #166534; }}
    .severity-badge {{
        display: inline-block; padding: 2px 8px; border-radius: 4px;
        font-size: 0.75em; font-weight: 700; text-transform: uppercase; color: white;
    }}
    .owasp-grid {{
        display: grid; grid-template-columns: repeat(5, 1fr);
        gap: 8px; margin: 16px 0;
    }}
    .owasp-cell {{
        padding: 12px 8px; border-radius: 8px; text-align: center;
        border: 1px solid {border};
    }}
    .owasp-cell .owasp-id {{ font-size: 0.75em; font-weight: 700; letter-spacing: 0.5px; }}
    .owasp-cell .owasp-name {{ font-size: 0.7em; margin-top: 4px; }}
    .nist-bar {{
        height: 24px; border-radius: 4px; margin: 4px 0;
    }}
    .rec-card {{
        padding: 16px; margin: 8px 0; border-radius: 8px; border-left: 4px solid;
    }}
    .rec-critical {{ border-color: #dc2626; background: #fef2f2; }}
    .rec-high {{ border-color: #ea580c; background: #fff7ed; }}
    .rec-medium {{ border-color: #ca8a04; background: #fefce8; }}
    .footer {{
        text-align: center; padding: 32px; color: {text_muted};
        font-size: 0.85em; border-top: 1px solid {border}; margin-top: 32px;
    }}
    """.format(bg=bg, card_bg=card_bg, text=text, text_muted=text_muted,
               border=border, table_header=table_header, table_stripe=table_stripe)


def _build_score_banner(report):
    gc = _grade_color(report.overall_grade)
    vuln_prompt = sum(1 for r in report.prompt_attack_results if r.success)
    vuln_owasp = sum(1 for f in report.owasp_findings if f.status.value == "vulnerable")

    return """
    <div class="score-banner">
        <div class="score-item">
            <div class="value" style="color:{gc}">{score:.1f}%</div>
            <div class="label">Security Score</div>
        </div>
        <div class="score-item">
            <div class="value" style="color:{gc}">{grade}</div>
            <div class="label">{label}</div>
        </div>
        <div class="score-item">
            <div class="value" style="color:#dc2626">{vuln_prompt}</div>
            <div class="label">Prompt Vulns</div>
        </div>
        <div class="score-item">
            <div class="value" style="color:#ea580c">{vuln_owasp}</div>
            <div class="label">OWASP Vulns</div>
        </div>
        <div class="score-item">
            <div class="value">{shadow}</div>
            <div class="label">Shadow AI</div>
        </div>
    </div>
    """.format(gc=gc, score=report.overall_risk_score, grade=report.overall_grade,
               label=report.grade_label, vuln_prompt=vuln_prompt, vuln_owasp=vuln_owasp,
               shadow=len(report.shadow_ai_findings))


def _build_prompt_section(report):
    if not report.prompt_attack_results:
        return ""

    rows = ""
    for r in report.prompt_attack_results:
        icon = "&#x274C;" if r.success else "&#x2705;"
        status_label = "VULNERABLE" if r.success else "DEFENDED"
        status_cls = "status-vulnerable" if r.success else "status-pass"
        sev_col = _severity_color(r.severity)

        rows += """
        <tr>
            <td>{icon} <span class="status-badge {cls}">{label}</span></td>
            <td>{name}</td>
            <td><code>{owasp}</code></td>
            <td><span class="severity-badge" style="background:{sev}">{sevl}</span></td>
            <td>{risk}</td>
        </tr>
        """.format(icon=icon, cls=status_cls, label=status_label,
                   name=r.attack_name, owasp=r.owasp_id, sev=sev_col,
                   sevl=r.severity.value, risk=r.risk_score)

    vuln = sum(1 for r in report.prompt_attack_results if r.success)
    total = len(report.prompt_attack_results)

    return """
    <div class="card">
        <h2>&#x1F534; Prompt Injection Red Team Results</h2>
        <p>{vuln}/{total} attacks bypassed defenses ({rate:.0f}% vulnerability rate)</p>
        <table>
            <tr><th>Status</th><th>Attack</th><th>OWASP</th><th>Severity</th><th>Risk</th></tr>
            {rows}
        </table>
    </div>
    """.format(vuln=vuln, total=total,
               rate=(vuln/total*100) if total else 0, rows=rows)


def _build_shadow_section(report):
    if not report.shadow_ai_findings:
        return ""

    rows = ""
    for f in report.shadow_ai_findings:
        sev_col = _severity_color(f.severity)
        rows += """
        <tr>
            <td><span class="severity-badge" style="background:{sev}">{sevl}</span></td>
            <td>{service}</td>
            <td>{ftype}</td>
            <td>{desc}</td>
            <td>{risk}</td>
        </tr>
        """.format(sev=sev_col, sevl=f.severity.value, service=f.service_name,
                   ftype=f.finding_type, desc=f.description[:80], risk=f.risk_score)

    return """
    <div class="card">
        <h2>&#x1F47B; Shadow AI Detection</h2>
        <p>{count} unauthorized AI usage instances detected</p>
        <table>
            <tr><th>Severity</th><th>Service</th><th>Type</th><th>Description</th><th>Risk</th></tr>
            {rows}
        </table>
    </div>
    """.format(count=len(report.shadow_ai_findings), rows=rows)


def _build_owasp_section(report):
    if not report.owasp_findings:
        return ""

    cells = ""
    for f in report.owasp_findings:
        status_val = f.status.value
        if status_val == "vulnerable":
            cell_bg = "#fecaca"; cell_col = "#991b1b"
        elif status_val == "warning":
            cell_bg = "#fef9c3"; cell_col = "#854d0e"
        elif status_val == "pass":
            cell_bg = "#dcfce7"; cell_col = "#166534"
        else:
            cell_bg = "#f1f5f9"; cell_col = "#64748b"

        cat_parts = f.category.value.split(": ")
        cat_id = cat_parts[0] if len(cat_parts) > 0 else ""
        cat_name = cat_parts[1] if len(cat_parts) > 1 else f.category.value

        cells += """
        <div class="owasp-cell" style="background:{bg}">
            <div class="owasp-id" style="color:{col}">{cid}</div>
            <div class="owasp-name" style="color:{col}">{name}</div>
            <div style="font-size:1.4em;margin-top:4px">{icon}</div>
        </div>
        """.format(bg=cell_bg, col=cell_col, cid=cat_id, name=cat_name, icon=f.status_icon)

    # Details table
    rows = ""
    for f in report.owasp_findings:
        sev_col = _severity_color(f.severity)
        status_cls = "status-{}".format(f.status.value)
        cat_parts = f.category.value.split(": ")
        cat_id = cat_parts[0]

        rows += """
        <tr>
            <td><code>{cid}</code></td>
            <td>{icon} <span class="status-badge {cls}">{status}</span></td>
            <td><span class="severity-badge" style="background:{sev}">{sevl}</span></td>
            <td>{risk}</td>
            <td style="font-size:0.85em">{desc}</td>
        </tr>
        """.format(cid=cat_id, icon=f.status_icon, cls=status_cls,
                   status=f.status.value, sev=sev_col, sevl=f.severity.value,
                   risk=f.risk_score, desc=f.description[:90])

    return """
    <div class="card">
        <h2>&#x1F6E1;&#xFE0F; OWASP Top 10 for LLM Applications</h2>
        <div class="owasp-grid">{cells}</div>
        <table>
            <tr><th>Category</th><th>Status</th><th>Severity</th><th>Risk</th><th>Finding</th></tr>
            {rows}
        </table>
    </div>
    """.format(cells=cells, rows=rows)


def _build_nist_section(report):
    if not report.nist_assessments:
        return ""

    bars = ""
    for nist in report.nist_assessments:
        if nist.score >= 60:
            bar_col = "#16a34a"
        elif nist.score >= 30:
            bar_col = "#ca8a04"
        else:
            bar_col = "#dc2626"

        bars += """
        <div style="margin:12px 0">
            <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                <strong>{func}</strong>
                <span>{score:.1f}% ({maturity})</span>
            </div>
            <div style="background:#e2e8f0;border-radius:4px;overflow:hidden">
                <div class="nist-bar" style="width:{score}%;background:{col}"></div>
            </div>
        </div>
        """.format(func=nist.function.value.upper(), score=nist.score,
                   maturity=nist.maturity, col=bar_col)

    # Control details
    rows = ""
    for nist in report.nist_assessments:
        for c in nist.controls:
            status_cls = "status-pass" if c.status.value == "pass" else "status-vulnerable"
            status_label = c.status.value
            icon = "&#x2705;" if c.status.value == "pass" else "&#x274C;"

            rows += """
            <tr>
                <td>{func}</td>
                <td><code>{cid}</code></td>
                <td>{name}</td>
                <td>{icon} <span class="status-badge {cls}">{status}</span></td>
                <td style="font-size:0.85em">{gap}</td>
            </tr>
            """.format(func=nist.function.value.upper(), cid=c.id, name=c.name,
                       icon=icon, cls=status_cls, status=status_label,
                       gap=c.gap[:80] if c.gap else "-")

    avg_score = sum(n.score for n in report.nist_assessments) / len(report.nist_assessments)

    return """
    <div class="card">
        <h2>&#x1F4CB; NIST AI Risk Management Framework</h2>
        <p>Average maturity: {avg:.1f}%</p>
        {bars}
        <h3>Control Details</h3>
        <table>
            <tr><th>Function</th><th>ID</th><th>Control</th><th>Status</th><th>Gap</th></tr>
            {rows}
        </table>
    </div>
    """.format(avg=avg_score, bars=bars, rows=rows)


def _build_ot_section(report):
    if not report.ot_ics_findings:
        return ""

    rows = ""
    for f in report.ot_ics_findings:
        sev = f.get("severity", "medium")
        sev_col = _severity_color(sev)
        status = f.get("status", "fail")
        icon = "&#x2705;" if status == "pass" else "&#x274C;"
        status_cls = "status-pass" if status == "pass" else "status-vulnerable"

        rows += """
        <tr>
            <td><code>{fid}</code></td>
            <td>{name}</td>
            <td><span class="severity-badge" style="background:{sev_col}">{sev}</span></td>
            <td>{icon} <span class="status-badge {cls}">{status}</span></td>
            <td style="font-size:0.85em">{risk}</td>
        </tr>
        """.format(fid=f.get("id",""), name=f.get("name",""), sev_col=sev_col,
                   sev=sev, icon=icon, cls=status_cls, status=status,
                   risk=f.get("risk","")[:80])

    fail_count = sum(1 for f in report.ot_ics_findings if f.get("status") == "fail")

    return """
    <div class="card">
        <h2>&#x1F3ED; OT/ICS AI-Specific Risk Assessment</h2>
        <p style="color:#dc2626;font-weight:700">{fail}/{total} critical infrastructure AI controls are MISSING</p>
        <table>
            <tr><th>ID</th><th>Control</th><th>Severity</th><th>Status</th><th>Risk</th></tr>
            {rows}
        </table>
    </div>
    """.format(fail=fail_count, total=len(report.ot_ics_findings), rows=rows)


def generate_html_report(reports, output_path, dark_mode=False):
    """Generate the full HTML assessment report."""
    css = _build_css(dark_mode)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    all_sections = ""
    for report in reports:
        env_name = report.environment.name if report.environment else "Unknown"
        env_type = report.environment.environment_type if report.environment else "unknown"

        all_sections += """
        <div class="card">
            <h2>&#x1F4CA; Assessment: {name}</h2>
            <p><strong>Environment:</strong> {etype} | <strong>Score:</strong>
            <span style="color:{gc};font-weight:700">{score:.1f}% ({grade} - {label})</span></p>
        </div>
        """.format(name=env_name, etype=env_type,
                   gc=_grade_color(report.overall_grade),
                   score=report.overall_risk_score,
                   grade=report.overall_grade,
                   label=report.grade_label)

        all_sections += _build_score_banner(report)
        all_sections += _build_prompt_section(report)
        all_sections += _build_shadow_section(report)
        all_sections += _build_owasp_section(report)
        all_sections += _build_nist_section(report)
        all_sections += _build_ot_section(report)

    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LAIS Assessment Report</title>
    <style>{css}</style>
</head>
<body>
    <div class="header">
        <h1>LAIS Assessment Report</h1>
        <div class="subtitle">Linux AI Security Toolkit &mdash; AI Security Assessment &amp; Red Teaming</div>
        <div class="meta">Generated: {now} | Author: Larry Odeyemi | github.com/Sh8rlock/LAIS</div>
    </div>
    <div class="container">
        {sections}
        <div class="card">
            <h2>&#x1F6E0;&#xFE0F; Assessment Methodology</h2>
            <table>
                <tr><td style="width:180px"><strong>Tool</strong></td><td>LAIS - Linux AI Security Toolkit v1.0.0</td></tr>
                <tr><td><strong>Frameworks</strong></td><td>OWASP Top 10 for LLM Applications + NIST AI Risk Management Framework</td></tr>
                <tr><td><strong>Prompt Red Team</strong></td><td>15+ attack categories: direct/indirect injection, jailbreak, PII leakage, excessive agency, system prompt extraction</td></tr>
                <tr><td><strong>Shadow AI</strong></td><td>Network traffic analysis + endpoint process scanning for 9 known AI service families</td></tr>
                <tr><td><strong>OT/ICS Module</strong></td><td>7 critical infrastructure AI-specific risk checks (predictive maintenance, SCADA/DCS integration, autonomous safety decisions)</td></tr>
            </table>
        </div>
    </div>
    <div class="footer">
        LAIS Assessment Report &mdash; Generated by Linux AI Security Toolkit v1.0.0<br>
        Author: Larry Odeyemi | github.com/Sh8rlock/LAIS
    </div>
</body>
</html>""".format(css=css, now=now, sections=all_sections)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def generate_json_report(reports, output_path):
    """Generate JSON assessment report."""
    data = {
        "report": {
            "title": "LAIS Assessment Report",
            "tool": "Linux AI Security Toolkit v1.0.0",
            "author": "Larry Odeyemi",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "frameworks": ["OWASP Top 10 for LLM Applications", "NIST AI Risk Management Framework"],
        },
        "assessments": [r.to_dict() for r in reports],
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
