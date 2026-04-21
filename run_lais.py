#!/usr/bin/env python3
"""
LAIS - Linux AI Security Toolkit
AI Security Assessment & Red Teaming
Author: Larry Odeyemi

Usage:
    python run_lais.py --demo                        # Run all 3 scenarios
    python run_lais.py --demo --scenario enterprise  # Enterprise AI chatbot
    python run_lais.py --demo --scenario soc         # AI-powered SOC
    python run_lais.py --demo --scenario ot          # AI in OT/ICS
    python run_lais.py --demo --dark                 # Dark mode reports
    python run_lais.py --demo --verbose              # Show detailed output
"""

import argparse
import os
import sys
import time
from datetime import datetime

VERSION = "1.0.0"

BANNER = r"""
 {line}
 {side}     _        _    ___ ____                                {side2}
 {side}    | |      / \  |_ _/ ___|                               {side2}
 {side}    | |     / _ \  | |\___ \                               {side2}
 {side}    | |___ / ___ \ | | ___) |                              {side2}
 {side}    |_____/_/   \_\___|____/                               {side2}
 {side}                                                           {side2}
 {side}    Linux AI Security Toolkit v{version}                      {side2}
 {side}    AI Security Assessment & Red Teaming                   {side2}
 {side}    Author: Larry Odeyemi                                  {side2}
 {line2}
"""


def print_banner():
    print(BANNER.format(
        version=VERSION,
        line=chr(9556) + chr(9552) * 58 + chr(9559),
        line2=chr(9562) + chr(9552) * 58 + chr(9565),
        side=chr(9553),
        side2=chr(9553),
    ))


def print_header(title):
    print()
    print("  " + "=" * 58)
    print("  " + title)
    print("  " + "=" * 58)


def print_section(title):
    print()
    print("  " + chr(9472) * 58)
    print("    " + title)
    print("  " + chr(9472) * 58)


def parse_args():
    parser = argparse.ArgumentParser(
        description="LAIS - Linux AI Security Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_lais.py --demo                        Run all demo scenarios
  python run_lais.py --demo --scenario enterprise  Enterprise AI chatbot
  python run_lais.py --demo --scenario soc         AI-powered SOC
  python run_lais.py --demo --scenario ot          AI in OT/ICS
  python run_lais.py --demo --dark                 Dark mode HTML reports
  python run_lais.py --demo --verbose              Show detailed output
        """
    )

    parser.add_argument("--demo", action="store_true",
                        help="Run with built-in demo scenarios")
    parser.add_argument("--scenario", type=str, default="all",
                        choices=["all", "enterprise", "soc", "ot"],
                        help="Which demo scenario to run (default: all)")
    parser.add_argument("--dark", action="store_true",
                        help="Generate dark-themed HTML reports")
    parser.add_argument("--verbose", action="store_true",
                        help="Show detailed output during assessment")
    parser.add_argument("--output", type=str, default="output",
                        help="Output directory for reports (default: output)")
    parser.add_argument("--version", action="version",
                        version="LAIS v{}".format(VERSION))

    return parser.parse_args()


def ensure_output_dir(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def run_scenario(environment, verbose=False):
    """Run a full AI security assessment on one environment."""
    from prompt_attack import PromptAttackEngine
    from shadow_detector import ShadowAIDetector
    from owasp_scanner import OWASPScanner
    from nist_ai_rmf import NISTAIRMFAssessor
    from ai_model import AssessmentReport

    report = AssessmentReport(
        title="LAIS Assessment: {}".format(environment.name),
        environment=environment,
    )

    # Phase 1: Prompt Injection Red Teaming
    print_section("PHASE 1: Prompt Injection Red Teaming")
    prompt_engine = PromptAttackEngine()
    for asset in environment.assets:
        results = prompt_engine.assess_asset(asset, verbose=verbose)
        report.prompt_attack_results.extend(results)

    vuln_count = sum(1 for r in report.prompt_attack_results if r.success)
    total = len(report.prompt_attack_results)
    print("    Attacks executed: {}".format(total))
    print("    Vulnerabilities found: {}".format(vuln_count))
    print("    Defended: {}".format(total - vuln_count))

    for r in report.prompt_attack_results:
        icon = chr(10060) if r.success else chr(9989)
        label = "VULNERABLE" if r.success else "DEFENDED"
        print("      {} {}  {} [{}]".format(
            icon, label.ljust(12), r.attack_name[:42].ljust(42), r.owasp_id
        ))

    # Phase 2: Shadow AI Detection
    print_section("PHASE 2: Shadow AI Detection")
    shadow_detector = ShadowAIDetector()
    shadow_findings = shadow_detector.scan(environment, verbose=verbose)
    report.shadow_ai_findings = shadow_findings

    print("    Shadow AI instances found: {}".format(len(shadow_findings)))
    for f in shadow_findings:
        sev = f.severity.value.upper()
        print("      {} [{}] {} - {}".format(
            chr(9888) + chr(65039) if f.severity.value in ("critical", "high") else chr(9432),
            sev.ljust(8),
            f.service_name.ljust(20),
            f.description[:50]
        ))

    # Phase 3: OWASP Top 10 for LLMs Assessment
    print_section("PHASE 3: OWASP Top 10 for LLMs")
    owasp_scanner = OWASPScanner()
    owasp_findings = owasp_scanner.assess(environment, report.prompt_attack_results, verbose=verbose)
    report.owasp_findings = owasp_findings

    vuln_owasp = sum(1 for f in owasp_findings if f.status.value == "vulnerable")
    warn_owasp = sum(1 for f in owasp_findings if f.status.value == "warning")
    pass_owasp = sum(1 for f in owasp_findings if f.status.value == "pass")

    print("    Categories assessed: {}".format(len(owasp_findings)))
    print("    {} Vulnerable: {}  {} Warning: {}  {} Pass: {}".format(
        chr(10060), vuln_owasp, chr(9888) + chr(65039), warn_owasp, chr(9989), pass_owasp
    ))

    for f in owasp_findings:
        cat_short = f.category.value.split(":")[0]
        cat_name = f.category.value.split(": ")[1] if ": " in f.category.value else f.category.value
        print("      {} {}  {}".format(
            f.status_icon, cat_short.ljust(6), cat_name
        ))

    # Phase 4: NIST AI RMF Compliance
    print_section("PHASE 4: NIST AI Risk Management Framework")
    nist_assessor = NISTAIRMFAssessor()
    nist_results = nist_assessor.assess(environment, verbose=verbose)
    report.nist_assessments = nist_results

    for nist in nist_results:
        nist.calculate_score()
        print("    {}: {:.1f}% ({})".format(
            nist.function.value.upper().ljust(8),
            nist.score,
            nist.maturity,
        ))

    # Phase 5: OT/ICS AI-Specific Risks (if applicable)
    if environment.environment_type == "ot_ics":
        print_section("PHASE 5: OT/ICS AI-Specific Risk Assessment")
        ot_findings = nist_assessor.assess_ot_ai_risks(environment, verbose=verbose)
        report.ot_ics_findings = ot_findings

        print("    OT/ICS AI risks identified: {}".format(len(ot_findings)))
        for f in ot_findings:
            sev = f.get("severity", "medium").upper()
            print("      {} [{}] {}".format(
                chr(10060) if sev in ("CRITICAL", "HIGH") else chr(9888) + chr(65039),
                sev.ljust(8),
                f.get("name", "Unknown")[:50],
            ))

    # Calculate overall score
    report.calculate_overall()

    return report


def print_report_summary(report):
    """Print the overall assessment summary."""
    from ai_model import Severity

    grade_display = "{} - {}".format(report.overall_grade, report.grade_label)

    print_header("LAIS ASSESSMENT COMPLETE")
    print("    Environment:         {}".format(report.environment.name if report.environment else "N/A"))
    print("    Overall Score:       {:.1f}%".format(report.overall_risk_score))
    print("    Grade:               {}".format(grade_display))
    print("    Prompt Attacks:      {} tested, {} vulnerable".format(
        len(report.prompt_attack_results),
        sum(1 for r in report.prompt_attack_results if r.success),
    ))
    print("    Shadow AI:           {} instances found".format(len(report.shadow_ai_findings)))
    print("    OWASP Top 10:        {} vulnerable, {} warnings".format(
        sum(1 for f in report.owasp_findings if f.status.value == "vulnerable"),
        sum(1 for f in report.owasp_findings if f.status.value == "warning"),
    ))
    if report.nist_assessments:
        avg_nist = sum(a.score for a in report.nist_assessments) / len(report.nist_assessments)
        print("    NIST AI RMF:         {:.1f}% average maturity".format(avg_nist))
    if report.ot_ics_findings:
        print("    OT/ICS AI Risks:     {} identified".format(len(report.ot_ics_findings)))
    print("  " + "=" * 58)


def main():
    print_banner()
    args = parse_args()

    if not args.demo:
        print("  [!] No input specified. Use --demo for built-in scenarios.")
        print("  [*] Run 'python run_lais.py --help' for usage information.")
        sys.exit(1)

    from demo_environments import get_environments
    from report_generator import generate_html_report, generate_json_report

    # Load environments
    if args.scenario == "all":
        environments = get_environments()
    else:
        environments = get_environments(args.scenario)

    print("  [*] Loaded {} environment(s)".format(len(environments)))

    all_reports = []
    for env in environments:
        print()
        print("  [*] Assessing: {} ({})".format(env.name, env.environment_type))
        print("  [*] AI assets: {}".format(len(env.assets)))

        report = run_scenario(env, verbose=args.verbose)
        all_reports.append(report)
        print_report_summary(report)

    # Generate reports
    output_dir = ensure_output_dir(args.output)
    print()
    print("  [*] Generating reports...")

    start = time.time()

    html_path = os.path.join(output_dir, "lais_report.html")
    generate_html_report(all_reports, html_path, dark_mode=args.dark)
    html_size = os.path.getsize(html_path) / 1024
    print("    [+] lais_report.html{}  {:.1f} KB".format(" " * 28, html_size))

    json_path = os.path.join(output_dir, "lais_report.json")
    generate_json_report(all_reports, json_path)
    json_size = os.path.getsize(json_path) / 1024
    print("    [+] lais_report.json{}  {:.1f} KB".format(" " * 28, json_size))

    elapsed = time.time() - start
    print("    Reports generated in {:.2f}s".format(elapsed))

    files = [f for f in os.listdir(output_dir) if os.path.isfile(os.path.join(output_dir, f))]
    print()
    print("  " + "=" * 58)
    print("  LAIS COMPLETE")
    print("  " + "=" * 58)
    print("  Output directory: {}".format(os.path.abspath(output_dir)))
    print("  Files generated:  {}".format(len(files)))
    for f in sorted(files):
        fsize = os.path.getsize(os.path.join(output_dir, f)) / 1024
        print("    {} {:<45s} {:.1f} KB".format(chr(8226), f, fsize))
    print("  " + "=" * 58)


if __name__ == "__main__":
    main()
