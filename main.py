"""
Compliance Auditor — CLI
Usage:
    python main.py --all               # Run all framework checks
    python main.py --framework nist    # Run only NIST 800-53 checks
    python main.py --framework e8      # Run only Essential Eight checks
    python main.py --report reports/   # Set output directory
"""

import argparse
from pathlib import Path
from src.auditor import ComplianceAuditor, ReportRenderer, Framework


FRAMEWORKS_MAP = {
    "nist": Framework.NIST_800_53,
    "iso": Framework.ISO_27001,
    "e8": Framework.ESSENTIAL_EIGHT,
    "gdpr": Framework.GDPR,
}


def main():
    parser = argparse.ArgumentParser(
        description="Automated Security Compliance Auditor — NIST / ISO 27001 / Essential Eight"
    )
    parser.add_argument("--all", action="store_true", help="Run all framework checks")
    parser.add_argument(
        "--framework", choices=list(FRAMEWORKS_MAP.keys()),
        help="Run checks for a specific framework"
    )
    parser.add_argument("--report", type=Path, default=Path("reports"), help="Output directory")
    parser.add_argument("--auditor", default="automated", help="Auditor name/ID")
    args = parser.parse_args()

    frameworks = None
    if args.framework:
        frameworks = [FRAMEWORKS_MAP[args.framework]]

    print("\n🔒 Compliance Auditor Starting...\n" + "="*50)
    auditor = ComplianceAuditor(auditor=args.auditor)
    report = auditor.run_audit(frameworks=frameworks)

    renderer = ReportRenderer(report, args.report)
    json_path = renderer.to_json()
    md_path = renderer.to_markdown()

    s = report.summary
    print(f"\n{'='*50}")
    print(f"  Compliance Score : {s['compliance_score']}%")
    print(f"  Passed           : {s['passed']}/{s['total_checks']}")
    print(f"  Critical Failures: {s['critical_failures']}")
    print(f"  JSON Report      : {json_path}")
    print(f"  Markdown Report  : {md_path}")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
