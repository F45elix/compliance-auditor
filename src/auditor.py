"""
Automated Compliance Auditor
==============================
Performs automated security control checks against three frameworks:

  1. NIST SP 800-53 Rev 5 (US Federal + widely used in AU/UK govt)
  2. ISO/IEC 27001:2022 (Annex A controls)
  3. ASD Essential Eight Maturity Model (Australian government mandate)

Each check returns a ComplianceResult with:
  - Pass / Fail / Not Applicable / Manual Review Required
  - Evidence collected
  - Remediation steps
  - Regulatory reference

Skills: Compliance, risk management, security controls, NIST, ISO 27001,
        ASD Essential Eight, Python, reporting, PowerShell-equivalent automation
"""

import os
import re
import json
import platform
import subprocess
import hashlib
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional, Callable

logger = logging.getLogger("compliance.auditor")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    ERROR = "ERROR"


class Framework(str, Enum):
    NIST_800_53 = "NIST SP 800-53 Rev 5"
    ISO_27001 = "ISO/IEC 27001:2022"
    ESSENTIAL_EIGHT = "ASD Essential Eight"
    GDPR = "GDPR / UK GDPR"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class ComplianceResult:
    check_id: str
    check_name: str
    framework: Framework
    control_ref: str          # e.g. "NIST AC-2", "ISO A.9.2.1"
    status: CheckStatus
    evidence: str
    remediation: str
    risk_level: str           # CRITICAL / HIGH / MEDIUM / LOW
    maturity_level: Optional[int] = None   # Essential Eight: 0–3
    details: Optional[str] = None


@dataclass
class AuditReport:
    report_id: str
    generated_at: str
    target_system: str
    auditor: str
    framework_results: dict[str, list[ComplianceResult]] = field(default_factory=dict)
    summary: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Individual Control Checks
# ---------------------------------------------------------------------------

class SystemChecker:
    """
    Cross-platform security control checks.
    Each method returns a ComplianceResult.
    Methods are grouped by framework.
    """

    OS = platform.system()

    # ── NIST SP 800-53 Checks ──────────────────────────────────────────────

    def nist_ac2_account_management(self) -> ComplianceResult:
        """NIST AC-2: Account Management — Check for inactive/default accounts."""
        evidence_parts = []
        status = CheckStatus.MANUAL_REVIEW
        details = ""

        try:
            if self.OS == "Linux":
                # Check for users with UID 0 (root equivalents)
                with open("/etc/passwd", "r") as f:
                    passwd = f.read()
                uid0_users = [
                    line.split(":")[0]
                    for line in passwd.splitlines()
                    if len(line.split(":")) > 2 and line.split(":")[2] == "0"
                ]
                evidence_parts.append(f"UID-0 accounts: {uid0_users}")

                # Check for accounts with empty passwords
                try:
                    shadow = subprocess.check_output(
                        ["awk", "-F:", "($2 == \"\" ) {print $1}", "/etc/shadow"],
                        stderr=subprocess.DEVNULL, text=True, timeout=5
                    ).strip()
                    if shadow:
                        evidence_parts.append(f"Empty password accounts: {shadow}")
                        status = CheckStatus.FAIL
                    else:
                        status = CheckStatus.PASS
                except (subprocess.SubprocessError, PermissionError):
                    status = CheckStatus.MANUAL_REVIEW
            else:
                evidence_parts.append("Windows: Manual review of AD account policies required")
                status = CheckStatus.MANUAL_REVIEW
        except Exception as e:
            evidence_parts.append(f"Check error: {e}")
            status = CheckStatus.ERROR

        return ComplianceResult(
            check_id="NIST-AC-2",
            check_name="Account Management",
            framework=Framework.NIST_800_53,
            control_ref="NIST SP 800-53 AC-2",
            status=status,
            evidence="; ".join(evidence_parts) or "No evidence collected",
            remediation=(
                "Disable or remove inactive accounts. Enforce password policies. "
                "Implement quarterly account reviews. Use privileged access management (PAM)."
            ),
            risk_level="HIGH",
        )

    def nist_au6_audit_review(self) -> ComplianceResult:
        """NIST AU-6: Audit Review — Verify audit logging is enabled."""
        evidence_parts = []
        status = CheckStatus.PASS

        try:
            if self.OS == "Linux":
                result = subprocess.run(
                    ["systemctl", "is-active", "auditd"],
                    capture_output=True, text=True, timeout=5
                )
                if "active" in result.stdout:
                    evidence_parts.append("auditd service: ACTIVE")
                else:
                    evidence_parts.append("auditd service: INACTIVE")
                    status = CheckStatus.FAIL

                # Check audit rules
                audit_rules = Path("/etc/audit/audit.rules")
                if audit_rules.exists():
                    rules_count = len(audit_rules.read_text().splitlines())
                    evidence_parts.append(f"Audit rules: {rules_count} rules defined")
                else:
                    evidence_parts.append("Audit rules file: NOT FOUND")
                    status = CheckStatus.FAIL
            else:
                evidence_parts.append("Windows Event Log: Manual review required")
                status = CheckStatus.MANUAL_REVIEW
        except Exception as e:
            evidence_parts.append(f"Check error: {e}")
            status = CheckStatus.ERROR

        return ComplianceResult(
            check_id="NIST-AU-6",
            check_name="Audit Review, Analysis and Reporting",
            framework=Framework.NIST_800_53,
            control_ref="NIST SP 800-53 AU-6",
            status=status,
            evidence="; ".join(evidence_parts),
            remediation=(
                "Install and configure auditd. Define rules to log privileged commands, "
                "file access, and authentication events. Forward logs to SIEM."
            ),
            risk_level="HIGH",
        )

    def nist_ia5_authenticator_management(self) -> ComplianceResult:
        """NIST IA-5: Authenticator Management — Check password policy settings."""
        evidence_parts = []
        status = CheckStatus.PASS

        try:
            if self.OS == "Linux":
                # Check /etc/login.defs for password age settings
                login_defs = Path("/etc/login.defs")
                if login_defs.exists():
                    content = login_defs.read_text()
                    max_days_m = re.search(r"^PASS_MAX_DAYS\s+(\d+)", content, re.M)
                    min_len_m = re.search(r"^PASS_MIN_LEN\s+(\d+)", content, re.M)
                    max_days = int(max_days_m.group(1)) if max_days_m else 99999
                    min_len = int(min_len_m.group(1)) if min_len_m else 0

                    evidence_parts.append(f"PASS_MAX_DAYS: {max_days}")
                    evidence_parts.append(f"PASS_MIN_LEN: {min_len}")

                    if max_days > 90:
                        status = CheckStatus.FAIL
                        evidence_parts.append("Password max age exceeds 90 days")
                    if min_len < 12:
                        status = CheckStatus.FAIL
                        evidence_parts.append("Minimum password length < 12 characters")
                else:
                    evidence_parts.append("/etc/login.defs not found")
                    status = CheckStatus.MANUAL_REVIEW
            else:
                evidence_parts.append("Windows: Check Group Policy password settings")
                status = CheckStatus.MANUAL_REVIEW
        except Exception as e:
            evidence_parts.append(f"Check error: {e}")
            status = CheckStatus.ERROR

        return ComplianceResult(
            check_id="NIST-IA-5",
            check_name="Authenticator Management",
            framework=Framework.NIST_800_53,
            control_ref="NIST SP 800-53 IA-5",
            status=status,
            evidence="; ".join(evidence_parts),
            remediation=(
                "Set PASS_MAX_DAYS=90, PASS_MIN_LEN=12. "
                "Install libpam-pwquality. Enforce complexity rules. "
                "Consider passphrase policies per NIST 800-63B."
            ),
            risk_level="HIGH",
        )

    def nist_si2_flaw_remediation(self) -> ComplianceResult:
        """NIST SI-2: Flaw Remediation — Check for available OS updates."""
        evidence_parts = []
        status = CheckStatus.PASS

        try:
            if self.OS == "Linux":
                # Check for available security updates
                result = subprocess.run(
                    ["apt-get", "--simulate", "--just-print", "upgrade"],
                    capture_output=True, text=True, timeout=30
                )
                output = result.stdout + result.stderr
                upgrade_count_m = re.search(r"(\d+) upgraded", output)
                count = int(upgrade_count_m.group(1)) if upgrade_count_m else 0
                evidence_parts.append(f"Available upgrades: {count}")
                if count > 0:
                    status = CheckStatus.FAIL
                    evidence_parts.append("Pending system updates detected")
            else:
                evidence_parts.append("Windows: Check Windows Update status manually")
                status = CheckStatus.MANUAL_REVIEW
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            evidence_parts.append(f"Package manager check failed: {e}")
            status = CheckStatus.MANUAL_REVIEW

        return ComplianceResult(
            check_id="NIST-SI-2",
            check_name="Flaw Remediation / Patch Management",
            framework=Framework.NIST_800_53,
            control_ref="NIST SP 800-53 SI-2",
            status=status,
            evidence="; ".join(evidence_parts),
            remediation=(
                "Apply all available security patches within SLA: "
                "Critical = 24h, High = 7 days, Medium = 30 days, Low = 90 days. "
                "Enable unattended-upgrades for automatic security patches."
            ),
            risk_level="CRITICAL",
        )

    # ── ISO 27001 Checks ───────────────────────────────────────────────────

    def iso_a921_user_registration(self) -> ComplianceResult:
        """ISO A.9.2.1: User Registration and De-registration."""
        # Check for locked/disabled accounts older than 90 days
        evidence_parts = []
        status = CheckStatus.MANUAL_REVIEW

        try:
            if self.OS == "Linux":
                result = subprocess.run(
                    ["lastlog", "--time", "90"],
                    capture_output=True, text=True, timeout=10
                )
                lines = [l for l in result.stdout.splitlines() if "**Never" not in l and l.strip()]
                if lines:
                    inactive = len(lines) - 1  # subtract header
                    evidence_parts.append(f"Accounts not logged in for 90+ days: {max(0, inactive)}")
                    status = CheckStatus.FAIL if inactive > 0 else CheckStatus.PASS
                else:
                    evidence_parts.append("lastlog output empty or unavailable")
            else:
                evidence_parts.append("Manual review: Check AD for stale accounts > 90 days")
        except Exception as e:
            evidence_parts.append(f"Check error: {e}")

        return ComplianceResult(
            check_id="ISO-A.9.2.1",
            check_name="User Registration and De-registration",
            framework=Framework.ISO_27001,
            control_ref="ISO/IEC 27001:2022 A.9.2.1",
            status=status,
            evidence="; ".join(evidence_parts) or "Manual review required",
            remediation=(
                "Implement a formal user provisioning process. "
                "Disable accounts inactive for >90 days. "
                "Conduct quarterly access reviews."
            ),
            risk_level="MEDIUM",
        )

    def iso_a1211_technical_vuln(self) -> ComplianceResult:
        """ISO A.12.6.1: Management of Technical Vulnerabilities."""
        evidence_parts = []
        status = CheckStatus.MANUAL_REVIEW

        # Check for vulnerability scanner presence
        scanners = ["nessus", "openvas", "trivy", "grype", "snyk"]
        found_scanners = []
        for scanner in scanners:
            result = subprocess.run(["which", scanner], capture_output=True, timeout=3)
            if result.returncode == 0:
                found_scanners.append(scanner)

        if found_scanners:
            evidence_parts.append(f"Vulnerability scanners found: {found_scanners}")
            status = CheckStatus.PASS
        else:
            evidence_parts.append("No vulnerability scanner found in PATH")
            status = CheckStatus.FAIL

        return ComplianceResult(
            check_id="ISO-A.12.6.1",
            check_name="Management of Technical Vulnerabilities",
            framework=Framework.ISO_27001,
            control_ref="ISO/IEC 27001:2022 A.12.6.1",
            status=status,
            evidence="; ".join(evidence_parts),
            remediation=(
                "Deploy a vulnerability scanner (e.g., OpenVAS, Trivy for containers). "
                "Schedule weekly scans. Maintain a vulnerability register. "
                "Define remediation SLAs aligned with CVSS scores."
            ),
            risk_level="HIGH",
        )

    # ── ASD Essential Eight Checks ─────────────────────────────────────────

    def e8_application_control(self) -> ComplianceResult:
        """Essential Eight: Application Control (Maturity Level 1–3)."""
        evidence_parts = []
        maturity = 0

        try:
            if self.OS == "Linux":
                # Check for AppArmor or SELinux
                apparmor = subprocess.run(
                    ["aa-status"], capture_output=True, timeout=5
                )
                selinux = subprocess.run(
                    ["getenforce"], capture_output=True, text=True, timeout=5
                )

                if apparmor.returncode == 0:
                    evidence_parts.append("AppArmor: ACTIVE")
                    maturity = 2
                elif "Enforcing" in selinux.stdout:
                    evidence_parts.append("SELinux: ENFORCING")
                    maturity = 2
                elif "Permissive" in selinux.stdout:
                    evidence_parts.append("SELinux: PERMISSIVE (not enforcing)")
                    maturity = 1
                else:
                    evidence_parts.append("No application control framework detected")
                    maturity = 0
            else:
                evidence_parts.append("Windows: Check AppLocker / WDAC policy status")
                maturity = 0
        except Exception as e:
            evidence_parts.append(f"Check error: {e}")

        status = CheckStatus.PASS if maturity >= 2 else CheckStatus.FAIL

        return ComplianceResult(
            check_id="E8-APP-CTRL",
            check_name="Application Control",
            framework=Framework.ESSENTIAL_EIGHT,
            control_ref="ASD Essential Eight — Application Control",
            status=status,
            evidence="; ".join(evidence_parts),
            remediation=(
                "Linux: Enable AppArmor in enforce mode, or configure SELinux. "
                "Windows: Implement AppLocker or Windows Defender Application Control (WDAC). "
                "Maintain an approved application allowlist."
            ),
            risk_level="CRITICAL",
            maturity_level=maturity,
        )

    def e8_patch_os(self) -> ComplianceResult:
        """Essential Eight: Patch Operating Systems (Maturity Level)."""
        evidence_parts = []
        maturity = 0

        try:
            if self.OS == "Linux":
                # Check last update time
                if Path("/var/lib/apt/periodic/update-success-stamp").exists():
                    import time
                    mtime = Path("/var/lib/apt/periodic/update-success-stamp").stat().st_mtime
                    days_ago = (time.time() - mtime) / 86400
                    evidence_parts.append(f"Last apt update: {days_ago:.1f} days ago")
                    if days_ago <= 7:
                        maturity = 3
                    elif days_ago <= 30:
                        maturity = 2
                    elif days_ago <= 90:
                        maturity = 1
                    else:
                        maturity = 0
                else:
                    evidence_parts.append("Cannot determine last update time")
                    maturity = 0
        except Exception as e:
            evidence_parts.append(f"Check error: {e}")

        status = CheckStatus.PASS if maturity >= 2 else CheckStatus.FAIL

        return ComplianceResult(
            check_id="E8-PATCH-OS",
            check_name="Patch Operating Systems",
            framework=Framework.ESSENTIAL_EIGHT,
            control_ref="ASD Essential Eight — Patch Operating Systems",
            status=status,
            evidence="; ".join(evidence_parts) or "No evidence collected",
            remediation=(
                "Apply security patches within 48 hours for CVSS ≥9.0 vulnerabilities. "
                "Enable automated security updates. Use a patch management platform."
            ),
            risk_level="CRITICAL",
            maturity_level=maturity,
        )

    def e8_mfa(self) -> ComplianceResult:
        """Essential Eight: Multi-Factor Authentication."""
        evidence_parts = []
        status = CheckStatus.MANUAL_REVIEW

        try:
            if self.OS == "Linux":
                # Check PAM for MFA modules
                pam_dirs = [Path("/etc/pam.d/sshd"), Path("/etc/pam.d/common-auth")]
                mfa_found = False
                for pam_file in pam_dirs:
                    if pam_file.exists():
                        content = pam_file.read_text()
                        if "google_authenticator" in content or "pam_duo" in content or "pam_oath" in content:
                            evidence_parts.append(f"MFA module in {pam_file.name}: FOUND")
                            mfa_found = True
                if not mfa_found:
                    evidence_parts.append("No MFA PAM modules detected in SSH/common-auth")
                status = CheckStatus.PASS if mfa_found else CheckStatus.FAIL
        except Exception as e:
            evidence_parts.append(f"Check error: {e}")

        return ComplianceResult(
            check_id="E8-MFA",
            check_name="Multi-Factor Authentication",
            framework=Framework.ESSENTIAL_EIGHT,
            control_ref="ASD Essential Eight — Multi-Factor Authentication",
            status=status,
            evidence="; ".join(evidence_parts),
            remediation=(
                "Enable MFA for all remote access (SSH, VPN, RDP). "
                "Use FIDO2/WebAuthn where possible. "
                "Configure Google Authenticator or Duo PAM module for SSH."
            ),
            risk_level="CRITICAL",
            maturity_level=0 if status == CheckStatus.FAIL else 2,
        )

    def e8_backup(self) -> ComplianceResult:
        """Essential Eight: Regular Backups."""
        evidence_parts = []

        # Check for common backup tools
        backup_tools = ["rsync", "borg", "restic", "duplicati", "bacula", "amanda"]
        found = [t for t in backup_tools
                 if subprocess.run(["which", t], capture_output=True, timeout=3).returncode == 0]

        if found:
            evidence_parts.append(f"Backup tools found: {found}")
            # Check for recent backup directories
            common_backup_paths = [Path("/backup"), Path("/var/backup"), Path("/mnt/backup")]
            found_paths = [str(p) for p in common_backup_paths if p.exists()]
            if found_paths:
                evidence_parts.append(f"Backup directories: {found_paths}")
            status = CheckStatus.PASS
            maturity = 2
        else:
            evidence_parts.append("No recognised backup tools found in PATH")
            status = CheckStatus.FAIL
            maturity = 0

        return ComplianceResult(
            check_id="E8-BACKUP",
            check_name="Regular Backups",
            framework=Framework.ESSENTIAL_EIGHT,
            control_ref="ASD Essential Eight — Regular Backups",
            status=status,
            evidence="; ".join(evidence_parts),
            remediation=(
                "Implement 3-2-1 backup strategy: 3 copies, 2 media types, 1 offsite. "
                "Test restoration quarterly. Encrypt backups. "
                "Ensure backups are immutable/offline to prevent ransomware encryption."
            ),
            risk_level="HIGH",
            maturity_level=maturity,
        )


# ---------------------------------------------------------------------------
# Audit Engine
# ---------------------------------------------------------------------------

class ComplianceAuditor:
    """
    Orchestrates all compliance checks and generates a structured report.
    """

    def __init__(self, auditor: str = "automated"):
        self.checker = SystemChecker()
        self.auditor = auditor
        self._all_checks: list[Callable] = [
            # NIST
            self.checker.nist_ac2_account_management,
            self.checker.nist_au6_audit_review,
            self.checker.nist_ia5_authenticator_management,
            self.checker.nist_si2_flaw_remediation,
            # ISO 27001
            self.checker.iso_a921_user_registration,
            self.checker.iso_a1211_technical_vuln,
            # Essential Eight
            self.checker.e8_application_control,
            self.checker.e8_patch_os,
            self.checker.e8_mfa,
            self.checker.e8_backup,
        ]

    def run_audit(self, frameworks: list[Framework] = None) -> AuditReport:
        """Run all checks (or filter by framework) and return an AuditReport."""
        report = AuditReport(
            report_id=f"AUDIT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            generated_at=datetime.now(timezone.utc).isoformat(),
            target_system=platform.node(),
            auditor=self.auditor,
        )

        results_by_framework: dict[str, list[ComplianceResult]] = {}

        for check_fn in self._all_checks:
            try:
                result = check_fn()
                if frameworks and result.framework not in frameworks:
                    continue
                fw_key = result.framework.value
                results_by_framework.setdefault(fw_key, []).append(result)
                icon = "✅" if result.status == CheckStatus.PASS else "❌" if result.status == CheckStatus.FAIL else "⚠️"
                logger.info("%s [%s] %s — %s", icon, result.status.value, result.check_id, result.check_name)
            except Exception as e:
                logger.error("Check %s failed: %s", check_fn.__name__, e)

        report.framework_results = results_by_framework
        report.summary = self._summarise(results_by_framework)
        return report

    @staticmethod
    def _summarise(results_by_framework: dict) -> dict:
        all_results = [r for results in results_by_framework.values() for r in results]
        return {
            "total_checks": len(all_results),
            "passed": sum(1 for r in all_results if r.status == CheckStatus.PASS),
            "failed": sum(1 for r in all_results if r.status == CheckStatus.FAIL),
            "manual_review": sum(1 for r in all_results if r.status == CheckStatus.MANUAL_REVIEW),
            "critical_failures": sum(1 for r in all_results if r.status == CheckStatus.FAIL and r.risk_level == "CRITICAL"),
            "compliance_score": round(
                sum(1 for r in all_results if r.status == CheckStatus.PASS) / max(len(all_results), 1) * 100, 1
            ),
        }


# ---------------------------------------------------------------------------
# Report Renderer
# ---------------------------------------------------------------------------

class ReportRenderer:
    """Renders audit reports to JSON and Markdown."""

    def __init__(self, report: AuditReport, output_dir: Path):
        self.report = report
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def to_json(self) -> Path:
        path = self.output_dir / f"{self.report.report_id}.json"
        path.write_text(json.dumps(asdict(self.report), indent=2, default=str))
        return path

    def to_markdown(self) -> Path:
        path = self.output_dir / f"{self.report.report_id}.md"
        s = self.report.summary
        lines = [
            f"# 🔒 Compliance Audit Report",
            f"**Report ID:** `{self.report.report_id}`  ",
            f"**Target:** {self.report.target_system}  ",
            f"**Generated:** {self.report.generated_at}  ",
            f"**Auditor:** {self.report.auditor}",
            "",
            "## 📊 Executive Summary",
            f"| Metric | Value |",
            f"|---|---|",
            f"| Total Checks | {s['total_checks']} |",
            f"| ✅ Passed | {s['passed']} |",
            f"| ❌ Failed | {s['failed']} |",
            f"| ⚠️ Manual Review | {s['manual_review']} |",
            f"| 🔴 Critical Failures | {s['critical_failures']} |",
            f"| **Compliance Score** | **{s['compliance_score']}%** |",
            "",
        ]
        for fw, results in self.report.framework_results.items():
            lines += [f"## {fw}", ""]
            for r in results:
                icon = {"PASS": "✅", "FAIL": "❌", "MANUAL_REVIEW": "⚠️"}.get(r.status.value, "❓")
                lines += [
                    f"### {icon} {r.check_name} (`{r.check_id}`)",
                    f"**Status:** {r.status.value} | **Risk:** {r.risk_level} | **Control:** {r.control_ref}",
                    f"> **Evidence:** {r.evidence}",
                    f"> **Remediation:** {r.remediation}",
                    "",
                ]
        path.write_text("\n".join(lines))
        return path
