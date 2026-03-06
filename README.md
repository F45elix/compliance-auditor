# 📋 Automated Compliance Auditor

> **Skills demonstrated:** NIST 800-53 · ISO/IEC 27001:2022 · ASD Essential Eight · Risk management · Security controls · Compliance automation · Python scripting

An automated security compliance checking engine that validates system configurations against three major frameworks — **NIST SP 800-53**, **ISO/IEC 27001**, and the **ASD Essential Eight** — and generates executive-ready audit reports. Directly mirrors the skills required by Australian government contractors and UK financial sector security roles.

---

## 📋 Why This Project

Compliance and risk management are among the **top-cited skills** in Australian/UK visa-sponsored security roles, especially in government, finance, and healthcare sectors:

| Framework | Why It Matters | Regions |
|---|---|---|
| NIST SP 800-53 Rev 5 | US Federal + adopted by AU/UK govt contractors | AU 🇦🇺 UK 🇬🇧 |
| ISO/IEC 27001:2022 | ISMS certification required by enterprise | Global |
| ASD Essential Eight | **Mandatory** for Australian government agencies | AU 🇦🇺 |
| UK Cyber Essentials | UK government procurement requirement | UK 🇬🇧 |

---

## 🚀 Quick Start

```bash
git clone https://github.com/F45elix/compliance-auditor.git
cd compliance-auditor
pip install -r requirements.txt

# Run all framework checks
python main.py --all

# Run only Essential Eight (Australian government)
python main.py --framework e8

# Run NIST 800-53 checks with custom output dir
python main.py --framework nist --report /tmp/audit-results/

# Run tests
pytest tests/ -v
```

---

## ✅ Control Checks Implemented

### NIST SP 800-53 Rev 5
| Control | Name | Category |
|---|---|---|
| AC-2 | Account Management | Access Control |
| AU-6 | Audit Review, Analysis | Audit |
| IA-5 | Authenticator Management | Identification & Auth |
| SI-2 | Flaw Remediation | System & Info Integrity |

### ISO/IEC 27001:2022
| Control | Name |
|---|---|
| A.9.2.1 | User Registration & De-registration |
| A.12.6.1 | Management of Technical Vulnerabilities |

### ASD Essential Eight
| Control | Maturity Levels |
|---|---|
| Application Control | 0–3 |
| Patch Operating Systems | 0–3 |
| Multi-Factor Authentication | 0–3 |
| Regular Backups | 0–3 |

---

## 📊 Sample Report

```
## ASD Essential Eight

### ❌ Multi-Factor Authentication (E8-MFA)
Status: FAIL | Risk: CRITICAL | Control: ASD Essential Eight — MFA

> Evidence: No MFA PAM modules detected in SSH/common-auth
> Remediation: Enable MFA for all remote access (SSH, VPN, RDP). 
  Use FIDO2/WebAuthn. Configure Google Authenticator PAM module.
```

---

## 🏗 Architecture

```
ComplianceAuditor
  └── SystemChecker
        ├── NIST checks (AC-2, AU-6, IA-5, SI-2)
        ├── ISO checks (A.9.2.1, A.12.6.1)
        └── Essential Eight (AppControl, PatchOS, MFA, Backup)
  └── ReportRenderer
        ├── JSON report (machine-readable)
        └── Markdown report (human-readable)
```

---

## 🎓 Relevant Certifications

- **CISSP** (all 8 domains, governance emphasis)
- **CISM** (risk and compliance focus)
- **ISO 27001 Lead Auditor**
- **CRISC** (risk and controls)
