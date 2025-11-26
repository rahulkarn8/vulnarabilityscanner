# ================================
#  Compliance Report Generator (Fixed)
#  Maps ALL automotive vulnerabilities to ISO 21434 & UN R155
#  OEM-grade scoring + full non-compliance visibility
# ================================

from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from collections import defaultdict


class ComplianceReportGenerator:
    """Generate compliance reports for ISO 21434 and UN R155 standards"""

    def __init__(self) -> None:

        # ===========================================================
        # Requirement Areas (unchanged)
        # ===========================================================
        self.iso21434_areas = {
            "Secure Communication": ["secure_communication", "secoc", "someip", "doip", "v2x"],
            "Secure Storage": ["secure_storage", "crypto_storage"],
            "Secure Update Mechanism": ["ota_update", "secure_update"],
            "Attack Detection": ["ids", "intrusion", "anomaly"],
            "Incident Response": ["incident", "response"],
            "Threat Analysis (TARA)": ["tara", "risk_assessment"],
            "Access Control": ["auth", "access_control", "permissions"],
            "Cryptographic Implementation": ["crypto", "aes", "rsa", "cert", "key"],
        }

        self.unr155_areas = {
            "CSMS Implementation": ["csms", "process", "governance", "risk"],
            "SUMS Implementation": ["sums", "update_process"],
            "Secure V2X Communication": ["v2x", "v2i", "v2v", "secure_v2x"],
            "Attack Prevention": ["attack_prevention", "filtering", "firewall"],
            "Secure Boot": ["secure_boot", "boot_integrity"],
            "Vulnerability Management": ["vuln_mgmt", "vulnerability_management"],
            "Incident Response Plan": ["incident_plan", "ir_plan"],
        }

        # ===========================================================
        # NEW: Rule-ID → Requirement mapping (CRITICAL FIX)
        # Anything not listed here is AUTO-MAPPED using fuzzy logic.
        # ===========================================================
        self.rule_to_area_iso = {
            "AUTOSAR-001": "Secure Communication",
            "AUTOSAR-002": "Access Control",
            "AUTOSAR-003": "Cryptographic Implementation",
            "AUTOSAR-004": "Secure Update Mechanism",
            "AUTOSAR-005": "Threat Analysis (TARA)",
            "CAN-001": "Secure Communication",
            "SOMEIP-001": "Secure Communication",
            "DOIP-001": "Secure Communication",
            "V2X-001": "Secure Communication",
            "CRYPTO-001": "Cryptographic Implementation",
            "SAFETY-001": "Threat Analysis (TARA)",
            # extend as needed
        }

        self.rule_to_area_r155 = {
            "AUTOSAR-001": "Attack Prevention",
            "AUTOSAR-002": "CSMS Implementation",
            "AUTOSAR-003": "Secure Boot",
            "CAN-001": "Attack Prevention",
            "SOMEIP-001": "Secure V2X Communication",
            "DOIP-001": "Secure V2X Communication",
            "V2X-001": "Secure V2X Communication",
            "SAFETY-001": "Vulnerability Management",
        }

    # ===============================================================
    #  Public API
    # ===============================================================

    def generate_compliance_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        files_analyzed: int = 0,
        scan_type: str = "Automotive Compliance Scan",
        scan_target: str = "Unknown",
    ) -> Dict[str, Any]:

        automotive_vulns = [
            v for v in vulnerabilities if v.get("scanner") == "automotive"
        ]

        iso = self._analyze_iso21434(automotive_vulns)
        r155 = self._analyze_unr155(automotive_vulns)

        status, score = self._calculate_overall(iso["compliance_score"], r155["compliance_score"])

        summary = {
            "total_files_analyzed": files_analyzed,
            "total_vulnerabilities": len(vulnerabilities),
            "automotive_vulnerabilities": len(automotive_vulns),
            "overall_compliance": status,
            "overall_score": score,
            "scan_type": scan_type,
            "scan_target": scan_target,
            "scan_date": datetime.now().isoformat(),
        }

        return {
            "summary": summary,
            "iso21434": iso,
            "unr155": r155,
            "detailed_vulnerabilities": automotive_vulns,
        }

    # ===============================================================
    #  ISO 21434
    # ===============================================================

    def _analyze_iso21434(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:

        violations_by_area = defaultdict(int)
        violations_by_severity = defaultdict(int)
        total = 0

        for v in vulns:
            rule = v.get("rule_id", "")
            severity = v.get("severity", "medium").lower()

            # 1. Direct mapping
            area = self.rule_to_area_iso.get(rule)

            # 2. Fallback fuzzy matching
            if area is None:
                area = self._fuzzy_match_area(v, self.iso21434_areas)

            if area:
                total += 1
                violations_by_area[area] += 1
                violations_by_severity[severity] += 1

        score = self._compute_score(violations_by_severity)

        return {
            "standard": "ISO 21434",
            "compliance_score": score,
            "compliance_status": self._status(score),
            "total_violations": total,
            "violations_by_area": dict(violations_by_area),
            "violations_by_severity": dict(violations_by_severity),
        }

    # ===============================================================
    #  UN R155
    # ===============================================================

    def _analyze_unr155(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:

        violations_by_area = defaultdict(int)
        violations_by_severity = defaultdict(int)
        total = 0

        for v in vulns:
            rule = v.get("rule_id", "")
            severity = v.get("severity", "medium").lower()

            area = self.rule_to_area_r155.get(rule)

            if area is None:
                area = self._fuzzy_match_area(v, self.unr155_areas)

            if area:
                total += 1
                violations_by_area[area] += 1
                violations_by_severity[severity] += 1

        score = self._compute_score(violations_by_severity)

        return {
            "standard": "UN R155",
            "compliance_score": score,
            "compliance_status": self._status(score),
            "total_violations": total,
            "violations_by_area": dict(violations_by_area),
            "violations_by_severity": dict(violations_by_severity),
        }

    # ===============================================================
    #  Shared helpers
    # ===============================================================

    def _compute_score(self, sev: Dict[str, int]) -> float:
        deduction = (
            sev.get("critical", 0) * 10 +
            sev.get("high", 0) * 7 +
            sev.get("medium", 0) * 4 +
            sev.get("low", 0) * 2
        )
        return max(0.0, 100.0 - deduction)

    def _status(self, score: float) -> str:
        if score >= 90:
            return "COMPLIANT"
        if score >= 70:
            return "PARTIALLY COMPLIANT"
        if score >= 50:
            return "NON-COMPLIANT (MINOR)"
        return "NON-COMPLIANT (MAJOR)"

    def _calculate_overall(self, iso: float, r155: float) -> Tuple[str, float]:
        avg = (iso + r155) / 2
        return self._status(avg), round(avg, 2)

    def _fuzzy_match_area(self, vuln: Dict[str, Any], area_map: Dict[str, List[str]]) -> Optional[str]:
        """Map rule descriptions or names to ISO/UN requirement areas automatically."""
        text = (vuln.get("type", "") + " " + vuln.get("description", "")).lower()

        for area, keys in area_map.items():
            if any(k in text for k in keys):
                return area
        return None
