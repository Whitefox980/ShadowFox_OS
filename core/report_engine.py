#!/usr/bin/env python3
"""
ShadowOS Cloud v1.0 - Report Engine
Professional Security Assessment Reporting System

Developed by ShadowFox Elite Security Team
Licensed under MIT License - Educational & Research Use Only
"""

import json
import os
import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import base64
import hashlib
from enum import Enum
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from jinja2 import Template
import pdfkit
from weasyprint import HTML, CSS
import markdown

class ReportFormat(Enum):
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"

class CVSSv3:
    """CVSS v3.1 Score Calculator"""
    
    def __init__(self):
        self.base_metrics = {
            'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},  # Attack Vector
            'AC': {'L': 0.77, 'H': 0.44},  # Attack Complexity
            'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},  # Privileges Required
            'UI': {'N': 0.85, 'R': 0.62},  # User Interaction
            'S': {'U': 'Unchanged', 'C': 'Changed'},  # Scope
            'C': {'N': 0, 'L': 0.22, 'H': 0.56},  # Confidentiality
            'I': {'N': 0, 'L': 0.22, 'H': 0.56},  # Integrity
            'A': {'N': 0, 'L': 0.22, 'H': 0.56}   # Availability
        }
    
    def calculate_score(self, metrics: Dict[str, str]) -> float:
        """Calculate CVSS v3.1 Base Score"""
        try:
            # Impact Sub-Score
            iss_base = 1 - ((1 - self.base_metrics['C'][metrics['C']]) * 
                           (1 - self.base_metrics['I'][metrics['I']]) * 
                           (1 - self.base_metrics['A'][metrics['A']]))
            
            if metrics['S'] == 'U':  # Scope Unchanged
                impact = 6.42 * iss_base
            else:  # Scope Changed
                impact = 7.52 * (iss_base - 0.029) - 3.25 * pow(iss_base - 0.02, 15)
            
            # Exploitability Sub-Score
            exploitability = (8.22 * self.base_metrics['AV'][metrics['AV']] * 
                            self.base_metrics['AC'][metrics['AC']] * 
                            self.base_metrics['PR'][metrics['PR']] * 
                            self.base_metrics['UI'][metrics['UI']])
            
            # Base Score
            if impact <= 0:
                return 0.0
            
            if metrics['S'] == 'U':
                base_score = min(impact + exploitability, 10)
            else:
                base_score = min(1.08 * (impact + exploitability), 10)
            
            return round(base_score, 1)
            
        except Exception as e:
            return 0.0

@dataclass
class SecurityFinding:
    """Enhanced security finding with professional scoring"""
    id: str
    title: str
    severity: str
    cvss_score: float
    cvss_vector: str
    cwe_id: str
    owasp_category: str
    
    # Technical details
    affected_url: str
    http_method: str
    vulnerable_parameter: str
    payload: str
    
    # Evidence
    request_sample: str
    response_sample: str
    poc_steps: List[str]
    business_impact: str
    
    # ShadowFox Scoring System (3v3)
    technical_complexity: int  # 1-3 (1=Simple, 2=Moderate, 3=Complex)
    exploit_reliability: int   # 1-3 (1=Unreliable, 2=Moderate, 3=Reliable)
    business_criticality: int  # 1-3 (1=Low, 2=Medium, 3=High)
    
    # Remediation
    remediation: str
    remediation_complexity: str
    estimated_fix_time: str
    
    # Metadata
    discovered_by: str
    discovery_date: datetime.datetime
    tool_signature: str
    confidence_level: float

@dataclass
class ScanStatistics:
    """Comprehensive scan statistics"""
    target_domain: str
    scan_start_time: datetime.datetime
    scan_end_time: datetime.datetime
    total_requests: int
    total_endpoints_tested: int
    scan_duration_minutes: int
    
    # Findings breakdown
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    
    # Coverage metrics
    coverage_percentage: float
    false_positive_rate: float
    detection_accuracy: float

class ShadowOSReportEngine:
    """
    📊 Professional Security Assessment Reporting Engine
    
    Features:
    - Enterprise-grade report templates
    - CVSS v3.1 scoring integration
    - ShadowFox 3v3 PoC scoring system
    - Multiple export formats (MD, HTML, PDF)
    - Executive and technical summaries
    - Compliance mapping (OWASP, CWE)
    - Professional disclaimers and legal notices
    """
    
    def __init__(self, output_dir: str = "reports/"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Report metadata
        self.report_template_version = "2.1.0"
        self.shadowos_version = "1.0.0"
        self.team_signature = "ShadowFox Elite Security Team"
        
        # Initialize CVSS calculator
        self.cvss_calculator = CVSSv3()
        
        # Legal and compliance
        self.legal_disclaimers = self.load_legal_disclaimers()
        self.compliance_mappings = self.load_compliance_mappings()
        
    def load_legal_disclaimers(self) -> Dict[str, str]:
        """Load professional legal disclaimers"""
        return {
            "main_disclaimer": """
IMPORTANT LEGAL DISCLAIMER AND TERMS OF USE

This security assessment report has been prepared by ShadowFox Elite Security Team 
using ShadowOS automated security testing platform. This report is intended solely 
for the authorized recipient and contains confidential and proprietary information.

SCOPE AND LIMITATIONS:
• This assessment was conducted using automated tools and may not identify all security vulnerabilities
• Manual verification is recommended for all findings before remediation
• The assessment scope was limited to the specified target domains and timeframe
• New vulnerabilities may emerge after the assessment date

LEGAL COMPLIANCE:
• All testing was conducted in accordance with applicable laws and regulations
• No unauthorized access to systems or data was attempted beyond scope
• All findings are reported in good faith for security improvement purposes
• This report should be handled as CONFIDENTIAL information

LIABILITY DISCLAIMER:
ShadowFox Elite Security Team provides this report "AS IS" without warranty of any kind.
We shall not be liable for any damages arising from the use of this report or the 
implementation of any recommendations contained herein.

For questions regarding this report, please contact: security@shadowfox.team
            """,
            
            "testing_methodology": """
TESTING METHODOLOGY DISCLAIMER

The ShadowOS platform employs advanced automated testing techniques including:
• Dynamic Application Security Testing (DAST)
• Business Logic Flaw Detection
• Authentication and Authorization Testing
• API Security Assessment
• OWASP Top 10 Vulnerability Analysis

All testing was conducted using ethical hacking methodologies and industry best practices.
No actual exploitation of vulnerabilities was performed beyond proof-of-concept validation.
            """,
            
            "data_handling": """
DATA HANDLING AND PRIVACY NOTICE

During the assessment process:
• Only test data was used where possible
• Any sensitive data encountered was immediately secured and not retained
• All testing activities were logged for quality assurance purposes
• No personal or confidential data was accessed, copied, or retained
• All testing data will be securely deleted after report delivery

This assessment complies with relevant data protection regulations including GDPR, CCPA, and industry standards.
            """
        }
        
    def load_compliance_mappings(self) -> Dict[str, Dict]:
        """Load compliance framework mappings"""
        return {
            "owasp_top10_2021": {
                "A01": "Broken Access Control",
                "A02": "Cryptographic Failures", 
                "A03": "Injection",
                "A04": "Insecure Design",
                "A05": "Security Misconfiguration",
                "A06": "Vulnerable and Outdated Components",
                "A07": "Identification and Authentication Failures",
                "A08": "Software and Data Integrity Failures",
                "A09": "Security Logging and Monitoring Failures",
                "A10": "Server-Side Request Forgery (SSRF)"
            },
            
            "cwe_mappings": {
                "CWE-79": "Cross-site Scripting (XSS)",
                "CWE-89": "SQL Injection",
                "CWE-200": "Information Exposure",
                "CWE-269": "Improper Privilege Management",
                "CWE-287": "Improper Authentication",
                "CWE-352": "Cross-Site Request Forgery (CSRF)",
                "CWE-639": "Authorization Bypass Through User-Controlled Key",
                "CWE-770": "Allocation of Resources Without Limits",
                "CWE-918": "Server-Side Request Forgery (SSRF)"
            }
        }
        
    def calculate_shadowfox_score(self, finding: SecurityFinding) -> Dict[str, Any]:
        """Calculate ShadowFox 3v3 PoC Scoring System"""
        
        # 3v3 Scoring: Technical Complexity + Exploit Reliability + Business Criticality
        total_score = (finding.technical_complexity + 
                      finding.exploit_reliability + 
                      finding.business_criticality)
        
        # Convert to percentage and risk level
        score_percentage = (total_score / 9.0) * 100
        
        if score_percentage >= 80:
            risk_level = "CRITICAL"
            priority = "IMMEDIATE"
        elif score_percentage >= 60:
            risk_level = "HIGH"
            priority = "URGENT"
        elif score_percentage >= 40:
            risk_level = "MEDIUM"
            priority = "PLANNED"
        else:
            risk_level = "LOW"
            priority = "MONITORED"
            
        return {
            "total_score": total_score,
            "max_score": 9,
            "score_percentage": round(score_percentage, 1),
            "risk_level": risk_level,
            "remediation_priority": priority,
            "scoring_breakdown": {
                "technical_complexity": f"{finding.technical_complexity}/3",
                "exploit_reliability": f"{finding.exploit_reliability}/3", 
                "business_criticality": f"{finding.business_criticality}/3"
            }
        }
        
    def enhance_finding_with_intelligence(self, finding: SecurityFinding) -> SecurityFinding:
        """Enhance finding with additional intelligence and scoring"""
        
        # Auto-generate CVSS vector if not provided
        if not finding.cvss_vector:
            finding.cvss_vector = self.generate_cvss_vector(finding)
            
        # Calculate CVSS score if not provided
        if not finding.cvss_score:
            cvss_metrics = self.parse_cvss_vector(finding.cvss_vector)
            finding.cvss_score = self.cvss_calculator.calculate_score(cvss_metrics)
            
        # Map to OWASP category
        if not finding.owasp_category:
            finding.owasp_category = self.map_to_owasp_category(finding.cwe_id)
            
        # Add tool signature
        finding.tool_signature = f"ShadowOS v{self.shadowos_version}"
        finding.discovered_by = self.team_signature
        
        return finding
        
    def generate_cvss_vector(self, finding: SecurityFinding) -> str:
        """Generate CVSS vector based on finding characteristics"""
        
        # Default CVSS metrics based on vulnerability type
        cvss_mappings = {
            "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "auth_bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "sql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "business_logic": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        }
        
        # Try to match finding type
        finding_type = finding.title.lower()
        for vuln_type, vector in cvss_mappings.items():
            if vuln_type in finding_type:
                return vector
                
        # Default vector
        return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
        
    def parse_cvss_vector(self, vector: str) -> Dict[str, str]:
        """Parse CVSS vector string into metrics dictionary"""
        metrics = {}
        
        if not vector.startswith("CVSS:3.1/"):
            return {}
            
        vector_parts = vector.replace("CVSS:3.1/", "").split("/")
        
        for part in vector_parts:
            if ":" in part:
                key, value = part.split(":")
                metrics[key] = value
                
        return metrics
        
    def map_to_owasp_category(self, cwe_id: str) -> str:
        """Map CWE ID to OWASP Top 10 category"""
        
        cwe_to_owasp = {
            "CWE-79": "A03:2021 – Injection",
            "CWE-89": "A03:2021 – Injection", 
            "CWE-200": "A01:2021 – Broken Access Control",
            "CWE-269": "A01:2021 – Broken Access Control",
            "CWE-287": "A07:2021 – Identification and Authentication Failures",
            "CWE-352": "A01:2021 – Broken Access Control",
            "CWE-639": "A01:2021 – Broken Access Control",
            "CWE-770": "A05:2021 – Security Misconfiguration",
            "CWE-918": "A10:2021 – Server-Side Request Forgery"
        }
        
        return cwe_to_owasp.get(cwe_id, "A05:2021 – Security Misconfiguration")
        
    def generate_executive_summary(self, findings: List[SecurityFinding], 
                                 stats: ScanStatistics) -> Dict[str, Any]:
        """Generate executive summary for C-level audience"""
        
        # Risk distribution
        risk_distribution = {
            "CRITICAL": len([f for f in findings if self.calculate_shadowfox_score(f)["risk_level"] == "CRITICAL"]),
            "HIGH": len([f for f in findings if self.calculate_shadowfox_score(f)["risk_level"] == "HIGH"]),
            "MEDIUM": len([f for f in findings if self.calculate_shadowfox_score(f)["risk_level"] == "MEDIUM"]),
            "LOW": len([f for f in findings if self.calculate_shadowfox_score(f)["risk_level"] == "LOW"])
        }
        
        # Calculate overall risk score
        total_findings = len(findings)
        if total_findings == 0:
            overall_risk_score = 0
            risk_level = "MINIMAL"
        else:
            weighted_score = (
                risk_distribution["CRITICAL"] * 4 +
                risk_distribution["HIGH"] * 3 +
                risk_distribution["MEDIUM"] * 2 +
                risk_distribution["LOW"] * 1
            ) / total_findings
            
            if weighted_score >= 3.5:
                risk_level = "CRITICAL"
            elif weighted_score >= 2.5:
                risk_level = "HIGH"
            elif weighted_score >= 1.5:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"
                
            overall_risk_score = round((weighted_score / 4.0) * 100, 1)
        
        # Business impact assessment
        business_impact = self.assess_business_impact(findings, risk_distribution)
        
        # Remediation timeline
        remediation_timeline = self.calculate_remediation_timeline(findings)
        
        return {
            "overall_risk_score": overall_risk_score,
            "risk_level": risk_level,
            "total_findings": total_findings,
            "risk_distribution": risk_distribution,
            "business_impact": business_impact,
            "remediation_timeline": remediation_timeline,
            "scan_coverage": f"{stats.coverage_percentage:.1f}%",
            "assessment_confidence": f"{stats.detection_accuracy:.1f}%"
        }
        
    def assess_business_impact(self, findings: List[SecurityFinding], 
                             risk_distribution: Dict[str, int]) -> Dict[str, Any]:
        """Assess business impact of findings"""
        
        # High-level business risks
        business_risks = []
        
        if risk_distribution["CRITICAL"] > 0:
            business_risks.append("Immediate risk of data breach and system compromise")
            business_risks.append("Potential regulatory compliance violations")
            business_risks.append("Significant reputational damage risk")
            
        if risk_distribution["HIGH"] > 0:
            business_risks.append("Elevated security posture concerns")
            business_risks.append("Potential for unauthorized access to sensitive data")
            
        if risk_distribution["MEDIUM"] > 0:
            business_risks.append("Moderate security vulnerabilities requiring attention")
            
        # Calculate potential financial impact
        financial_impact = self.estimate_financial_impact(risk_distribution)
        
        return {
            "business_risks": business_risks,
            "estimated_financial_impact": financial_impact,
            "compliance_risk": "HIGH" if risk_distribution["CRITICAL"] > 0 else "MEDIUM",
            "recommended_actions": [
                "Immediate remediation of critical and high-severity findings",
                "Implementation of additional security monitoring",
                "Regular security assessments and penetration testing",
                "Security awareness training for development teams"
            ]
        }
        
    def estimate_financial_impact(self, risk_distribution: Dict[str, int]) -> Dict[str, str]:
        """Estimate potential financial impact of vulnerabilities"""
        
        # Industry average cost of data breaches (in USD)
        base_costs = {
            "CRITICAL": 500000,  # $500K average per critical vulnerability
            "HIGH": 100000,     # $100K average per high vulnerability  
            "MEDIUM": 25000,    # $25K average per medium vulnerability
            "LOW": 5000         # $5K average per low vulnerability
        }
        
        total_estimated_cost = sum(
            risk_distribution[risk] * base_costs[risk] 
            for risk in base_costs
        )
        
        return {
            "potential_breach_cost": f"${total_estimated_cost:,}",
            "regulatory_fines": "Up to 4% of annual revenue (GDPR)" if risk_distribution["CRITICAL"] > 0 else "Minimal",
            "business_disruption": "HIGH" if risk_distribution["CRITICAL"] > 0 else "LOW",
            "remediation_cost_estimate": f"${total_estimated_cost * 0.1:,.0f} - ${total_estimated_cost * 0.3:,.0f}"
        }
        
    def calculate_remediation_timeline(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Calculate realistic remediation timeline"""
        
        timeline = {
            "immediate": [],    # 0-7 days
            "short_term": [],   # 1-4 weeks  
            "medium_term": [],  # 1-3 months
            "long_term": []     # 3+ months
        }
        
        for finding in findings:
            shadowfox_score = self.calculate_shadowfox_score(finding)
            risk_level = shadowfox_score["risk_level"]
            
            if risk_level == "CRITICAL":
                timeline["immediate"].append(finding.title)
            elif risk_level == "HIGH":
                timeline["short_term"].append(finding.title)
            elif risk_level == "MEDIUM":
                timeline["medium_term"].append(finding.title)
            else:
                timeline["long_term"].append(finding.title)
                
        return {
            "immediate_action_required": len(timeline["immediate"]),
            "short_term_remediation": len(timeline["short_term"]),
            "medium_term_planning": len(timeline["medium_term"]),
            "long_term_improvements": len(timeline["long_term"]),
            "timeline_details": timeline
        }
        
    def generate_markdown_report(self, findings: List[SecurityFinding], 
                               stats: ScanStatistics, 
                               executive_summary: Dict[str, Any]) -> str:
        """Generate comprehensive Markdown report"""
        
        report_date = datetime.datetime.now().strftime("%B %d, %Y")
        
        markdown_template = f"""# 🛡️ ShadowOS Security Assessment Report

**Target:** {stats.target_domain}  
**Assessment Date:** {report_date}  
**Report Version:** {self.report_template_version}  
**Generated by:** {self.team_signature}  
**Platform:** ShadowOS v{self.shadowos_version}  

---

## 📋 Executive Summary

### Overall Security Posture

**Risk Level:** **{executive_summary['risk_level']}**  
**Overall Risk Score:** {executive_summary['overall_risk_score']}/100  
**Total Findings:** {executive_summary['total_findings']}  
**Assessment Coverage:** {executive_summary['scan_coverage']}  

### Risk Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 **CRITICAL** | {executive_summary['risk_distribution']['CRITICAL']} | {(executive_summary['risk_distribution']['CRITICAL']/max(executive_summary['total_findings'], 1)*100):.1f}% |
| 🟠 **HIGH** | {executive_summary['risk_distribution']['HIGH']} | {(executive_summary['risk_distribution']['HIGH']/max(executive_summary['total_findings'], 1)*100):.1f}% |
| 🟡 **MEDIUM** | {executive_summary['risk_distribution']['MEDIUM']} | {(executive_summary['risk_distribution']['MEDIUM']/max(executive_summary['total_findings'], 1)*100):.1f}% |
| 🟢 **LOW** | {executive_summary['risk_distribution']['LOW']} | {(executive_summary['risk_distribution']['LOW']/max(executive_summary['total_findings'], 1)*100):.1f}% |

### Business Impact Assessment

**Estimated Financial Impact:** {executive_summary['business_impact']['estimated_financial_impact']['potential_breach_cost']}  
**Compliance Risk:** {executive_summary['business_impact']['compliance_risk']}  
**Remediation Cost Estimate:** {executive_summary['business_impact']['estimated_financial_impact']['remediation_cost_estimate']}  

#### Key Business Risks:
"""
        
        for risk in executive_summary['business_impact']['business_risks']:
            markdown_template += f"- {risk}\n"
            
        markdown_template += f"""
### Remediation Timeline

| Priority | Timeframe | Findings Count |
|----------|-----------|----------------|
| 🚨 **Immediate** | 0-7 days | {executive_summary['remediation_timeline']['immediate_action_required']} |
| ⚡ **Short Term** | 1-4 weeks | {executive_summary['remediation_timeline']['short_term_remediation']} |
| 📅 **Medium Term** | 1-3 months | {executive_summary['remediation_timeline']['medium_term_planning']} |
| 🔄 **Long Term** | 3+ months | {executive_summary['remediation_timeline']['long_term_improvements']} |

---

## 🔍 Assessment Methodology

### ShadowOS Testing Approach

This security assessment was conducted using the ShadowOS automated security testing platform, which employs:

- **Dynamic Application Security Testing (DAST)**
- **Business Logic Vulnerability Detection**
- **Authentication & Authorization Testing**
- **API Security Assessment**
- **OWASP Top 10 Coverage**
- **Advanced Payload Mutation Algorithms**

### ShadowFox 3v3 PoC Scoring System

Each finding is evaluated using our proprietary 3v3 scoring methodology:

1. **Technical Complexity** (1-3): Difficulty of exploitation
2. **Exploit Reliability** (1-3): Consistency of successful exploitation
3. **Business Criticality** (1-3): Impact on business operations

**Total Score Range:** 3-9 points (converted to percentage and risk level)

---

## 📊 Assessment Statistics

| Metric | Value |
|--------|-------|
| **Scan Duration** | {stats.scan_duration_minutes} minutes |
| **Total Requests** | {stats.total_requests:,} |
| **Endpoints Tested** | {stats.total_endpoints_tested:,} |
| **Coverage Percentage** | {stats.coverage_percentage:.1f}% |
| **Detection Accuracy** | {stats.detection_accuracy:.1f}% |
| **False Positive Rate** | {stats.false_positive_rate:.1f}% |

---

## 🚨 Detailed Findings

"""
        
        # Add individual findings
        for i, finding in enumerate(findings, 1):
            shadowfox_score = self.calculate_shadowfox_score(finding)
            
            severity_emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠", 
                "MEDIUM": "🟡",
                "LOW": "🟢"
            }.get(shadowfox_score["risk_level"], "⚪")
            
            markdown_template += f"""
### {i}. {severity_emoji} {finding.title}

**Severity:** {shadowfox_score["risk_level"]} ({shadowfox_score["score_percentage"]}%)  
**CVSS Score:** {finding.cvss_score} ({finding.cvss_vector})  
**CWE ID:** {finding.cwe_id}  
**OWASP Category:** {finding.owasp_category}  

#### ShadowFox 3v3 PoC Score: {shadowfox_score["total_score"]}/9

| Metric | Score | Description |
|--------|-------|-------------|
| Technical Complexity | {finding.technical_complexity}/3 | {self.get_complexity_description(finding.technical_complexity)} |
| Exploit Reliability | {finding.exploit_reliability}/3 | {self.get_reliability_description(finding.exploit_reliability)} |
| Business Criticality | {finding.business_criticality}/3 | {self.get_criticality_description(finding.business_criticality)} |

**Remediation Priority:** {shadowfox_score["remediation_priority"]}

#### Technical Details

**Affected URL:** `{finding.affected_url}`  
**HTTP Method:** `{finding.http_method}`  
**Vulnerable Parameter:** `{finding.vulnerable_parameter}`  
**Payload:** `{finding.payload}`  

#### Business Impact

{finding.business_impact}

#### Proof of Concept

"""
            
            for j, step in enumerate(finding.poc_steps, 1):
                markdown_template += f"{j}. {step}\n"
                
            markdown_template += f"""
#### Evidence

**Request Sample:**
```http
{finding.request_sample}
```

**Response Sample:**
```http
{finding.response_sample[:500]}{'...' if len(finding.response_sample) > 500 else ''}
```

#### Remediation

{finding.remediation}

**Estimated Fix Time:** {finding.estimated_fix_time}  
**Implementation Complexity:** {finding.remediation_complexity}  

---

"""
        
        # Add legal disclaimers
        markdown_template += f"""
## ⚖️ Legal Notice and Disclaimers

{self.legal_disclaimers['main_disclaimer']}

### Testing Methodology

{self.legal_disclaimers['testing_methodology']}

### Data Handling

{self.legal_disclaimers['data_handling']}

---

## 📞 Contact Information

**ShadowFox Elite Security Team**  
Email: security@shadowfox.team  
Report Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}  

**Report Hash:** {self.generate_report_hash(findings, stats)}  

---

*This report is confidential and proprietary. Distribution is restricted to authorized personnel only.*
"""
        
        return markdown_template
        
    def get_complexity_description(self, score: int) -> str:
        """Get description for technical complexity score"""
        descriptions = {
            1: "Simple exploitation, minimal technical skills required",
            2: "Moderate complexity, requires some technical expertise", 
            3: "Complex exploitation, requires advanced technical skills"
        }
        return descriptions.get(score, "Unknown")
        
    def generate_report_hash(self, findings: List[SecurityFinding], 
                           stats: ScanStatistics) -> str:
        """Generate unique hash for report integrity"""
        report_content = f"{stats.target_domain}_{len(findings)}_{stats.scan_start_time}"
        return hashlib.sha256(report_content.encode()).hexdigest()[:16].upper()
        
    def convert_markdown_to_html(self, markdown_content: str) -> str:
        """Convert Markdown to HTML with professional styling"""
        
        # Custom CSS for professional appearance
        css_styles = """
        <style>
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f8f9fa;
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
                text-align: center;
            }
            .summary-card {
                background: white;
                border-radius: 8px;
                padding: 20px;
                margin: 20px 0;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .risk-critical { border-left: 5px solid #dc3545; }
            .risk-high { border-left: 5px solid #fd7e14; }
            .risk-medium { border-left: 5px solid #ffc107; }
            .risk-low { border-left: 5px solid #28a745; }
            
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                background: white;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            th, td {
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #dee2e6;
            }
            th {
                background-color: #343a40;
                color: white;
                font-weight: 600;
            }
            
            .finding {
                background: white;
                border-radius: 8px;
                padding: 25px;
                margin: 25px 0;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            
            .code-block {
                background: #f8f9fa;
                border: 1px solid #e9ecef;
                border-radius: 4px;
                padding: 15px;
                font-family: 'Courier New', monospace;
                overflow-x: auto;
                margin: 15px 0;
            }
            
            .disclaimer {
                background: #e9ecef;
                border-radius: 8px;
                padding: 20px;
                margin: 30px 0;
                font-size: 0.9em;
                color: #6c757d;
            }
            
            .footer {
                text-align: center;
                padding: 30px;
                background: #343a40;
                color: white;
                border-radius: 10px;
                margin-top: 50px;
            }
        </style>
        """
        
        # Convert markdown to HTML
        html_content = markdown.markdown(markdown_content, extensions=['tables', 'fenced_code'])
        
        # Wrap in complete HTML document
        full_html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>ShadowOS Security Assessment Report</title>
            {css_styles}
        </head>
        <body>
            {html_content}
        </body>
        </html>
        """
        
        return full_html
        
    def convert_html_to_pdf(self, html_content: str, output_path: str) -> bool:
        """Convert HTML to PDF using WeasyPrint"""
        try:
            # Additional CSS for PDF formatting
            pdf_css = CSS(string="""
                @page {
                    size: A4;
                    margin: 2cm;
                    @top-center {
                        content: "ShadowOS Security Assessment - CONFIDENTIAL";
                        font-size: 10px;
                        color: #666;
                    }
                    @bottom-center {
                        content: "Page " counter(page) " of " counter(pages);
                        font-size: 10px;
                        color: #666;
                    }
                }
                
                body { font-size: 11px; }
                h1 { page-break-before: always; }
                .finding { page-break-inside: avoid; }
                .code-block { font-size: 9px; }
            """)
            
            HTML(string=html_content).write_pdf(output_path, stylesheets=[pdf_css])
            return True
            
        except Exception as e:
            print(f"PDF conversion failed: {str(e)}")
            return False
            
    def generate_json_export(self, findings: List[SecurityFinding], 
                           stats: ScanStatistics,
                           executive_summary: Dict[str, Any]) -> str:
        """Generate machine-readable JSON export"""
        
        export_data = {
            "report_metadata": {
                "shadowos_version": self.shadowos_version,
                "report_version": self.report_template_version,
                "generated_by": self.team_signature,
                "generation_date": datetime.datetime.now().isoformat(),
                "report_hash": self.generate_report_hash(findings, stats)
            },
            
            "target_information": {
                "domain": stats.target_domain,
                "scan_start": stats.scan_start_time.isoformat(),
                "scan_end": stats.scan_end_time.isoformat(),
                "scan_duration_minutes": stats.scan_duration_minutes
            },
            
            "executive_summary": executive_summary,
            
            "scan_statistics": asdict(stats),
            
            "findings": []
        }
        
        # Add enhanced findings
        for finding in findings:
            finding_dict = asdict(finding)
            
            # Add ShadowFox scoring
            finding_dict["shadowfox_score"] = self.calculate_shadowfox_score(finding)
            
            # Convert datetime to ISO format
            finding_dict["discovery_date"] = finding.discovery_date.isoformat()
            
            export_data["findings"].append(finding_dict)
            
        return json.dumps(export_data, indent=2, default=str)
        
    def generate_csv_export(self, findings: List[SecurityFinding]) -> str:
        """Generate CSV export for spreadsheet analysis"""
        
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # CSV Headers
        headers = [
            "ID", "Title", "Severity", "CVSS Score", "CWE ID", "OWASP Category",
            "Affected URL", "HTTP Method", "Vulnerable Parameter", "Payload",
            "ShadowFox Score", "Technical Complexity", "Exploit Reliability", 
            "Business Criticality", "Remediation Priority", "Estimated Fix Time",
            "Discovery Date", "Confidence Level"
        ]
        
        writer.writerow(headers)
        
        # Data rows
        for finding in findings:
            shadowfox_score = self.calculate_shadowfox_score(finding)
            
            row = [
                finding.id,
                finding.title,
                shadowfox_score["risk_level"],
                finding.cvss_score,
                finding.cwe_id,
                finding.owasp_category,
                finding.affected_url,
                finding.http_method,
                finding.vulnerable_parameter,
                finding.payload[:100] + "..." if len(finding.payload) > 100 else finding.payload,
                f"{shadowfox_score['total_score']}/9",
                finding.technical_complexity,
                finding.exploit_reliability,
                finding.business_criticality,
                shadowfox_score["remediation_priority"],
                finding.estimated_fix_time,
                finding.discovery_date.strftime("%Y-%m-%d"),
                f"{finding.confidence_level:.2f}"
            ]
            
            writer.writerow(row)
            
        return output.getvalue()
        
    def create_visualization_charts(self, findings: List[SecurityFinding], 
                                  stats: ScanStatistics) -> Dict[str, str]:
        """Create visualization charts and return base64 encoded images"""
        
        charts = {}
        
        # Set style for professional charts
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
        try:
            # 1. Risk Distribution Pie Chart
            shadowfox_scores = [self.calculate_shadowfox_score(f) for f in findings]
            risk_levels = [score["risk_level"] for score in shadowfox_scores]
            
            risk_counts = {level: risk_levels.count(level) for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
            risk_counts = {k: v for k, v in risk_counts.items() if v > 0}  # Remove zeros
            
            if risk_counts:
                fig, ax = plt.subplots(figsize=(10, 8))
                colors = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#28a745"}
                wedge_colors = [colors[level] for level in risk_counts.keys()]
                
                wedges, texts, autotexts = ax.pie(
                    risk_counts.values(), 
                    labels=risk_counts.keys(),
                    autopct='%1.1f%%',
                    colors=wedge_colors,
                    startangle=90,
                    textprops={'fontsize': 12, 'fontweight': 'bold'}
                )
                
                ax.set_title("Security Risk Distribution", fontsize=16, fontweight='bold', pad=20)
                
                # Save as base64
                from io import BytesIO
                buffer = BytesIO()
                plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
                buffer.seek(0)
                charts["risk_distribution"] = base64.b64encode(buffer.getvalue()).decode()
                plt.close()
            
            # 2. CVSS Score Distribution
            cvss_scores = [f.cvss_score for f in findings if f.cvss_score > 0]
            
            if cvss_scores:
                fig, ax = plt.subplots(figsize=(12, 6))
                
                ax.hist(cvss_scores, bins=10, color='skyblue', alpha=0.7, edgecolor='black')
                ax.set_xlabel('CVSS Score', fontsize=12, fontweight='bold')
                ax.set_ylabel('Number of Findings', fontsize=12, fontweight='bold')
                ax.set_title('CVSS Score Distribution', fontsize=14, fontweight='bold')
                ax.grid(True, alpha=0.3)
                
                buffer = BytesIO()
                plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
                buffer.seek(0)
                charts["cvss_distribution"] = base64.b64encode(buffer.getvalue()).decode()
                plt.close()
                
            # 3. ShadowFox 3v3 Score Breakdown
            technical_scores = [f.technical_complexity for f in findings]
            reliability_scores = [f.exploit_reliability for f in findings]
            business_scores = [f.business_criticality for f in findings]
            
            if findings:
                fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 5))
                
                # Technical Complexity
                ax1.hist(technical_scores, bins=3, color='lightcoral', alpha=0.7, edgecolor='black')
                ax1.set_xlabel('Technical Complexity', fontweight='bold')
                ax1.set_ylabel('Count', fontweight='bold')
                ax1.set_title('Technical Complexity\nDistribution', fontweight='bold')
                ax1.set_xticks([1, 2, 3])
                
                # Exploit Reliability
                ax2.hist(reliability_scores, bins=3, color='lightgreen', alpha=0.7, edgecolor='black')
                ax2.set_xlabel('Exploit Reliability', fontweight='bold')
                ax2.set_ylabel('Count', fontweight='bold')
                ax2.set_title('Exploit Reliability\nDistribution', fontweight='bold')
                ax2.set_xticks([1, 2, 3])
                
                # Business Criticality
                ax3.hist(business_scores, bins=3, color='lightblue', alpha=0.7, edgecolor='black')
                ax3.set_xlabel('Business Criticality', fontweight='bold')
                ax3.set_ylabel('Count', fontweight='bold')
                ax3.set_title('Business Criticality\nDistribution', fontweight='bold')
                ax3.set_xticks([1, 2, 3])
                
                plt.tight_layout()
                
                buffer = BytesIO()
                plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
                buffer.seek(0)
                charts["shadowfox_breakdown"] = base64.b64encode(buffer.getvalue()).decode()
                plt.close()
                
        except Exception as e:
            print(f"Chart generation error: {str(e)}")
            
        return charts
        
    def generate_complete_report(self, findings: List[SecurityFinding],
                               stats: ScanStatistics,
                               output_formats: List[ReportFormat] = None) -> Dict[str, str]:
        """Generate complete security assessment report in multiple formats"""
        
        if output_formats is None:
            output_formats = [ReportFormat.MARKDOWN, ReportFormat.HTML, ReportFormat.JSON]
            
        # Enhance findings with intelligence
        enhanced_findings = [self.enhance_finding_with_intelligence(f) for f in findings]
        
        # Generate executive summary
        executive_summary = self.generate_executive_summary(enhanced_findings, stats)
        
        # Generate visualizations
        charts = self.create_visualization_charts(enhanced_findings, stats)
        
        # Prepare output files
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        domain_clean = stats.target_domain.replace(".", "_").replace(":", "_")
        
        output_files = {}
        
        # Generate reports in requested formats
        for format_type in output_formats:
            
            if format_type == ReportFormat.MARKDOWN:
                markdown_content = self.generate_markdown_report(
                    enhanced_findings, stats, executive_summary
                )
                
                filename = f"shadowos_report_{domain_clean}_{timestamp}.md"
                filepath = self.output_dir / filename
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(markdown_content)
                    
                output_files["markdown"] = str(filepath)
                
            elif format_type == ReportFormat.HTML:
                markdown_content = self.generate_markdown_report(
                    enhanced_findings, stats, executive_summary
                )
                html_content = self.convert_markdown_to_html(markdown_content)
                
                filename = f"shadowos_report_{domain_clean}_{timestamp}.html"
                filepath = self.output_dir / filename
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                    
                output_files["html"] = str(filepath)
                
            elif format_type == ReportFormat.PDF:
                markdown_content = self.generate_markdown_report(
                    enhanced_findings, stats, executive_summary
                )
                html_content = self.convert_markdown_to_html(markdown_content)
                
                filename = f"shadowos_report_{domain_clean}_{timestamp}.pdf"
                filepath = self.output_dir / filename
                
                if self.convert_html_to_pdf(html_content, str(filepath)):
                    output_files["pdf"] = str(filepath)
                    
            elif format_type == ReportFormat.JSON:
                json_content = self.generate_json_export(
                    enhanced_findings, stats, executive_summary
                )
                
                filename = f"shadowos_data_{domain_clean}_{timestamp}.json"
                filepath = self.output_dir / filename
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(json_content)
                    
                output_files["json"] = str(filepath)
                
            elif format_type == ReportFormat.CSV:
                csv_content = self.generate_csv_export(enhanced_findings)
                
                filename = f"shadowos_findings_{domain_clean}_{timestamp}.csv"
                filepath = self.output_dir / filename
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(csv_content)
                    
                output_files["csv"] = str(filepath)
                
        # Save charts if generated
        if charts:
            charts_dir = self.output_dir / "charts"
            charts_dir.mkdir(exist_ok=True)
            
            for chart_name, chart_data in charts.items():
                chart_path = charts_dir / f"{chart_name}_{domain_clean}_{timestamp}.png"
                
                with open(chart_path, 'wb') as f:
                    f.write(base64.b64decode(chart_data))
                    
                output_files[f"chart_{chart_name}"] = str(chart_path)
                
        return output_files


# Integration adapter for Mission Orchestrator
class ReportModuleAdapter:
    """Adapter class for integration with Mission Orchestrator"""
    
    def __init__(self, output_dir: str = "reports/"):
        self.report_engine = ShadowOSReportEngine(output_dir)
        
    async def generate_report(self, target_domain: str, **parameters) -> Dict[str, Any]:
        """Main method called by Mission Orchestrator"""
        
        # Extract parameters
        findings_data = parameters.get("findings", [])
        scan_data = parameters.get("scan_statistics", {})
        report_formats = parameters.get("formats", ["markdown", "json"])
        
        # Convert findings data to SecurityFinding objects
        findings = []
        for finding_data in findings_data:
            # Map scanner engine findings to SecurityFinding format
            finding = SecurityFinding(
                id=finding_data.get("id", f"FIND_{len(findings)+1:03d}"),
                title=finding_data.get("title", "Security Finding"),
                severity=finding_data.get("severity", "medium").upper(),
                cvss_score=finding_data.get("cvss_score", 0.0),
                cvss_vector=finding_data.get("cvss_vector", ""),
                cwe_id=finding_data.get("cwe_id", "CWE-200"),
                owasp_category=finding_data.get("owasp_category", ""),
                
                affected_url=finding_data.get("url", target_domain),
                http_method=finding_data.get("method", "GET"),
                vulnerable_parameter=finding_data.get("vulnerable_parameter", ""),
                payload=finding_data.get("payload", ""),
                
                request_sample=finding_data.get("request_sample", ""),
                response_sample=finding_data.get("response_sample", ""),
                poc_steps=finding_data.get("poc_steps", []),
                business_impact=finding_data.get("business_impact", ""),
                
                # ShadowFox 3v3 scoring - auto-assign based on severity
                technical_complexity=self.map_severity_to_complexity(finding_data.get("severity", "medium")),
                exploit_reliability=finding_data.get("confidence", 2),
                business_criticality=self.map_severity_to_criticality(finding_data.get("severity", "medium")),
                
                remediation=finding_data.get("remediation", ""),
                remediation_complexity="Medium",
                estimated_fix_time="1-2 weeks",
                
                discovered_by="ShadowFox Elite Security Team",
                discovery_date=datetime.datetime.now(),
                tool_signature="ShadowOS v1.0",
                confidence_level=finding_data.get("confidence", 0.8)
            )
            
            findings.append(finding)
            
        # Create scan statistics
        stats = ScanStatistics(
            target_domain=target_domain,
            scan_start_time=datetime.datetime.now() - datetime.timedelta(hours=1),
            scan_end_time=datetime.datetime.now(),
            total_requests=scan_data.get("total_requests", 1000),
            total_endpoints_tested=scan_data.get("endpoints_tested", 50),
            scan_duration_minutes=scan_data.get("duration_minutes", 60),
            
            critical_findings=len([f for f in findings if "critical" in f.severity.lower()]),
            high_findings=len([f for f in findings if "high" in f.severity.lower()]),
            medium_findings=len([f for f in findings if "medium" in f.severity.lower()]),
            low_findings=len([f for f in findings if "low" in f.severity.lower()]),
            info_findings=len([f for f in findings if "info" in f.severity.lower()]),
            
            coverage_percentage=scan_data.get("coverage", 85.0),
            false_positive_rate=scan_data.get("false_positive_rate", 5.0),
            detection_accuracy=scan_data.get("accuracy", 92.0)
        )
        
        # Map format strings to enums
        format_mapping = {
            "markdown": ReportFormat.MARKDOWN,
            "html": ReportFormat.HTML,
            "pdf": ReportFormat.PDF,
            "json": ReportFormat.JSON,
            "csv": ReportFormat.CSV
        }
        
        format_enums = [format_mapping[fmt] for fmt in report_formats if fmt in format_mapping]
        
        # Generate reports
        output_files = self.report_engine.generate_complete_report(
            findings, stats, format_enums
        )
        
        return {
            "report_generated": True,
            "output_files": output_files,
            "findings_count": len(findings),
            "report_formats": list(output_files.keys()),
            "target_domain": target_domain
        }
        
    def map_severity_to_complexity(self, severity: str) -> int:
        """Map severity to technical complexity score"""
        mapping = {
            "critical": 3,
            "high": 2,
            "medium": 2,
            "low": 1,
            "info": 1
        }
        return mapping.get(severity.lower(), 2)
        
    def map_severity_to_criticality(self, severity: str) -> int:
        """Map severity to business criticality score"""
        mapping = {
            "critical": 3,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 1
        }
        return mapping.get(severity.lower(), 2)
        
    async def execute(self, target_domain: str, **parameters) -> Dict[str, Any]:
        """Generic execute method for Mission Orchestrator compatibility"""
        return await self.generate_report(target_domain, **parameters)


# CLI Interface
def create_report_cli():
    """Create CLI interface for report engine"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ShadowOS Report Engine")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Generate report command
    generate_parser = subparsers.add_parser("generate", help="Generate security report")
    generate_parser.add_argument("findings_file", help="JSON file with findings data")
    generate_parser.add_argument("--domain", required=True, help="Target domain")
    generate_parser.add_argument("--formats", nargs="+", 
                               choices=["markdown", "html", "pdf", "json", "csv"],
                               default=["markdown", "json"])
    generate_parser.add_argument("--output-dir", default="reports/", help="Output directory")
    
    return parser

async def run_report_cli():
    """Run report CLI"""
    parser = create_report_cli()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
        
    if args.command == "generate":
        print("📊 ShadowOS Report Engine - Generating Professional Security Report")
        
        # Load findings data
        try:
            with open(args.findings_file, 'r') as f:
                findings_data = json.load(f)
        except Exception as e:
            print(f"❌ Error loading findings file: {str(e)}")
            return
            
        # Initialize report engine
        report_adapter = ReportModuleAdapter(args.output_dir)
        
        # Generate report
        result = await report_adapter.generate_report(
            args.domain,
            findings=findings_data.get("findings", []),
            scan_statistics=findings_data.get("statistics", {}),
            formats=args.formats
        )
        
        if result["report_generated"]:
            print("✅ Report generation completed!")
            print(f"📁 Output files:")
            for format_type, filepath in result["output_files"].items():
                print(f"   • {format_type}: {filepath}")
        else:
            print("❌ Report generation failed")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # CLI mode
        import asyncio
        asyncio.run(run_report_cli())
    else:
        # Example mode
        print("🦊 ShadowOS Report Engine v1.0")
        print("📊 Professional Security Assessment Reporting")
        print("\nUsage: python report_engine.py generate findings.json --domain example.com")
        print("Formats: markdown, html, pdf, json, csv")

"""
🔥 SHADOWOS REPORT ENGINE - ENTERPRISE READY! 📊

PROFESSIONAL FEATURES:
✅ Executive Summary - C-level audience ready
✅ ShadowFox 3v3 PoC Scoring - Proprietary scoring system
✅ CVSS v3.1 Integration - Industry standard scoring
✅ Multiple Export Formats - MD, HTML, PDF, JSON, CSV
✅ Professional Legal Disclaimers - Enterprise compliance
✅ Business Impact Assessment - Financial impact estimates
✅ Remediation Timeline - Actionable roadmap
✅ Compliance Mapping - OWASP Top 10, CWE integration
✅ Data Visualization Charts - Professional graphs
✅ Mission Orchestrator Integration - ReportModuleAdapter

SHADOWFOX BRANDING:
🦊 ShadowFox Elite Security Team signature
🛡️ ShadowOS v1.0 platform branding
⚖️ Professional legal disclaimers
📊 Enterprise-grade report templates
🎯 3v3 PoC scoring methodology

READY FOR INTEGRATION:
orchestrator.register_module(ModuleType.REPORT, ReportModuleAdapter())
""".get(score, "Unknown")
        
    def get_reliability_description(self, score: int) -> str:
        """Get description for exploit reliability score"""
        descriptions = {
            1: "Unreliable, exploitation may fail frequently",
            2: "Moderately reliable, consistent under normal conditions",
            3: "Highly reliable, consistent successful exploitation"
        }
        return descriptions.get(score, "Unknown")
        
    def get_criticality_description(self, score: int) -> str:
        """Get description for business criticality score"""
        descriptions = {
            1: "Low business impact, minimal operational disruption",
            2: "Medium business impact, noticeable operational effects",
            3: "High business impact, significant operational disruption"
        }
        return descriptions
