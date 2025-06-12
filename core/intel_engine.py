#!/usr/bin/env python3
"""
ShadowOS Cloud v1.0 - Intelligence Engine
Advanced Reconnaissance & Target Mapping System

Developed by ShadowRock Team
"""
import ssl
import whois
import requests
from datetime import timedelta
import asyncio
import aiohttp
import dns.resolver
import subprocess
import json
import re
import time
import logging
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from urllib.parse import urlparse, urljoin
import socket
import ssl
import whois
from bs4 import BeautifulSoup
import requests
from proxy_manager import ShadowProxyManager

@dataclass
class SubdomainInfo:
    domain: str
    ip_address: str
    status_code: int
    title: str
    server: str
    technologies: List[str]
    endpoints: List[str]
    vulnerability_indicators: List[str]
    last_scanned: datetime

@dataclass
class TechStackInfo:
    web_server: str
    framework: str
    cms: str
    database: str
    cdn: str
    waf: str
    language: str
    libraries: List[str]
    confidence: float

@dataclass
class TargetProfile:
    domain: str
    subdomains: List[SubdomainInfo]
    tech_stack: TechStackInfo
    endpoints: List[str]
    parameters: List[str]
    rate_limits: Dict[str, int]
    waf_info: Dict[str, str]
    security_headers: Dict[str, str]
    certificates: Dict[str, str]
    organization_info: Dict[str, str]
    attack_surface: Dict[str, int]
    priority_score: float

class ShadowIntelEngine:
    """
    🧠 Advanced Intelligence & Reconnaissance Engine
    
    Features:
    - Multi-source subdomain enumeration
    - Technology stack fingerprinting
    - WAF detection and bypass research
    - Rate limit probing
    - Attack surface mapping
    - Priority target scoring
    """
    
    def __init__(self, proxy_manager: Optional[ShadowProxyManager] = None):
        self.proxy_manager = proxy_manager
        self.session = None
        
        # Subdomain enumeration sources
        self.subdomain_sources = [
            "crt.sh",
            "securitytrails",
            "virustotal", 
            "sublist3r",
            "amass",
            "subfinder"
        ]
        
        # Technology fingerprinting patterns
        self.tech_patterns = {
            "web_servers": {
                "nginx": [r"nginx", r"server:\s*nginx"],
                "apache": [r"apache", r"server:\s*apache"],
                "iis": [r"microsoft-iis", r"server:\s*microsoft-iis"],
                "cloudflare": [r"cloudflare", r"cf-ray"],
                "aws": [r"amazon", r"aws", r"x-amz"],
                "azure": [r"azure", r"x-ms-"],
                "gcp": [r"gcp", r"google"]
            },
            "frameworks": {
                "react": [r"react", r"_next", r"__NEXT_DATA__"],
                "angular": [r"angular", r"ng-", r"__ngContext__"],
                "vue": [r"vue", r"__vue__", r"v-"],
                "django": [r"django", r"csrftoken", r"__admin"],
                "rails": [r"rails", r"csrf-param", r"_session"],
                "laravel": [r"laravel", r"csrf-token", r"_token"],
                "wordpress": [r"wp-content", r"wp-admin", r"wordpress"],
                "drupal": [r"drupal", r"/sites/"],
                "joomla": [r"joomla", r"/administrator/"]
            },
            "languages": {
                "php": [r"\.php", r"x-powered-by:\s*php"],
                "python": [r"\.py", r"x-powered-by:\s*python"],
                "node": [r"x-powered-by:\s*express", r"node"],
                "java": [r"jsessionid", r"j_security"],
                "asp": [r"\.aspx?", r"x-powered-by:\s*asp"],
                "go": [r"x-powered-by:\s*go"],
                "ruby": [r"x-powered-by:\s*ruby"]
            },
            "databases": {
                "mysql": [r"mysql", r"phpmyadmin"],
                "postgresql": [r"postgresql", r"postgres", r"pgadmin"],
                "mongodb": [r"mongodb", r"mongo"],
                "redis": [r"redis"],
                "elasticsearch": [r"elasticsearch", r"_search", r"_cluster"],
                "oracle": [r"oracle"],
                "mssql": [r"sql server", r"mssql"]
            },
            "waf": {
                "cloudflare": [r"cloudflare", r"cf-ray", r"__cf"],
                "aws_waf": [r"aws", r"x-amzn"],
                "incapsula": [r"incapsula", r"x-cdn"],
                "sucuri": [r"sucuri", r"x-sucuri"],
                "fastly": [r"fastly", r"x-served-by"],
                "akamai": [r"akamai", r"x-akamai"],
                "barracuda": [r"barracuda"],
                "f5": [r"f5", r"bigip"]
            }
        }
        
        # Common endpoints for discovery
        self.common_endpoints = [
            "/api", "/api/v1", "/api/v2", "/rest", "/graphql",
            "/admin", "/administrator", "/wp-admin", "/manager",
            "/login", "/signin", "/auth", "/oauth", "/sso",
            "/upload", "/uploads", "/files", "/assets",
            "/backup", "/backups", "/dump", "/export",
            "/config", "/configuration", "/settings",
            "/debug", "/test", "/dev", "/staging",
            "/docs", "/documentation", "/swagger", "/openapi",
            "/health", "/status", "/metrics", "/monitoring"
        ]
        
        # Vulnerability indicators
        self.vuln_indicators = [
            "debug", "test", "dev", "staging", "backup",
            "config", "admin", "phpmyadmin", "adminer",
            "swagger", "graphql", "api-docs", "openapi",
            "error", "exception", "stack trace", "sql",
            "internal server error", "404", "403", "500"
        ]
        
        self.setup_logging()
        
    def setup_logging(self):
        """Setup intelligence logging system"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [🧠 INTEL] %(levelname)s: %(message)s',
            handlers=[
                logging.FileHandler('shadowos_intel.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    async def initialize_session(self):
        """Initialize HTTP session with proxy support"""
        if self.proxy_manager and self.proxy_manager.current_proxy:
            proxy_url = f"http://{self.proxy_manager.current_proxy.ip}:{self.proxy_manager.current_proxy.port}"
            self.session = aiohttp.ClientSession(
                connector=aiohttp.ProxyConnector.from_url(proxy_url),
                timeout=aiohttp.ClientTimeout(total=30)
            )
        else:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )
            

    async def get_ssl_certificate_info(self, domain: str) -> Dict[str, str]:
        """Get SSL certificate information"""
        cert_info = {}
    
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                
                    cert_info = {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "version": cert['version'],
                        "serial_number": cert['serialNumber'],
                        "not_before": cert['notBefore'],
                        "not_after": cert['notAfter'],
                        "subject_alt_names": [x[1] for x in cert.get('subjectAltName', [])]
                    }
                
        except Exception as e:
            self.logger.debug(f"SSL cert info failed for {domain}: {str(e)}")
        
        return cert_info

    async def get_whois_info(self, domain: str) -> Dict[str, str]:
        """Get WHOIS information for domain"""
        whois_info = {}
    
        try:
            w = whois.whois(domain)
            whois_info = {
                "registrar": str(w.registrar) if w.registrar else "",
                "creation_date": str(w.creation_date) if w.creation_date else "",
                "expiration_date": str(w.expiration_date) if w.expiration_date else "",
                "name_servers": w.name_servers if w.name_servers else [],
                "organization": str(w.org) if hasattr(w, 'org') and w.org else ""
            }
        
        except Exception as e:
            self.logger.debug(f"WHOIS lookup failed for {domain}: {str(e)}")
        
        return whois_info

    def generate_intelligence_summary(self, target: TargetProfile) -> str:
        """Generate human-readable intelligence summary"""
    
        summary = f"""
🎯 SHADOWOS INTELLIGENCE REPORT
═══════════════════════════════════════════════════════════════

📋 TARGET OVERVIEW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌐 Domain: {target.domain}
📊 Priority Score: {target.priority_score:.1f}/100
⏰ Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📈 ATTACK SURFACE METRICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 Subdomains Discovered: {len(target.subdomains)}
🎯 Endpoints Found: {len(target.endpoints)}
⚙️ Technologies Identified: {target.attack_surface['technologies']}
⚠️ Vulnerability Indicators: {target.attack_surface['vulnerability_indicators']}

🔧 TECHNOLOGY STACK
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌐 Web Server: {target.tech_stack.web_server}
⚡ Framework: {target.tech_stack.framework}
💻 Programming Language: {target.tech_stack.language}
🗄️ Database: {target.tech_stack.database}
🛡️ WAF: {target.tech_stack.waf}
🎯 Detection Confidence: {target.tech_stack.confidence:.1f}%
"""

        if target.waf_info.get('detected'):
            summary += f"""
🛡️ WAF DETECTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚫 WAF Type: {target.waf_info['type']}
📊 Confidence: {target.waf_info['confidence']}%
⚠️ Bypass Research Required: YES
"""

        if target.rate_limits:
            summary += f"""
⏱️ RATE LIMITING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
            for endpoint, limit in target.rate_limits.items():
                summary += f"📍 {endpoint}: {limit} requests/second\n"

    # Top vulnerable subdomains
        vulnerable_subs = [sub for sub in target.subdomains if sub.vulnerability_indicators]
        if vulnerable_subs:
            summary += f"""
🚨 HIGH-PRIORITY TARGETS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
            for sub in vulnerable_subs[:5]:
                summary += f"⚠️ {sub.domain} - {len(sub.vulnerability_indicators)} indicators\n"
                for indicator in sub.vulnerability_indicators[:3]:
                    summary += f"   🔥 {indicator}\n"

    # API endpoints
        api_endpoints = [ep for ep in target.endpoints if any(keyword in ep.lower() for keyword in ['api', 'rest', 'graphql'])]
        if api_endpoints:
            summary += f"""
🎯 API ENDPOINTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
            for endpoint in api_endpoints[:10]:
                summary += f"🔥 {endpoint}\n"

        summary += f"""
📊 RECOMMENDATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Focus on high-priority subdomains with vulnerability indicators
2. Test API endpoints for IDOR vulnerabilities
3. Research WAF bypass techniques if detected
4. Monitor rate limits during automated testing
5. Investigate technology-specific vulnerabilities

⚡ NEXT STEPS: Load target into scanner_engine.py for vulnerability testing
═══════════════════════════════════════════════════════════════
"""
    
        return summary


    async def enumerate_subdomains_crtsh(self, domain: str) -> Set[str]:
        """Enumerate subdomains using crt.sh certificate transparency logs"""
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            if not self.session:
                await self.initialize_session()
                
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for entry in data:
                        name_value = entry.get('name_value', '')
                        for subdomain in name_value.split('\n'):
                            subdomain = subdomain.strip().lower()
                            if subdomain.endswith(f'.{domain}') and '*' not in subdomain:
                                subdomains.add(subdomain)
                                
            self.logger.info(f"🔍 crt.sh found {len(subdomains)} subdomains for {domain}")
            
        except Exception as e:
            self.logger.error(f"❌ crt.sh enumeration failed: {str(e)}")
            
        return subdomains
        
    async def enumerate_subdomains_virustotal(self, domain: str, api_key: str = None) -> Set[str]:
        """Enumerate subdomains using VirusTotal API"""
        subdomains = set()
        
        if not api_key:
            self.logger.warning("⚠️ VirusTotal API key not provided")
            return subdomains
            
        try:
            headers = {"x-apikey": api_key}
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {"apikey": api_key, "domain": domain}
            
            if not self.session:
                await self.initialize_session()
                
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for subdomain in data.get('subdomains', []):
                        if subdomain.endswith(f'.{domain}'):
                            subdomains.add(subdomain)
                            
            self.logger.info(f"🔍 VirusTotal found {len(subdomains)} subdomains for {domain}")
            
        except Exception as e:
            self.logger.error(f"❌ VirusTotal enumeration failed: {str(e)}")
            
        return subdomains
        
    async def enumerate_subdomains_bruteforce(self, domain: str) -> Set[str]:
        """Brute force common subdomain names"""
        subdomains = set()
        
        # Common subdomain wordlist
        common_subdomains = [
            "www", "api", "app", "dev", "test", "staging", "prod", "production",
            "admin", "administrator", "management", "control", "panel",
            "mail", "email", "smtp", "pop", "imap", "webmail",
            "ftp", "sftp", "files", "uploads", "downloads", "assets",
            "blog", "news", "support", "help", "docs", "documentation",
            "status", "health", "monitoring", "metrics", "analytics",
            "cdn", "static", "media", "images", "img", "js", "css",
            "secure", "ssl", "vpn", "portal", "gateway", "proxy",
            "mobile", "m", "wap", "touch", "beta", "alpha",
            "shop", "store", "cart", "payment", "billing", "invoice",
            "crm", "erp", "hr", "finance", "accounting",
            "backup", "archive", "old", "legacy", "deprecated"
        ]
        
        try:
            tasks = []
            for subdomain in common_subdomains:
                full_domain = f"{subdomain}.{domain}"
                tasks.append(self.check_subdomain_exists(full_domain))
                
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if result and not isinstance(result, Exception):
                    subdomains.add(f"{common_subdomains[i]}.{domain}")
                    
            self.logger.info(f"🔍 Brute force found {len(subdomains)} subdomains for {domain}")
            
        except Exception as e:
            self.logger.error(f"❌ Brute force enumeration failed: {str(e)}")
            
        return subdomains
        
    async def check_subdomain_exists(self, subdomain: str) -> bool:
        """Check if subdomain exists and is accessible"""
        try:
            # DNS resolution check
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            answers = resolver.resolve(subdomain, 'A')
            if answers:
                return True
                
        except Exception:
            pass
            
        return False
        
    async def probe_subdomain_info(self, subdomain: str) -> Optional[SubdomainInfo]:
        """Probe detailed information about a subdomain"""
        try:
            if not self.session:
                await self.initialize_session()
                
            # Try both HTTP and HTTPS
            for protocol in ['https', 'http']:
                url = f"{protocol}://{subdomain}"
                
                try:
                    async with self.session.get(url, allow_redirects=True) as response:
                        content = await response.text()
                        
                        # Extract title
                        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                        title = title_match.group(1).strip() if title_match else ""
                        
                        # Extract server header
                        server = response.headers.get('Server', '')
                        
                        # Detect technologies
                        technologies = self.detect_technologies(content, response.headers)
                        
                        # Find endpoints
                        endpoints = self.extract_endpoints(content, url)
                        
                        # Check vulnerability indicators
                        vuln_indicators = self.check_vulnerability_indicators(content)
                        
                        # Get IP address
                        ip_address = socket.gethostbyname(subdomain)
                        
                        subdomain_info = SubdomainInfo(
                            domain=subdomain,
                            ip_address=ip_address,
                            status_code=response.status,
                            title=title,
                            server=server,
                            technologies=technologies,
                            endpoints=endpoints,
                            vulnerability_indicators=vuln_indicators,
                            last_scanned=datetime.now()
                        )
                        
                        self.logger.info(f"✅ Probed {subdomain} - Status: {response.status}, Tech: {len(technologies)}")
                        return subdomain_info
                        
                except Exception as e:
                    self.logger.debug(f"❌ Failed to probe {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"❌ Subdomain probe failed for {subdomain}: {str(e)}")
            
        return None
        
    def detect_technologies(self, content: str, headers: Dict[str, str]) -> List[str]:
        """Detect web technologies from content and headers"""
        technologies = []
        
        # Combine content and headers for analysis
        analysis_text = content.lower() + " " + " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        
        for tech_category, tech_dict in self.tech_patterns.items():
            for tech_name, patterns in tech_dict.items():
                for pattern in patterns:
                    if re.search(pattern, analysis_text, re.IGNORECASE):
                        tech_info = f"{tech_category}:{tech_name}"
                        if tech_info not in technologies:
                            technologies.append(tech_info)
                        break
                        
        return technologies
        
    def extract_endpoints(self, content: str, base_url: str) -> List[str]:
        """Extract API endpoints and interesting paths from content"""
        endpoints = set()
        
        # Extract links from HTML
        soup = BeautifulSoup(content, 'html.parser')
        
        # Find all links
        for link in soup.find_all(['a', 'link', 'script', 'form']):
            href = link.get('href') or link.get('src') or link.get('action')
            if href:
                full_url = urljoin(base_url, href)
                path = urlparse(full_url).path
                if path and path != '/':
                    endpoints.add(path)
                    
        # Extract API endpoints using regex
        api_patterns = [
            r'/api/[^"\s<>]+',
            r'/rest/[^"\s<>]+', 
            r'/graphql[^"\s<>]*',
            r'/v\d+/[^"\s<>]+',
            r'\.json[^"\s<>]*',
            r'\.xml[^"\s<>]*'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                endpoints.add(match)
                
        return list(endpoints)[:50]  # Limit to 50 endpoints
        
    def check_vulnerability_indicators(self, content: str) -> List[str]:
        """Check for potential vulnerability indicators"""
        indicators = []
        
        content_lower = content.lower()
        
        for indicator in self.vuln_indicators:
            if indicator in content_lower:
                indicators.append(indicator)
                
        # Check for specific patterns
        vuln_patterns = [
            (r'sql.*error', 'sql_error'),
            (r'stack.*trace', 'stack_trace'),
            (r'debug.*mode', 'debug_mode'),
            (r'internal.*server.*error', 'internal_error'),
            (r'database.*connection.*failed', 'db_error'),
            (r'unauthorized', 'auth_issue'),
            (r'access.*denied', 'access_denied')
        ]
        
        for pattern, indicator_name in vuln_patterns:
            if re.search(pattern, content_lower):
                indicators.append(indicator_name)
                
        return indicators
        
    async def detect_waf(self, domain: str) -> Dict[str, str]:
        """Detect Web Application Firewall"""
        waf_info = {"detected": False, "type": "unknown", "confidence": 0}
        
        try:
            # Test with malicious payloads to trigger WAF
            test_payloads = [
                "?id=1' OR '1'='1",
                "?q=<script>alert('xss')</script>",
                "?file=../../../../etc/passwd",
                "?cmd=cat /etc/passwd"
            ]
            
            for payload in test_payloads:
                url = f"https://{domain}/{payload}"
                
                if self.proxy_manager:
                    try:
                        status, content, headers = await self.proxy_manager.make_request(url)
                        
                        # Check for WAF indicators in headers and content
                        for waf_name, patterns in self.tech_patterns["waf"].items():
                            for pattern in patterns:
                                header_text = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
                                if re.search(pattern, header_text + content.lower(), re.IGNORECASE):
                                    waf_info = {
                                        "detected": True,
                                        "type": waf_name,
                                        "confidence": min(100, waf_info.get("confidence", 0) + 25)
                                    }
                                    
                        # Check for blocked status codes
                        if status in [403, 406, 429, 503]:
                            waf_info["detected"] = True
                            waf_info["confidence"] = min(100, waf_info.get("confidence", 0) + 15)
                            
                    except Exception as e:
                        self.logger.debug(f"WAF test failed: {str(e)}")
                        
        except Exception as e:
            self.logger.error(f"❌ WAF detection failed: {str(e)}")
            
        return waf_info
        
    async def probe_rate_limits(self, domain: str) -> Dict[str, int]:
        """Probe rate limits for different endpoints"""
        rate_limits = {}
        
        test_endpoints = ["/", "/api", "/login", "/search"]
        
        for endpoint in test_endpoints:
            url = f"https://{domain}{endpoint}"
            
            # Send rapid requests to test rate limiting
            start_time = time.time()
            request_count = 0
            
            try:
                for i in range(20):  # Test with 20 rapid requests
                    if self.proxy_manager:
                        status, _, _ = await self.proxy_manager.make_request(url)
                        request_count += 1
                        
                        if status in [429, 503]:  # Rate limited
                            elapsed = time.time() - start_time
                            rate_limits[endpoint] = int(request_count / elapsed)
                            self.logger.info(f"📊 Rate limit detected for {endpoint}: {rate_limits[endpoint]} req/sec")
                            break
                            
                    await asyncio.sleep(0.1)  # Small delay between requests
                    
            except Exception as e:
                self.logger.debug(f"Rate limit probing failed for {endpoint}: {str(e)}")
                
        return rate_limits
        
    def analyze_tech_stack(self, subdomains: List[SubdomainInfo]) -> TechStackInfo:
        """Analyze and consolidate technology stack information"""
        tech_counter = {}
        
        # Count technology occurrences across all subdomains
        for subdomain in subdomains:
            for tech in subdomain.technologies:
                tech_counter[tech] = tech_counter.get(tech, 0) + 1
                
        # Extract most common technologies by category
        web_server = self.get_most_common_tech(tech_counter, "web_servers")
        framework = self.get_most_common_tech(tech_counter, "frameworks")
        language = self.get_most_common_tech(tech_counter, "languages")
        database = self.get_most_common_tech(tech_counter, "databases")
        waf = self.get_most_common_tech(tech_counter, "waf")
        
        # Calculate confidence based on consistency
        total_subdomains = len(subdomains)
        confidence = 0.0
        if total_subdomains > 0:
            consistent_techs = sum(1 for count in tech_counter.values() if count > total_subdomains * 0.5)
            confidence = min(100.0, (consistent_techs / max(1, len(tech_counter))) * 100)
            
        return TechStackInfo(
            web_server=web_server,
            framework=framework,
            cms="",  # Will be enhanced
            database=database,
            cdn="",  # Will be enhanced
            waf=waf,
            language=language,
            libraries=[],  # Will be enhanced
            confidence=confidence
        )
        
    def get_most_common_tech(self, tech_counter: Dict[str, int], category: str) -> str:
        """Get most common technology in a category"""
        category_techs = {k: v for k, v in tech_counter.items() if k.startswith(f"{category}:")}
        if category_techs:
            return max(category_techs, key=category_techs.get).split(":", 1)[1]
        return "unknown"
        
    def calculate_priority_score(self, target: TargetProfile) -> float:
        """Calculate priority score for target based on attack surface and vulnerabilities"""
        score = 0.0
        
        # Subdomain count factor (more subdomains = larger attack surface)
        subdomain_score = min(50.0, len(target.subdomains) * 2)
        score += subdomain_score
        
        # Technology diversity factor
        tech_diversity = len(set(tech for subdomain in target.subdomains for tech in subdomain.technologies))
        tech_score = min(20.0, tech_diversity)
        score += tech_score
        
        # Vulnerability indicator factor
        vuln_count = sum(len(sub.vulnerability_indicators) for sub in target.subdomains)
        vuln_score = min(20.0, vuln_count * 2)
        score += vuln_score
        
        # Endpoint discovery factor
        endpoint_count = sum(len(sub.endpoints) for sub in target.subdomains)
        endpoint_score = min(10.0, endpoint_count * 0.1)
        score += endpoint_score
        
        return min(100.0, score)
        
    async def full_reconnaissance(self, domain: str, api_keys: Dict[str, str] = None) -> TargetProfile:
        """Perform comprehensive reconnaissance on target domain"""
        self.logger.info(f"🎯 Starting full reconnaissance for {domain}")
        
        api_keys = api_keys or {}
        
        # Phase 1: Subdomain Enumeration
        self.logger.info("🔍 Phase 1: Subdomain Enumeration")
        all_subdomains = set([domain])  # Include main domain
        
        # crt.sh enumeration
        crtsh_subdomains = await self.enumerate_subdomains_crtsh(domain)
        all_subdomains.update(crtsh_subdomains)
        
        # VirusTotal enumeration (if API key provided)
        if api_keys.get('virustotal'):
            vt_subdomains = await self.enumerate_subdomains_virustotal(domain, api_keys['virustotal'])
            all_subdomains.update(vt_subdomains)
            
        # Brute force enumeration
        bf_subdomains = await self.enumerate_subdomains_bruteforce(domain)
        all_subdomains.update(bf_subdomains)
        
        self.logger.info(f"📊 Found {len(all_subdomains)} total subdomains")
        
        # Phase 2: Subdomain Probing
        self.logger.info("🔍 Phase 2: Subdomain Probing")
        subdomain_infos = []
        
        probe_tasks = []
        for subdomain in all_subdomains:
            probe_tasks.append(self.probe_subdomain_info(subdomain))
            
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)
        
        for result in probe_results:
            if result and not isinstance(result, Exception):
                subdomain_infos.append(result)
                
        self.logger.info(f"✅ Successfully probed {len(subdomain_infos)} subdomains")
        
        # Phase 3: Technology Analysis
        self.logger.info("🔍 Phase 3: Technology Stack Analysis")
        tech_stack = self.analyze_tech_stack(subdomain_infos)
        
        # Phase 4: Security Analysis
        self.logger.info("🔍 Phase 4: Security Analysis")
        waf_info = await self.detect_waf(domain)
        rate_limits = await self.probe_rate_limits(domain)
        
        # Phase 5: Compile Results
        all_endpoints = []
        all_parameters = []
        
        for subdomain in subdomain_infos:
            all_endpoints.extend(subdomain.endpoints)
            
        # Remove duplicates and sort
        all_endpoints = sorted(list(set(all_endpoints)))
        
        target_profile = TargetProfile(
            domain=domain,
            subdomains=subdomain_infos,
            tech_stack=tech_stack,
            endpoints=all_endpoints,
            parameters=all_parameters,
            rate_limits=rate_limits,
            waf_info=waf_info,
            security_headers={},
            certificates={},
            organization_info={},
            attack_surface={
                "subdomains": len(subdomain_infos),
                "endpoints": len(all_endpoints),
                "technologies": len(set(tech for sub in subdomain_infos for tech in sub.technologies)),
                "vulnerability_indicators": sum(len(sub.vulnerability_indicators) for sub in subdomain_infos)
            },
            priority_score=0.0
        )
        
        # Calculate priority score
        target_profile.priority_score = self.calculate_priority_score(target_profile)
        
        self.logger.info(f"🎯 Reconnaissance complete for {domain}")
        self.logger.info(f"📊 Priority Score: {target_profile.priority_score:.1f}/100")
        
        return target_profile
        
    def export_intelligence_report(self, target: TargetProfile, filename: str = None) -> str:
        """Export comprehensive intelligence report"""
        if not filename:
            filename = f"shadowos_intel_{target.domain}_{int(time.time())}.json"
            
        # Convert dataclass to dict for JSON serialization
        report = {
            "timestamp": datetime.now().isoformat(),
            "target": target.domain,
            "priority_score": target.priority_score,
            "attack_surface": target.attack_surface,
            "tech_stack": asdict(target.tech_stack),
            "waf_info": target.waf_info,
            "rate_limits": target.rate_limits,
            "subdomains": [asdict(sub) for sub in target.subdomains],
            "endpoints": target.endpoints,
            "summary": {
                "total_subdomains": len(target.subdomains),
                "total_endpoints": len(target.endpoints),
                "vulnerability_indicators": target.attack_surface["vulnerability_indicators"],
                "primary_technology": target.tech_stack.framework or target.tech_stack.language,
                "waf_detected": target.waf_info.get("detected", False)
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
            
        self.logger.info(f"📊 Intelligence report exported to {filename}")
        return filename

# CLI Interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="ShadowOS Intelligence Engine")
    parser.add_argument("domain", help="Target domain for reconnaissance")
    parser.add_argument("--proxy", action="store_true", help="Use proxy manager")
    parser.add_argument("--vt-key", type=str, help="VirusTotal API key")
    parser.add_argument("--output", type=str, help="Output file for report")
    
    args = parser.parse_args()
    
    async def main():
        # Initialize proxy manager if requested
        proxy_manager = None
        if args.proxy:
            from proxy_manager import ShadowProxyManager
            proxy_manager = ShadowProxyManager()
            await proxy_manager.health_check_all_proxies()
            proxy_manager.rotate_proxy()
            
        # Initialize intelligence engine
        intel_engine = ShadowIntelEngine(proxy_manager)
        
        try:
            # API keys setup
            api_keys = {}
            if args.vt_key:
                api_keys['virustotal'] = args.vt_key
                
            # Perform reconnaissance
            print(f"🎯 Starting reconnaissance for {args.domain}")
            target_profile = await intel_engine.full_reconnaissance(args.domain, api_keys)
            
            # Generate and display summary
            summary = intel_engine.generate_intelligence_summary(target_profile)
            print(summary)
            
            # Export detailed JSON report
            output_file = args.output or f"intel_report_{args.domain}_{int(time.time())}.json"
            intel_engine.export_intelligence_report(target_profile, output_file)
            print(f"📊 Detailed report exported to: {output_file}")
            
        except Exception as e:
            print(f"❌ Reconnaissance failed: {str(e)}")
            import traceback
            print(traceback.format_exc())
            
        finally:
            await intel_engine.close_session()
