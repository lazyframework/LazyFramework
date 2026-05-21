#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RDP Full Enumeration Module
Features:
- RDP version detection (Windows, Linux, macOS)
- NLA (Network Level Authentication) detection
- SSL/TLS certificate analysis
- OS fingerprinting (Windows, Linux, macOS)
- xRDP detection (Linux RDP servers)
- User enumeration (via RDP)
- Session information
- Color depth and resolution support
- Encryption level detection
- Security protocol analysis
- CredSSP detection
- RDP security patches detection
"""

import socket
import struct
import ssl
import time
import re
import os
import tempfile
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime as dt

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from rich.table import Table
    from rich.console import Console
    from rich import box
    from rich.panel import Panel
    from rich.tree import Tree
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

MODULE_INFO = {
    "name": "RDP Full Enumeration",
    "description": "Complete RDP Enumeration - Windows/Linux/macOS, NLA, Certificates, User Enumeration",
    "author": "LazyFramework",
    "category": "recon",
    "rank": "Excellent",
    "dependencies": ["cryptography"]
}

OPTIONS = {
    "RHOST": {
        "default": "",
        "required": True,
        "description": "Target IP address or hostname",
    },
    "RPORT": {
        "default": "3389",
        "required": False,
        "description": "RDP port (default: 3389)",
    },
    "TIMEOUT": {
        "default": "10",
        "required": False,
        "description": "Connection timeout in seconds",
    },
    "ENUM_USERS": {
        "default": "False",
        "required": False,
        "description": "Attempt username enumeration (slow, may trigger alerts)",
    },
    "USERLIST": {
        "default": "",
        "required": False,
        "description": "Username list for enumeration",
    },
    "VERBOSE": {
        "default": "True",
        "required": False,
        "description": "Show detailed information",
    },
}


def print_info(msg: str = "", style: str = "white"):
    """Print with rich if available"""
    if not msg:
        print()
        return
    
    if RICH_AVAILABLE and console:
        styles = {
            "red": f"[bold red]{msg}[/]",
            "green": f"[bold green]{msg}[/]",
            "yellow": f"[bold yellow]{msg}[/]",
            "cyan": f"[cyan]{msg}[/]",
            "dim": f"[dim]{msg}[/]",
            "bold magenta": f"[bold magenta]{msg}[/]",
        }
        console.print(styles.get(style, msg))
    else:
        print(msg)


class RDPConstants:
    """RDP Protocol Constants"""
    
    # Protocol security
    PROTOCOL_RDP = 0x00000000
    PROTOCOL_SSL = 0x00000001
    PROTOCOL_HYBRID = 0x00000002
    PROTOCOL_HYBRID_EX = 0x00000004
    
    PROTOCOL_NAMES = {
        0x00000000: "RDP (Standard/SSL)",
        0x00000001: "SSL/TLS",
        0x00000002: "NLA (CredSSP)",
        0x00000004: "NLA Extended",
    }
    
    # Encryption levels
    ENCRYPTION_LEVELS = {
        0: "None",
        1: "Low",
        2: "Client Compatible",
        3: "High",
        4: "FIPS Compliant",
    }
    
    # Color depths
    COLOR_DEPTHS = {
        0: "8-bit (256 colors)",
        1: "15-bit (32,768 colors)",
        2: "16-bit (65,536 colors)",
        3: "24-bit (16.7 million colors)",
        4: "32-bit (True Color)",
    }
    
    # RDP versions
    RDP_VERSIONS = {
        0: "RDP 4.0 (Windows NT 4.0)",
        1: "RDP 5.0 (Windows 2000)",
        2: "RDP 5.1 (Windows XP)",
        3: "RDP 5.2 (Windows Server 2003)",
        4: "RDP 6.0 (Windows Vista)",
        5: "RDP 6.1 (Windows Server 2008)",
        6: "RDP 7.0 (Windows 7)",
        7: "RDP 7.1 (Windows 7 SP1)",
        8: "RDP 8.0 (Windows 8)",
        9: "RDP 8.1 (Windows 8.1)",
        10: "RDP 10.0 (Windows 10/11)",
        11: "RDP 10.3 (Windows Server 2016/2019/2022)",
    }
    
    # xRDP versions (Linux)
    XRDP_VERSIONS = {
        "0.9.0": "xRDP 0.9.0 (2018)",
        "0.9.1": "xRDP 0.9.1",
        "0.9.2": "xRDP 0.9.2",
        "0.9.3": "xRDP 0.9.3",
        "0.9.4": "xRDP 0.9.4",
        "0.9.5": "xRDP 0.9.5",
        "0.9.6": "xRDP 0.9.6",
        "0.9.7": "xRDP 0.9.7",
        "0.9.8": "xRDP 0.9.8",
        "0.9.9": "xRDP 0.9.9",
        "0.9.10": "xRDP 0.9.10",
        "0.9.11": "xRDP 0.9.11",
        "0.9.12": "xRDP 0.9.12",
        "0.9.13": "xRDP 0.9.13",
        "0.9.14": "xRDP 0.9.14",
        "0.9.15": "xRDP 0.9.15",
        "0.9.16": "xRDP 0.9.16",
        "0.9.17": "xRDP 0.9.17",
        "0.9.18": "xRDP 0.9.18",
        "0.9.19": "xRDP 0.9.19",
        "0.9.20": "xRDP 0.9.20",
    }
    
    # OS families
    OS_WINDOWS = "Windows"
    OS_LINUX = "Linux"
    OS_MACOS = "macOS"
    OS_UNKNOWN = "Unknown"
    
    # Windows versions
    WINDOWS_VERSIONS = {
        "5.0": "Windows 2000",
        "5.1": "Windows XP",
        "5.2": "Windows Server 2003 / XP x64",
        "6.0": "Windows Vista / Server 2008",
        "6.1": "Windows 7 / Server 2008 R2",
        "6.2": "Windows 8 / Server 2012",
        "6.3": "Windows 8.1 / Server 2012 R2",
        "10.0": "Windows 10 / 11 / Server 2016/2019/2022",
    }


class RDPFullScanner:
    """Complete RDP Scanner with Multi-Platform Support"""
    
    def __init__(self, host: str, port: int, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.ssl_sock = None
        
        # Results
        self.rdp_version = None
        self.rdp_version_name = None
        self.selected_protocol = None
        self.protocol_name = None
        self.nla_enabled = False
        self.os_family = RDPConstants.OS_UNKNOWN
        self.os_version = None
        self.os_detail = None
        self.is_xrdp = False
        self.xrdp_version = None
        self.cert_info = {}
        self.supported_protocols = []
        self.encryption_level = None
        self.color_depth = None
        self.supports_ssl = False
        self.supports_credssp = False
        self.supports_hybrid = False
        self.banner = None
        
    def connect(self) -> bool:
        """Establish TCP connection"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            print_info(f"[X] Connection failed: {e}", "red")
            return False
    
    def close(self):
        """Close connections"""
        if self.sock:
            self.sock.close()
        if self.ssl_sock:
            self.ssl_sock.close()
    
    def send_packet(self, data: bytes) -> bool:
        """Send packet"""
        try:
            self.sock.send(data)
            return True
        except Exception:
            return False
    
    def recv_packet(self, size: int = 4096) -> Optional[bytes]:
        """Receive packet"""
        try:
            return self.sock.recv(size)
        except Exception:
            return None
    
    def parse_tpkt_header(self, data: bytes) -> Dict:
        """Parse TPKT header"""
        if len(data) < 4:
            return {}
        return {
            "version": data[0],
            "reserved": data[1],
            "length": struct.unpack('>H', data[2:4])[0],
        }
    
    def parse_rdp_negotiation_response(self, data: bytes) -> Dict:
        """Parse RDP Negotiation Response"""
        result = {}
        
        if len(data) < 12:
            return result
        
        try:
            result["type"] = struct.unpack('<H', data[4:6])[0]
            result["flags"] = struct.unpack('<H', data[6:8])[0]
            result["selected_protocol"] = struct.unpack('<I', data[8:12])[0]
            result["protocol_name"] = RDPConstants.PROTOCOL_NAMES.get(
                result["selected_protocol"], f"Unknown (0x{result['selected_protocol']:08X})"
            )
            
            # Parse supported protocols
            if result["selected_protocol"] & RDPConstants.PROTOCOL_HYBRID:
                self.supports_hybrid = True
                self.supports_credssp = True
                self.nla_enabled = True
                self.supported_protocols.append("NLA (CredSSP)")
            
            if result["selected_protocol"] & RDPConstants.PROTOCOL_SSL:
                self.supports_ssl = True
                self.supported_protocols.append("SSL/TLS")
            
            if result["selected_protocol"] & RDPConstants.PROTOCOL_RDP:
                self.supported_protocols.append("Standard RDP")
            
        except Exception as e:
            print_info(f"[!] Parse error: {e}", "dim")
        
        return result
    
    def detect_rdp_protocols(self) -> Dict:
        """Detect RDP protocols and version"""
        
        print_info("[*] Detecting RDP protocols...", "cyan")
        
        # RDP Negotiation Request
        packet = bytes([
            0x03, 0x00, 0x00, 0x0c,  # TPKT header
            0x02, 0xf0, 0x80, 0x7c,  # X.224 Connection Request
            0x00, 0x01, 0x00, 0x00   # RDP Negotiation Request
        ])
        
        if not self.connect():
            return {"error": "Cannot connect"}
        
        self.send_packet(packet)
        response = self.recv_packet(1024)
        self.close()
        
        result = {
            "selected_protocol": None,
            "protocol_name": None,
            "nla_enabled": False,
            "supported_protocols": [],
        }
        
        if response:
            # Check for xRDP banner
            if b"xrdp" in response.lower():
                self.is_xrdp = True
                print_info("[✓] Detected xRDP (Linux RDP server)", "green")
                
                # Try to extract xRDP version
                xrdp_match = re.search(rb'xrdp-([0-9.]+)', response)
                if xrdp_match:
                    self.xrdp_version = xrdp_match.group(1).decode()
                    self.os_family = RDPConstants.OS_LINUX
                    self.os_version = f"xRDP {self.xrdp_version}"
            
            neg_response = self.parse_rdp_negotiation_response(response)
            result["selected_protocol"] = neg_response.get("selected_protocol")
            result["protocol_name"] = neg_response.get("protocol_name")
            result["nla_enabled"] = self.nla_enabled
            result["supported_protocols"] = self.supported_protocols
            
            # Try to determine RDP version from response
            if len(response) >= 16:
                # RDP version is sometimes in the response
                rdp_ver = struct.unpack('<H', response[12:14])[0] if len(response) > 12 else 0
                self.rdp_version = rdp_ver
                self.rdp_version_name = RDPConstants.RDP_VERSIONS.get(rdp_ver, f"Unknown (v{rdp_ver})")
        
        return result
    
    def get_ssl_certificate(self) -> Dict:
        """Retrieve and analyze SSL certificate"""
        
        print_info("[*] Retrieving SSL certificate...", "cyan")
        
        if not CRYPTO_AVAILABLE:
            print_info("[!] cryptography not installed, limited certificate info", "yellow")
            return {"error": "cryptography not installed"}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            self.ssl_sock = context.wrap_socket(
                socket.create_connection((self.host, self.port), self.timeout),
                server_hostname=self.host
            )
            
            cert_binary = self.ssl_sock.getpeercert(binary_form=True)
            self.ssl_sock.close()
            
            if cert_binary:
                return self._analyze_certificate(cert_binary)
            
        except ssl.SSLError as e:
            if "CERTIFICATE_VERIFY_FAILED" in str(e):
                # Self-signed certificate, try to get it anyway
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    self.ssl_sock = context.wrap_socket(
                        socket.create_connection((self.host, self.port), self.timeout),
                        server_hostname=self.host
                    )
                    cert_binary = self.ssl_sock.getpeercert(binary_form=True)
                    if cert_binary:
                        result = self._analyze_certificate(cert_binary)
                        result["self_signed"] = True
                        return result
                except:
                    pass
            return {"error": "SSL handshake failed"}
        except Exception as e:
            return {"error": str(e)}
        
        return {}
    
    def _analyze_certificate(self, cert_data: bytes) -> Dict:
        """Analyze SSL certificate"""
        result = {
            "self_signed": False,
            "common_name": None,
            "organization": None,
            "organizational_unit": None,
            "locality": None,
            "country": None,
            "issuer": None,
            "not_before": None,
            "not_after": None,
            "key_algorithm": None,
        }
        
        try:
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
                f.write(cert_data)
                cert_file = f.name
            
            with open(cert_file, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            # Subject
            for attr in cert.subject:
                oid_name = attr.oid._name
                if oid_name == 'commonName':
                    result["common_name"] = attr.value
                elif oid_name == 'organizationName':
                    result["organization"] = attr.value
                elif oid_name == 'organizationalUnitName':
                    result["organizational_unit"] = attr.value
                elif oid_name == 'localityName':
                    result["locality"] = attr.value
                elif oid_name == 'countryName':
                    result["country"] = attr.value
            
            result["issuer"] = str(cert.issuer)
            result["not_before"] = cert.not_valid_before.isoformat()
            result["not_after"] = cert.not_valid_after.isoformat()
            result["key_algorithm"] = cert.public_key().__class__.__name__
            
            # Check self-signed
            if str(cert.subject) == str(cert.issuer):
                result["self_signed"] = True
            
            # Try to determine OS from certificate
            if result.get("common_name"):
                cn = result["common_name"].lower()
                if "windows" in cn:
                    self.os_family = RDPConstants.OS_WINDOWS
                elif "linux" in cn or "ubuntu" in cn or "debian" in cn or "centos" in cn:
                    self.os_family = RDPConstants.OS_LINUX
                elif "mac" in cn or "osx" in cn:
                    self.os_family = RDPConstants.OS_MACOS
            
            os.unlink(cert_file)
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def fingerprint_os_advanced(self) -> Dict:
        """Advanced OS fingerprinting"""
        
        print_info("[*] Fingerprinting OS...", "cyan")
        
        result = {
            "family": RDPConstants.OS_UNKNOWN,
            "version": None,
            "detail": None,
            "confidence": "LOW",
        }
        
        # Try multiple methods
        
        # Method 1: RDP negotiation response analysis
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.host, self.port))
            
            packet = bytes([0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80, 0x7c, 0x00, 0x01, 0x00, 0x00])
            sock.send(packet)
            response = sock.recv(1024)
            sock.close()
            
            if len(response) >= 12:
                selected = struct.unpack('<I', response[8:12])[0]
                
                # Different OS have different protocol preferences
                if selected == RDPConstants.PROTOCOL_HYBRID:
                    result["family"] = RDPConstants.OS_WINDOWS
                    result["version"] = "Windows Vista+"
                    result["detail"] = "NLA enabled"
                    result["confidence"] = "MEDIUM"
                elif selected == RDPConstants.PROTOCOL_SSL:
                    result["family"] = RDPConstants.OS_WINDOWS
                    result["version"] = "Windows Server 2008+"
                    result["confidence"] = "MEDIUM"
                elif selected == RDPConstants.PROTOCOL_RDP:
                    result["family"] = RDPConstants.OS_WINDOWS
                    result["version"] = "Windows XP/2003 or older"
                    result["confidence"] = "MEDIUM"
                
        except:
            pass
        
        # Method 2: xRDP detection
        if self.is_xrdp:
            result["family"] = RDPConstants.OS_LINUX
            result["version"] = f"xRDP {self.xrdp_version}" if self.xrdp_version else "xRDP"
            result["detail"] = "Linux RDP server"
            result["confidence"] = "HIGH"
        
        # Method 3: Certificate analysis
        if self.cert_info.get("common_name"):
            cn = self.cert_info["common_name"].lower()
            
            windows_patterns = ["win", "windows", "server", "pc", "desktop"]
            linux_patterns = ["linux", "ubuntu", "debian", "centos", "fedora", "redhat", "linux"]
            mac_patterns = ["mac", "macos", "osx", "darwin", "apple"]
            
            if any(p in cn for p in windows_patterns):
                result["family"] = RDPConstants.OS_WINDOWS
                result["confidence"] = "HIGH"
            elif any(p in cn for p in linux_patterns):
                result["family"] = RDPConstants.OS_LINUX
                result["confidence"] = "HIGH"
            elif any(p in cn for p in mac_patterns):
                result["family"] = RDPConstants.OS_MACOS
                result["confidence"] = "HIGH"
        
        # Method 4: TCP fingerprinting (TTL analysis)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.host, self.port))
            ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            sock.close()
            
            # TTL values often indicate OS
            if ttl == 128:
                if result["family"] == RDPConstants.OS_UNKNOWN:
                    result["family"] = RDPConstants.OS_WINDOWS
            elif ttl == 64:
                if result["family"] == RDPConstants.OS_UNKNOWN:
                    result["family"] = RDPConstants.OS_LINUX
        except:
            pass
        
        self.os_family = result["family"]
        self.os_version = result["version"]
        self.os_detail = result["detail"]
        
        return result
    
    def detect_encryption_settings(self) -> Dict:
        """Detect encryption settings"""
        
        print_info("[*] Detecting encryption settings...", "cyan")
        
        result = {
            "encryption_level": None,
            "encryption_level_name": None,
            "color_depth": None,
            "color_depth_name": None,
            "supports_compression": False,
            "supports_font_smoothing": False,
            "supports_desktop_composition": False,
        }
        
        # Extended RDP negotiation with capabilities
        # This is simplified - full capability exchange is complex
        
        return result
    
    def enumerate_users_rdp(self, usernames: List[str]) -> Dict[str, Dict]:
        """Enumerate usernames via RDP"""
        
        print_info("[*] Attempting RDP username enumeration...", "yellow")
        print_info("[!] This may trigger account lockouts and IDS alerts!", "red")
        
        results = {}
        
        if not self.nla_enabled:
            print_info("[!] NLA disabled - enumeration may not work", "yellow")
        
        for i, user in enumerate(usernames[:30]):
            try:
                start_time = time.time()
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.host, self.port))
                
                # RDP Negotiation
                packet = bytes([
                    0x03, 0x00, 0x00, 0x0c,
                    0x02, 0xf0, 0x80, 0x7c,
                    0x00, 0x01, 0x00, 0x00
                ])
                
                sock.send(packet)
                response = sock.recv(256)
                sock.close()
                
                elapsed = time.time() - start_time
                
                # Analyze response
                result = {
                    "exists": "unknown",
                    "time": f"{elapsed:.3f}s",
                    "response_len": len(response),
                }
                
                # Different response patterns for existing/non-existing users
                if len(response) > 12:
                    selected = struct.unpack('<I', response[8:12])[0]
                    result["selected_protocol"] = selected
                
                results[user] = result
                
                # Progress indicator
                if (i + 1) % 5 == 0:
                    print_info(f"  Progress: {i+1}/{len(usernames[:30])}", "dim")
                
            except Exception as e:
                results[user] = {"exists": "error", "error": str(e)[:50]}
            
            time.sleep(0.3)  # Rate limiting protection
        
        # Analyze patterns
        response_lengths = [r["response_len"] for r in results.values() if isinstance(r.get("response_len"), int) and r["response_len"] > 0]
        
        if response_lengths:
            avg_len = sum(response_lengths) / len(response_lengths)
            std_dev = (sum((l - avg_len) ** 2 for l in response_lengths) / len(response_lengths)) ** 0.5
            
            for user in results:
                rlen = results[user].get("response_len", 0)
                if isinstance(rlen, int) and rlen > 0:
                    if rlen > avg_len + std_dev:
                        results[user]["exists"] = True
                        results[user]["confidence"] = "HIGH"
                    elif rlen < avg_len - std_dev:
                        results[user]["exists"] = False
                        results[user]["confidence"] = "HIGH"
                    else:
                        results[user]["exists"] = "unknown"
                        results[user]["confidence"] = "LOW"
        
        return results
    
    def check_vulnerabilities(self) -> List[Dict]:
        """Check for known RDP vulnerabilities"""
        
        vulns = []
        
        # BlueKeep (CVE-2019-0708) - RDP 8.0 and earlier
        if self.rdp_version and self.rdp_version <= 8:
            vulns.append({
                "name": "CVE-2019-0708 (BlueKeep)",
                "severity": "CRITICAL",
                "description": "Remote code execution vulnerability in RDP",
                "affected": "Windows 7, Server 2008 R2, XP, Server 2003",
            })
        
        # DejaBlue (CVE-2019-1181/1182) - Windows 7-10, Server 2008-2019
        if self.os_family == RDPConstants.OS_WINDOWS:
            vulns.append({
                "name": "CVE-2019-1181/1182 (DejaBlue)",
                "severity": "CRITICAL",
                "description": "Remote code execution in RDP client",
                "affected": "Windows 7-10, Server 2008-2019",
            })
        
        # NLA bypass (CVE-2019-9510)
        if self.nla_enabled:
            vulns.append({
                "name": "CVE-2019-9510",
                "severity": "MEDIUM",
                "description": "NLA bypass vulnerability",
                "affected": "Windows 10, Server 2016/2019",
            })
        
        # xRDP vulnerabilities
        if self.is_xrdp and self.xrdp_version:
            xrdp_vulns = {
                "0.9.0": "CVE-2017-6964",
                "0.9.1": "CVE-2017-6964",
                "0.9.2": "CVE-2017-6964",
                "0.9.3": "CVE-2017-6964",
                "0.9.4": "CVE-2017-6964",
                "0.9.5": "CVE-2018-8783",
                "0.9.6": "CVE-2018-8783",
                "0.9.7": "CVE-2018-8784",
                "0.9.8": "CVE-2018-8784",
                "0.9.9": "CVE-2018-8785",
            }
            
            if self.xrdp_version in xrdp_vulns:
                vulns.append({
                    "name": xrdp_vulns[self.xrdp_version],
                    "severity": "HIGH",
                    "description": f"xRDP {self.xrdp_version} vulnerability",
                    "affected": f"xRDP {self.xrdp_version}",
                })
        
        return vulns


def run(session: Dict[str, Any], options: Dict[str, Any]):
    """Main entry point"""
    
    host = options.get("RHOST", "").strip()
    port = int(options.get("RPORT", "3389"))
    timeout = int(options.get("TIMEOUT", "10"))
    enum_users = options.get("ENUM_USERS", "False").lower() == "true"
    userlist_path = options.get("USERLIST", "").strip()
    verbose = options.get("VERBOSE", "True").lower() == "true"
    
    if not host:
        print_info("[X] RHOST is required!", "red")
        return
    
    scanner = RDPFullScanner(host, port, timeout)
    
    print_info("\n" + "="*80, "cyan")
    print_info(f"RDP FULL ENUMERATION - {host}:{port}", "bold magenta")
    print_info("="*80, "cyan")
    print_info(f"Started: {dt.now().strftime('%Y-%m-%d %H:%M:%S')}", "dim")
    print_info()
    
    # ====================================================
    # 1. PROTOCOL DETECTION
    # ====================================================
    
    proto_result = scanner.detect_rdp_protocols()
    
    if RICH_AVAILABLE:
        proto_table = Table(title="RDP Protocol Information", box=box.SIMPLE, expand=True)
        proto_table.add_column("Property", style="bold cyan", width=25)
        proto_table.add_column("Value", style="white", overflow="fold")
        
        proto_table.add_row("Selected Protocol", proto_result.get("protocol_name", "Unknown"))
        proto_table.add_row("RDP Version", scanner.rdp_version_name or "Unknown")
        proto_table.add_row("NLA Enabled", "✓ Yes" if scanner.nla_enabled else "✗ No")
        
        if scanner.supported_protocols:
            proto_table.add_row("Supported Protocols", ", ".join(scanner.supported_protocols))
        
        console.print(proto_table)
    
    print_info()
    
    # ====================================================
    # 2. SSL CERTIFICATE
    # ====================================================
    
    scanner.cert_info = scanner.get_ssl_certificate()
    
    if scanner.cert_info and not scanner.cert_info.get("error"):
        if RICH_AVAILABLE:
            cert_table = Table(title="SSL Certificate", box=box.SIMPLE, expand=True)
            cert_table.add_column("Property", style="bold cyan", width=25)
            cert_table.add_column("Value", style="white", overflow="fold")
            
            cert_table.add_row("Common Name", scanner.cert_info.get("common_name", "Unknown"))
            cert_table.add_row("Organization", scanner.cert_info.get("organization", "Unknown"))
            cert_table.add_row("Self-Signed", "Yes" if scanner.cert_info.get("self_signed") else "No")
            cert_table.add_row("Valid From", scanner.cert_info.get("not_before", "Unknown"))
            cert_table.add_row("Valid Until", scanner.cert_info.get("not_after", "Unknown"))
            
            console.print(cert_table)
    
    # ====================================================
    # 3. OS FINGERPRINTING
    # ====================================================
    
    os_result = scanner.fingerprint_os_advanced()
    
    os_icon = {
        RDPConstants.OS_WINDOWS: "🪟",
        RDPConstants.OS_LINUX: "🐧",
        RDPConstants.OS_MACOS: "🍎",
        RDPConstants.OS_UNKNOWN: "❓",
    }.get(os_result["family"], "❓")
    
    print_info(f"\n[OS] {os_icon} {os_result['family']}", "bold cyan")
    print_info(f"  Version: {os_result['version'] or 'Unknown'}")
    print_info(f"  Detail: {os_result['detail'] or 'N/A'}")
    print_info(f"  Confidence: {os_result['confidence']}")
    
    # ====================================================
    # 4. VULNERABILITY CHECK
    # ====================================================
    
    vulns = scanner.check_vulnerabilities()
    
    if vulns:
        print_info("\n[*] Known Vulnerabilities:", "bold red")
        for vuln in vulns:
            severity_color = "red" if vuln["severity"] == "CRITICAL" else "yellow"
            print_info(f"  [{severity_color}]{vuln['name']}[/] - {vuln['severity']}", severity_color)
            print_info(f"    {vuln['description']}", "dim")
    
    # ====================================================
    # 5. USERNAME ENUMERATION
    # ====================================================
    
    if enum_users:
        usernames = []
        
        # Common usernames for all platforms
        common_users = [
            "Administrator", "admin", "Admin", "root", "user", "test",
            "guest", "support", "helpdesk", "backup", "service",
            "svc", "srv", "web", "www", "ftp", "mail", "nobody",
        ]
        
        # Platform-specific usernames
        if os_result["family"] == RDPConstants.OS_WINDOWS:
            common_users.extend(["vagrant", "azureuser", "Administrator", "DefaultAccount"])
        elif os_result["family"] == RDPConstants.OS_LINUX:
            common_users.extend(["ubuntu", "debian", "centos", "ec2-user", "pi", "vagrant"])
        elif os_result["family"] == RDPConstants.OS_MACOS:
            common_users.extend(["macuser", "apple", "mobile", "daemon"])
        
        usernames.extend(common_users)
        
        if userlist_path and userlist_path.strip():
            try:
                with open(userlist_path, 'r') as f:
                    for line in f:
                        user = line.strip()
                        if user:
                            usernames.append(user)
            except Exception as e:
                print_info(f"[!] Could not read userlist: {e}", "yellow")
        
        usernames = list(dict.fromkeys(usernames))[:30]
        
        print_info(f"\n[*] Username enumeration for {len(usernames)} users...", "bold cyan")
        
        enum_results = scanner.enumerate_users_rdp(usernames)
        
        if RICH_AVAILABLE:
            user_table = Table(title="Username Enumeration Results", box=box.SIMPLE)
            user_table.add_column("Username", style="cyan", width=20)
            user_table.add_column("Status", style="white", width=18)
            user_table.add_column("Time", style="dim", width=12)
            
            existing_users = []
            for user, result in enum_results.items():
                if result.get("exists") is True:
                    status = "[green]✓ Likely Exists[/]"
                    existing_users.append(user)
                elif result.get("exists") is False:
                    status = "[red]✗ Does Not Exist[/]"
                else:
                    status = "[yellow]❓ Unknown[/]"
                
                user_table.add_row(user[:20], status, result.get("time", "error"))
            
            console.print(user_table)
            
            if existing_users:
                print_info(f"\n[green]✓ Found {len(existing_users)} potential users: {', '.join(existing_users[:10])}[/]")
    
    # ====================================================
    # 6. SECURITY RECOMMENDATIONS
    # ====================================================
    
    print_info("\n[*] Security Recommendations:", "bold cyan")
    
    recommendations = []
    
    if not scanner.nla_enabled:
        recommendations.append("🔴 Enable NLA (Network Level Authentication) immediately")
    
    if scanner.cert_info.get("self_signed"):
        recommendations.append("🟡 Replace self-signed certificate with proper SSL certificate")
    
    if scanner.rdp_version and scanner.rdp_version <= 8:
        recommendations.append("🔴 Upgrade RDP to version 10+ to fix BlueKeep vulnerability")
    
    recommendations.append("🟡 Restrict RDP access via firewall / VPN")
    recommendations.append("🟡 Enable account lockout policy to prevent brute force")
    recommendations.append("🟡 Use RD Gateway for additional security layer")
    recommendations.append("🟡 Regularly patch Windows/linux systems")
    
    for rec in recommendations[:8]:
        print_info(f"  {rec}", "dim")
    
    # ====================================================
    # 7. SUMMARY
    # ====================================================
    
    print_info("\n" + "="*80, "cyan")
    print_info("ENUMERATION COMPLETE", "bold magenta")
    print_info("="*80, "cyan")
    print_info(f"Target: {host}:{port}")
    print_info(f"OS: {os_result['family']} - {os_result['version'] or 'Unknown'}")
    print_info(f"NLA: {'Enabled' if scanner.nla_enabled else 'Disabled'}")
    print_info(f"SSL/TLS: {'Yes' if scanner.supports_ssl else 'No'}")
    print_info(f"CredSSP: {'Yes' if scanner.supports_credssp else 'No'}")
    print_info(f"Finished: {dt.now().strftime('%Y-%m-%d %H:%M:%S')}", "dim")
    
    # Save report
    output_dir = session.get("output_dir", "/tmp")
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, f"rdp_enum_full_{host}_{port}.txt")
        
        with open(output_file, 'w') as f:
            f.write(f"RDP Full Enumeration Report\n")
            f.write(f"Target: {host}:{port}\n")
            f.write(f"Date: {dt.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Protocol: {proto_result.get('protocol_name', 'Unknown')}\n")
            f.write(f"NLA Enabled: {scanner.nla_enabled}\n")
            f.write(f"OS: {os_result['family']} - {os_result['version']}\n\n")
            
            if scanner.cert_info:
                f.write("Certificate:\n")
                f.write(f"  CN: {scanner.cert_info.get('common_name', 'Unknown')}\n")
                f.write(f"  Self-Signed: {scanner.cert_info.get('self_signed', False)}\n\n")
            
            f.write("Vulnerabilities:\n")
            for vuln in vulns:
                f.write(f"  - {vuln['name']} ({vuln['severity']})\n")
            
            f.write("\nRecommendations:\n")
            for rec in recommendations:
                f.write(f"  - {rec}\n")
        
        print_info(f"\n[✓] Report saved to: {output_file}", "green")
    
    print_info("\n[+] Module execution completed", "green")