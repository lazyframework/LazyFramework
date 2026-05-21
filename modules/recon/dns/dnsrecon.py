#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNSRecon Module for LazyFramework
DNS Enumeration and Reconnaissance Tool
"""

import subprocess
import re
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    from rich.text import Text
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None

console = Console()

MODULE_INFO = {
    "name": "DNSRecon DNS Enumeration",
    "description": "DNSRecon - Advanced DNS enumeration and reconnaissance tool. Performs various DNS record lookups, brute forcing, zone transfers, and search engine enumeration.",
    "author": "LazyFramework",
    "license": "GPLv3",
    "platform": "Linux/Unix",
    "arch": "all",
    "rank": "Excellent",
    "dependencies": [],
    "references": [
        "https://github.com/darkoperator/dnsrecon",
        "https://www.kali.org/tools/dnsrecon/"
    ]
}

OPTIONS = {
    "DOMAIN": {
        "description": "Target domain (required)",
        "required": True,
        "default": ""
    },
    "TYPE": {
        "description": "Enumeration type: std, rvl, brt, srv, axfr, bing, yand, crt, snoop, tld, zonewalk",
        "required": False,
        "default": "std"
    },
    "NAME_SERVER": {
        "description": "DNS server to use (comma separated for multiple)",
        "required": False,
        "default": ""
    },
    "RANGE": {
        "description": "IP range for reverse lookup (e.g., 192.168.1.1-255 or 192.168.1.0/24)",
        "required": False,
        "default": ""
    },
    "DICTIONARY": {
        "description": "Dictionary file for brute force",
        "required": False,
        "default": ""
    },
    "THREADS": {
        "description": "Number of threads to use",
        "required": False,
        "default": "10"
    },
    "LIFETIME": {
        "description": "Time to wait for server response (seconds)",
        "required": False,
        "default": "3.0"
    },
    "AXFR": {
        "description": "Perform AXFR zone transfer with standard enumeration",
        "required": False,
        "default": "false"
    },
    "REVERSE_LOOKUP": {
        "description": "Perform reverse lookup of IPv4 ranges in SPF record",
        "required": False,
        "default": "false"
    },
    "BING": {
        "description": "Perform Bing enumeration",
        "required": False,
        "default": "false"
    },
    "YANDEX": {
        "description": "Perform Yandex enumeration",
        "required": False,
        "default": "false"
    },
    "CRTSH": {
        "description": "Perform crt.sh enumeration",
        "required": False,
        "default": "false"
    },
    "WHOIS": {
        "description": "Perform deep whois analysis",
        "required": False,
        "default": "false"
    },
    "DNSSEC_WALK": {
        "description": "Perform DNSSEC zone walk",
        "required": False,
        "default": "false"
    },
    "FILTER_WILDCARD": {
        "description": "Filter out wildcard IP addresses",
        "required": False,
        "default": "false"
    },
    "IGNORE_WILDCARD": {
        "description": "Continue brute force even if wildcard is discovered",
        "required": False,
        "default": "false"
    },
    "USE_TCP": {
        "description": "Use TCP protocol for queries",
        "required": False,
        "default": "false"
    },
    "VERBOSE": {
        "description": "Enable verbose output",
        "required": False,
        "default": "false"
    },
    "OUTPUT_JSON": {
        "description": "Save results to JSON file",
        "required": False,
        "default": ""
    },
    "OUTPUT_XML": {
        "description": "Save results to XML file",
        "required": False,
        "default": ""
    },
    "OUTPUT_CSV": {
        "description": "Save results to CSV file",
        "required": False,
        "default": ""
    }
}

class DNSReconResult:
    """Class to store and display DNSRecon results"""
    def __init__(self, domain):
        self.domain = domain
        self.start_time = datetime.now()
        self.end_time = None
        self.records = {
            'A': [],
            'AAAA': [],
            'CNAME': [],
            'MX': [],
            'NS': [],
            'SOA': [],
            'TXT': [],
            'SRV': [],
            'PTR': [],
            'SPF': []
        }
        self.subdomains = []
        self.nameservers = []
        self.zone_transfer_success = []
        self.zone_transfer_failed = []
        self.summary = {}
        self.raw_output = []
    
    def add_record(self, record_type, data):
        """Add DNS record to results"""
        if record_type in self.records:
            if data not in self.records[record_type]:
                self.records[record_type].append(data)
    
    def add_subdomain(self, subdomain, ip=None):
        """Add discovered subdomain"""
        entry = {"subdomain": subdomain}
        if ip:
            entry["ip"] = ip
        if entry not in self.subdomains:
            self.subdomains.append(entry)
    
    def add_nameserver(self, ns):
        """Add nameserver"""
        if ns not in self.nameservers:
            self.nameservers.append(ns)
    
    def add_zone_transfer(self, ns, success=True):
        """Record zone transfer result"""
        if success:
            if ns not in self.zone_transfer_success:
                self.zone_transfer_success.append(ns)
        else:
            if ns not in self.zone_transfer_failed:
                self.zone_transfer_failed.append(ns)
    
    def finish(self):
        self.end_time = datetime.now()
        
        # Calculate summary
        total_records = sum(len(v) for v in self.records.values())
        self.summary = {
            "Total Records": total_records,
            "Subdomains Found": len(self.subdomains),
            "Nameservers": len(self.nameservers),
            "Zone Transfers": f"{len(self.zone_transfer_success)}/{len(self.zone_transfer_success) + len(self.zone_transfer_failed)}",
            "Duration": self.get_duration()
        }
    
    def get_duration(self):
        if self.end_time:
            return str(self.end_time - self.start_time).split('.')[0]
        return "In progress"

def check_dnsrecon():
    """Check if dnsrecon is installed"""
    try:
        result = subprocess.run(
            ["dnsrecon", "-V"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return "dnsrecon"
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    
    # Try to find with which
    try:
        result = subprocess.run(["which", "dnsrecon"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    
    return None

def display_banner():
    """Display dynamic banner (tanpa Rich console)"""
    try:
        width = shutil.get_terminal_size().columns
    except (AttributeError, OSError):
        width = 80  # fallback untuk mobile / environment tanpa terminal size
    
    width = min(width, 80)  # batasi agar tetap rapi di layar kecil
    
    title = "DNSRecon"
    subtitle = "Advanced DNS Enumeration Tool"
    
    line = "═" * (width - 2)
    
    # Padding untuk rata tengah
    title_pad = (width - len(title) - 2) // 2
    subtitle_pad = (width - len(subtitle) - 2) // 2
    
    # ANSI Color
    CYAN = "\033[1;36m"
    WHITE = "\033[1;37m"
    RESET = "\033[0m"
    
    print(f"\n{CYAN}╔{line}╗{RESET}")
    print(f"{CYAN}║{RESET}{' ' * title_pad}{WHITE}{title}{RESET}{' ' * (width - len(title) - title_pad - 2)}{CYAN}║{RESET}")
    print(f"{CYAN}║{RESET}{' ' * subtitle_pad}{CYAN}{subtitle}{RESET}{' ' * (width - len(subtitle) - subtitle_pad - 2)}{CYAN}║{RESET}")
    print(f"{CYAN}╚{line}╝{RESET}\n")

def display_type_info():
    """Display available enumeration types"""
    types_table = Table(title="[bold cyan]Available Enumeration Types[/bold cyan]",
                        box=box.HEAVY_EDGE,
                        border_style="cyan")
    types_table.add_column("Type", style="bold green", width=12)
    types_table.add_column("Description", style="white")
    
    types = [
        ("std", "Standard: SOA, NS, A, AAAA, MX, TXT, SRV records"),
        ("rvl", "Reverse lookup of IP range or CIDR"),
        ("brt", "Brute force subdomains using dictionary"),
        ("srv", "Enumerate SRV records"),
        ("axfr", "Test all NS servers for zone transfer"),
        ("bing", "Bing search engine enumeration"),
        ("yand", "Yandex search engine enumeration"),
        ("crt", "crt.sh certificate transparency search"),
        ("snoop", "Cache snooping against NS servers"),
        ("tld", "Test against all TLDs registered in IANA"),
        ("zonewalk", "DNSSEC zone walk using NSEC records")
    ]
    
    for t, desc in types:
        types_table.add_row(t, desc)
    
    console.print(types_table)

def parse_dnsrecon_output_line(line, result):
    """Parse DNSRecon output line and extract records"""
    
    # Patterns for different record types
    patterns = {
        'A': re.compile(r'.*\s+A\s+([0-9.]+)'),
        'AAAA': re.compile(r'.*\s+AAAA\s+([a-fA-F0-9:]+)'),
        'CNAME': re.compile(r'.*\s+CNAME\s+(\S+)'),
        'MX': re.compile(r'.*\s+MX\s+(\S+)\s+(\d+)'),
        'NS': re.compile(r'.*\s+NS\s+(\S+)'),
        'TXT': re.compile(r'.*\s+TXT\s+"([^"]+)"'),
        'SOA': re.compile(r'.*\s+SOA\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)'),
        'SRV': re.compile(r'.*\s+SRV\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)'),
        'PTR': re.compile(r'.*\s+PTR\s+(\S+)'),
        'SPF': re.compile(r'.*\s+SPF\s+"([^"]+)"'),
        'SUBDOMAIN': re.compile(r'.*\s+A\s+(\S+)\s+([0-9.]+)'),
        'ZONE_TRANSFER_SUCCESS': re.compile(r'.*Zone transfer success.*?(\S+)$', re.I),
        'ZONE_TRANSFER_FAILED': re.compile(r'.*Zone transfer failed.*?(\S+)$', re.I),
        'NAMESERVER': re.compile(r'.*NS Server:\s+(\S+)'),
    }
    
    # Skip noise
    if any(x in line for x in ["Starting", "Completed", "Querying", "Using", "Total records"]):
        return
    
    # Parse A records and subdomains
    if patterns['A'].search(line) and not line.startswith('[*]'):
        match = patterns['A'].search(line)
        if match:
            ip = match.group(1)
            # Try to extract subdomain from line
            parts = line.split()
            for part in parts:
                if '.' in part and result.domain in part:
                    result.add_subdomain(part, ip)
            result.add_record('A', ip)
    
    # Parse CNAME
    if patterns['CNAME'].search(line):
        match = patterns['CNAME'].search(line)
        if match:
            result.add_record('CNAME', match.group(1))
    
    # Parse MX
    if patterns['MX'].search(line):
        match = patterns['MX'].search(line)
        if match:
            mx_entry = f"{match.group(2)} {match.group(1)}"
            result.add_record('MX', mx_entry)
    
    # Parse NS
    if patterns['NS'].search(line):
        match = patterns['NS'].search(line)
        if match:
            result.add_nameserver(match.group(1))
            result.add_record('NS', match.group(1))
    
    # Parse TXT
    if patterns['TXT'].search(line):
        match = patterns['TXT'].search(line)
        if match:
            result.add_record('TXT', match.group(1))
    
    # Parse SRV
    if patterns['SRV'].search(line):
        match = patterns['SRV'].search(line)
        if match:
            srv_entry = f"{match.group(1)} {match.group(2)} {match.group(3)} {match.group(4)}"
            result.add_record('SRV', srv_entry)
    
    # Zone transfer results
    if patterns['ZONE_TRANSFER_SUCCESS'].search(line):
        match = patterns['ZONE_TRANSFER_SUCCESS'].search(line)
        if match:
            result.add_zone_transfer(match.group(1), True)
    
    if patterns['ZONE_TRANSFER_FAILED'].search(line):
        match = patterns['ZONE_TRANSFER_FAILED'].search(line)
        if match:
            result.add_zone_transfer(match.group(1), False)

def display_results_table(result):
    """Display DNSRecon results in beautiful table format"""
    
    # Header Panel
    header = Panel(
        f"[bold cyan]DNSRecon Scan Results[/bold cyan]\n"
        f"[dim]Domain: {result.domain} | Duration: {result.get_duration()}[/dim]",
        box=box.HEAVY,
        border_style="cyan"
    )
    console.print(header)
    
    # Statistics Grid
    stats_grid = Table.grid(padding=(0, 3))
    stats_grid.add_column(style="bold white", justify="center")
    stats_grid.add_column(justify="center")
    
    stats_row = f"""
    [bold cyan]📊 Statistics[/bold cyan]
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    🔍 Total Records:  [green]{result.summary['Total Records']}[/green]
    🌐 Subdomains:     [yellow]{result.summary['Subdomains Found']}[/yellow]
    🖥 Nameservers:    [cyan]{result.summary['Nameservers']}[/cyan]
    🔄 Zone Transfers: [magenta]{result.summary['Zone Transfers']}[/magenta]
    ⏱ Time Elapsed:   [dim]{result.summary['Duration']}[/dim]
    """
    
    console.print(Panel(stats_row, border_style="blue"))
    console.print()
    
    # Nameservers Table
    if result.nameservers:
        ns_table = Table(title="[bold cyan]🖥 Nameservers[/bold cyan]",
                         box=box.ROUNDED,
                         border_style="cyan")
        ns_table.add_column("Server", style="green", no_wrap=False)
        
        for ns in result.nameservers:
            # Mark zone transfer success
            if ns in result.zone_transfer_success:
                ns_display = f"[bold green]{ns} ✓ (Zone Transfer)[/bold green]"
            elif ns in result.zone_transfer_failed:
                ns_display = f"[red]{ns} ✗ (Zone Transfer Failed)[/red]"
            else:
                ns_display = f"[white]{ns}[/white]"
            ns_table.add_row(ns_display)
        
        console.print(ns_table)
        console.print()
    
    # A Records Table
    if result.records['A']:
        a_table = Table(title="[bold green]📡 A Records (IPv4)[/bold green]",
                        box=box.ROUNDED,
                        border_style="green")
        a_table.add_column("IP Address", style="green")
        a_table.add_column("Related Subdomains", style="yellow")
        
        for ip in result.records['A'][:20]:
            subdomains = [s['subdomain'] for s in result.subdomains if s.get('ip') == ip]
            sub_list = "\n".join(subdomains[:3])
            if len(subdomains) > 3:
                sub_list += f"\n... and {len(subdomains)-3} more"
            a_table.add_row(ip, sub_list if sub_list else "-")
        
        if len(result.records['A']) > 20:
            a_table.add_row(f"... and {len(result.records['A'])-20} more", "")
        
        console.print(a_table)
        console.print()
    
    # Subdomains Table
    if result.subdomains:
        sub_table = Table(title="[bold yellow]🌐 Discovered Subdomains[/bold yellow]",
                          box=box.ROUNDED,
                          border_style="yellow")
        sub_table.add_column("Subdomain", style="yellow")
        sub_table.add_column("IP Address", style="green")
        
        for sub in result.subdomains[:25]:
            sub_table.add_row(sub['subdomain'], sub.get('ip', '[dim]unknown[/dim]'))
        
        if len(result.subdomains) > 25:
            sub_table.add_row(f"... and {len(result.subdomains)-25} more", "")
        
        console.print(sub_table)
        console.print()
    
    # MX Records
    if result.records['MX']:
        mx_table = Table(title="[bold magenta]📧 MX Records (Mail Exchangers)[/bold magenta]",
                         box=box.ROUNDED,
                         border_style="magenta")
        mx_table.add_column("Priority", style="cyan", width=10)
        mx_table.add_column("Mail Server", style="white")
        
        for mx in result.records['MX']:
            parts = mx.split(' ', 1)
            if len(parts) == 2:
                mx_table.add_row(parts[0], parts[1])
        
        console.print(mx_table)
        console.print()
    
    # TXT Records
    if result.records['TXT']:
        txt_table = Table(title="[bold blue]📝 TXT Records[/bold blue]",
                          box=box.ROUNDED,
                          border_style="blue")
        txt_table.add_column("Content", style="dim", no_wrap=False)
        
        for txt in result.records['TXT'][:10]:
            # Truncate long TXT records
            if len(txt) > 100:
                txt = txt[:100] + "..."
            txt_table.add_row(txt)
        
        if len(result.records['TXT']) > 10:
            txt_table.add_row(f"... and {len(result.records['TXT'])-10} more")
        
        console.print(txt_table)
        console.print()
    
    # SRV Records
    if result.records['SRV']:
        srv_table = Table(title="[bold cyan]🔧 SRV Records[/bold cyan]",
                          box=box.ROUNDED,
                          border_style="cyan")
        srv_table.add_column("Service", style="green")
        srv_table.add_column("Priority", style="yellow")
        srv_table.add_column("Weight", style="yellow")
        srv_table.add_column("Port", style="cyan")
        srv_table.add_column("Target", style="white")
        
        for srv in result.records['SRV'][:15]:
            parts = srv.split()
            if len(parts) == 4:
                srv_table.add_row(parts[0], parts[1], parts[2], parts[3], "")
            elif len(parts) == 5:
                srv_table.add_row(parts[0], parts[1], parts[2], parts[3], parts[4])
        
        console.print(srv_table)
        console.print()
    
    # CNAME Records
    if result.records['CNAME']:
        cname_table = Table(title="[bold yellow]🔄 CNAME Records[/bold yellow]",
                            box=box.ROUNDED,
                            border_style="yellow")
        cname_table.add_column("Alias", style="white")
        
        for cname in result.records['CNAME'][:10]:
            cname_table.add_row(cname)
        
        console.print(cname_table)
        console.print()

def execute_dnsrecon(cmd, options):
    """Execute DNSRecon and parse output"""
    domain = options.get("DOMAIN", "")
    result = DNSReconResult(domain)
    
    console.print("[cyan]Starting DNSRecon scan...[/cyan]")
    console.print()
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        for line in process.stdout:
            line = line.rstrip()
            result.raw_output.append(line)
            
            # Display important findings with colors
            if line.startswith('[+]'):
                console.print(f"[green]{line}[/green]")
            elif any(x in line for x in ['A record', 'CNAME', 'MX', 'NS', 'TXT']):
                console.print(f"[yellow]{line}[/yellow]")
            elif line.startswith('[-]'):
                console.print(f"[red]{line}[/red]")
            elif line.startswith('[*]'):
                console.print(f"[cyan]{line}[/cyan]")
            elif line.strip():
                console.print(f"[dim]{line}[/dim]")
            
            # Parse for structured data
            parse_dnsrecon_output_line(line, result)
        
        process.wait()
        
        if process.returncode != 0:
            console.print(f"[red]DNSRecon exited with code {process.returncode}[/red]")
        
    except subprocess.TimeoutExpired:
        console.print("[red]DNSRecon scan timed out[/red]")
        return None
    except Exception as e:
        console.print(f"[red]Error running dnsrecon: {str(e)}[/red]")
        return None
    
    result.finish()
    return result

def run(session, options):
    """
    Execute DNSRecon scan with beautiful output
    """
    console.clear()
    display_banner()
    
    # Check installation
    dnsrecon_path = check_dnsrecon()
    if not dnsrecon_path:
        error_panel = Panel(
            "[red]DNSRecon is not installed![/red]\n\n"
            "Install it using:\n"
            "  [yellow]• Kali Linux: Already installed[/yellow]\n"
            "  [yellow]• Ubuntu/Debian: sudo apt-get install dnsrecon[/yellow]\n"
            "  [yellow]• pip: pip3 install dnsrecon[/yellow]",
            title="[red]Error[/red]",
            border_style="red"
        )
        console.print(error_panel)
        return "[!] DNSRecon not found"
    
    # Validate required options
    domain = options.get("DOMAIN", "").strip()
    if not domain:
        console.print("[red]Error: DOMAIN option is required![/red]")
        console.print("[yellow]Usage: set DOMAIN <target.com>[/yellow]")
        return "[!] Missing required option: DOMAIN"
    
    # Show enumeration type info
    display_type_info()
    console.print()
    
    # Build command
    cmd = [dnsrecon_path]
    
    # Add domain
    cmd.extend(["-d", domain])
    
    # Enumeration type
    enum_type = options.get("TYPE", "std")
    cmd.extend(["-t", enum_type])
    
    # Options based on enumeration type
    if enum_type == "rvl" and options.get("RANGE"):
        cmd.extend(["-r", options["RANGE"]])
    
    if enum_type == "brt" and options.get("DICTIONARY"):
        cmd.extend(["-D", options["DICTIONARY"]])
    
    # Nameserver
    if options.get("NAME_SERVER"):
        cmd.extend(["-n", options["NAME_SERVER"]])
    
    # Threads
    if options.get("THREADS"):
        cmd.extend(["--threads", options["THREADS"]])
    
    # Lifetime
    if options.get("LIFETIME"):
        cmd.extend(["--lifetime", options["LIFETIME"]])
    
    # Various flags
    if options.get("AXFR", "").lower() == "true":
        cmd.append("-a")
    
    if options.get("REVERSE_LOOKUP", "").lower() == "true":
        cmd.append("-s")
    
    if options.get("BING", "").lower() == "true":
        cmd.append("-b")
    
    if options.get("YANDEX", "").lower() == "true":
        cmd.append("-y")
    
    if options.get("CRTSH", "").lower() == "true":
        cmd.append("-k")
    
    if options.get("WHOIS", "").lower() == "true":
        cmd.append("-w")
    
    if options.get("DNSSEC_WALK", "").lower() == "true":
        cmd.append("-z")
    
    if options.get("FILTER_WILDCARD", "").lower() == "true":
        cmd.append("-f")
    
    if options.get("IGNORE_WILDCARD", "").lower() == "true":
        cmd.append("--iw")
    
    if options.get("USE_TCP", "").lower() == "true":
        cmd.append("--tcp")
    
    if options.get("VERBOSE", "").lower() == "true":
        cmd.append("-v")
    
    # Output files
    if options.get("OUTPUT_JSON"):
        cmd.extend(["-j", options["OUTPUT_JSON"]])
    
    if options.get("OUTPUT_XML"):
        cmd.extend(["-x", options["OUTPUT_XML"]])
    
    if options.get("OUTPUT_CSV"):
        cmd.extend(["-c", options["OUTPUT_CSV"]])
    
    # Display target info
    target_panel = Panel(
        f"[bold green]Target:[/bold green] {domain}\n"
        f"[bold green]Type:[/bold green] {enum_type}\n"
        f"[bold green]Threads:[/bold green] {options.get('THREADS', '10')}",
        title="[bold cyan]Target Information[/bold cyan]",
        border_style="cyan"
    )
    console.print(target_panel)
    console.print()
    
    # Show command if verbose
    if options.get("VERBOSE", "").lower() == "true":
        console.print(Panel(
            f"[dim]{' '.join(cmd)}[/dim]",
            title="[bold]Command[/bold]",
            border_style="dim"
        ))
        console.print()
    
    # Run scan
    result = execute_dnsrecon(cmd, options)
    
    if not result:
        return "[!] Scan failed"
    
    # Display results
    console.print()
    display_results_table(result)
    
    # Save summary
    summary = f"""
DNSRecon Results for {domain}:
- Record Types Found: {', '.join([k for k,v in result.records.items() if v])}
- Total Records: {result.summary['Total Records']}
- Subdomains: {len(result.subdomains)}
- Nameservers: {len(result.nameservers)}
- Zone Transfers: {result.summary['Zone Transfers']}

Top Subdomains:
{chr(10).join(['- ' + s['subdomain'] for s in result.subdomains[:10]])}
"""
    
    return summary
