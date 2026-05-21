#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Nikto Web Scanner Module for LazyFramework
Web server vulnerability scanner with Rich table output
"""

import subprocess
import re
import shutil
import os
import json
from pathlib import Path
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.syntax import Syntax
    from rich import box
    from rich.text import Text
    from rich.columns import Columns
    from rich.layout import Layout
    from rich.live import Live
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    console = Console()

console = Console()

MODULE_INFO = {
    "name": "Nikto Web Scanner",
    "description": "Nikto web server scanner",
    "author": "LazyFramework",
    "license": "GPLv3",
    "platform": "Linux/Unix",
    "arch": "all",
    "rank": "Excellent",
    "dependencies": [],
    "references": [
        "https://github.com/sullo/nikto",
        "https://cirt.net/Nikto2"
    ]
}

OPTIONS = {
    "RHOSTS": {
        "description": "Target host/URL (required)",
        "required": True,
        "default": ""
    },
    "RPORT": {
        "description": "Target port (default: 80)",
        "required": False,
        "default": "80"
    },
    "SSL": {
        "description": "Force SSL mode",
        "required": False,
        "default": "false"
    },
    "TUNING": {
        "description": "Scan tuning (1-9,a,b,c,d,e,x)",
        "required": False,
        "default": ""
    },
    "MUTATE": {
        "description": "Mutate technique (1,2,3,4,6)",
        "required": False,
        "default": ""
    },
    "ROOT": {
        "description": "Prepend root value to all requests",
        "required": False,
        "default": ""
    },
    "CGIDIRS": {
        "description": "Scan CGI dirs: 'none', 'all', or custom",
        "required": False,
        "default": "all"
    },
    "FORMAT": {
        "description": "Output format: txt, csv, json, htm, xml",
        "required": False,
        "default": "txt"
    },
    "OUTPUT": {
        "description": "Output file (empty = print to console)",
        "required": False,
        "default": ""
    },
    "TIMEOUT": {
        "description": "Timeout per request (seconds)",
        "required": False,
        "default": "10"
    },
    "MAXTIME": {
        "description": "Maximum testing time (e.g., '60m')",
        "required": False,
        "default": ""
    },
    "DISPLAY": {
        "description": "Display options: 1=redirects,2=cookies,3=200s,4=auth",
        "required": False,
        "default": ""
    },
    "EVASION": {
        "description": "Evasion technique (1-8,A,B)",
        "required": False,
        "default": ""
    },
    "FOLLOWREDIRECTS": {
        "description": "Follow 3xx redirects",
        "required": False,
        "default": "false"
    },
    "NOCOOKIES": {
        "description": "Don't use/send cookies",
        "required": False,
        "default": "false"
    },
    "NOLOOKUP": {
        "description": "Disable DNS lookups",
        "required": False,
        "default": "false"
    },
    "PLUGINS": {
        "description": "Plugins to run (default: ALL)",
        "required": False,
        "default": "ALL"
    },
    "USERAGENT": {
        "description": "Custom User-Agent string",
        "required": False,
        "default": ""
    },
    "VHOST": {
        "description": "Virtual host for Host header",
        "required": False,
        "default": ""
    },
    "AUTH": {
        "description": "HTTP auth (format: user:pass)",
        "required": False,
        "default": ""
    },
    "PROXY": {
        "description": "Proxy URL (e.g., http://proxy:8080)",
        "required": False,
        "default": ""
    },
    "VERBOSE": {
        "description": "Verbose output",
        "required": False,
        "default": "false"
    }
}

class NiktoResult:
    """Class to store and display Nikto results"""
    def __init__(self, target):
        self.target = target
        self.start_time = datetime.now()
        self.end_time = None
        self.vulnerabilities = []
        self.interesting_files = []
        self.cgi_dirs = []
        self.osvdb_refs = set()
        self.web_server = None
        self.ssl_info = None
        self.raw_output = []
        self.summary = {}
    
    def add_vulnerability(self, vuln):
        self.vulnerabilities.append(vuln)
    
    def add_interesting_file(self, file):
        self.interesting_files.append(file)
    
    def add_cgi_dir(self, cgi):
        self.cgi_dirs.append(cgi)
    
    def add_osvdb(self, osvdb):
        self.osvdb_refs.add(osvdb)
    
    def finish(self):
        self.end_time = datetime.now()
    
    def get_duration(self):
        if self.end_time:
            return str(self.end_time - self.start_time).split('.')[0]
        return "In progress"

def check_nikto():
    """Check if nikto is installed and return path"""
    nikto_paths = [
        "nikto",
        "/usr/bin/nikto",
        "/usr/local/bin/nikto",
        "/opt/nikto/nikto.pl",
        "/usr/share/nikto/program/nikto.pl"
    ]
    
    for path in nikto_paths:
        try:
            result = subprocess.run(
                [path, "-Version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 or "Nikto" in result.stdout or "Nikto" in result.stderr:
                return path
        except (subprocess.SubprocessError, FileNotFoundError):
            continue
    
    try:
        result = subprocess.run(["which", "nikto"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    
    return None

def display_banner():
    """Dynamic banner yang otomatis menyesuaikan lebar layar"""
    try:
        width = shutil.get_terminal_size().columns
    except (AttributeError, OSError):
        width = 80  # fallback untuk mobile/termux
    
    width = min(width, 85)  # batasi agar tetap rapi
    
    title = "N I K T O"
    subtitle = "Web Server Scanner"
    
    line = "═" * (width - 2)
    title_pad = (width - len(title) - 2) // 2
    subtitle_pad = (width - len(subtitle) - 2) // 2
    
    console.print(f"\n[bold cyan]╔{line}╗[/bold cyan]")
    console.print(f"[bold cyan]║[/bold cyan]{' ' * title_pad}[bold white]{title}[/bold white]{' ' * (width - len(title) - title_pad - 2)}[bold cyan]║[/bold cyan]")
    console.print(f"[bold cyan]║[/bold cyan]{' ' * subtitle_pad}[bold cyan]{subtitle}[/bold cyan]{' ' * (width - len(subtitle) - subtitle_pad - 2)}[bold cyan]║[/bold cyan]")
    console.print(f"[bold cyan]╚{line}╝[/bold cyan]\n")

def show_options_table(options):
    """Display current options in a nice table"""
    table = Table(title="[bold yellow]Module Options[/bold yellow]", 
                  box=box.HEAVY_EDGE,
                  border_style="cyan")
    table.add_column("Name", style="bold green", width=20)
    table.add_column("Current Setting", style="white", width=30)
    table.add_column("Required", style="yellow", width=10)
    table.add_column("Description", style="dim", width=40)
    
    for name, opt in options.items():
        current = str(opt.get('value', opt.get('default', '')))
        if not current:
            current = "[dim]Not set[/dim]"
        required = "[red]yes[/red]" if opt.get('required') else "[green]no[/green]"
        table.add_row(name, current, required, opt['description'])
    
    console.print(table)

def show_target_info(target, port, ssl, vhost=None):
    """Display target information"""
    protocol = "https" if ssl else "http"
    url = f"{protocol}://{target}"
    if str(port) not in ["80", "443"]:
        url += f":{port}"
    if vhost:
        url += f" (vhost: {vhost})"
    
    info_table = Table(title="[bold cyan]Target Information[/bold cyan]",
                       box=box.SIMPLE,
                       border_style="blue")
    info_table.add_column("Property", style="bold white")
    info_table.add_column("Value", style="green")
    info_table.add_row("Target", url)
    info_table.add_row("Port", str(port))
    info_table.add_row("SSL", "Enabled" if ssl else "Disabled")
    if vhost:
        info_table.add_row("Virtual Host", vhost)
    
    console.print(info_table)

def parse_nikto_output_line(line, result):
    """Parse a single line of nikto output"""
    # Vulnerability pattern
    vuln_pattern = re.compile(r'^\+\s+(.+?)(?::\s+(.+?))?$')
    # Interesting file pattern
    file_pattern = re.compile(r'^\+\s+(?:Entry|File|Directory)\s+[\'"]?([^\'"]+)[\'"]?\s+(?:found|exists)')
    # CGI directories
    cgi_pattern = re.compile(r'^\+\s+CGI\s+Directories?:\s+(.+)$')
    # Web server info
    server_pattern = re.compile(r'^\+\s+(?:The\s+)?(?:web\s+)?server\s+(?:is\s+)?(?:running|seems to be|appears to be)\s+.*?:\s+(.+?)(?:\s+-\s+|$)')
    # OSVDB references
    osvdb_pattern = re.compile(r'OSVDB-(\d+)')
    
    # Skip noise lines
    if any(x in line for x in ["Scanning", "Starting", "Completed", "Scan进度", "Scan terminated"]):
        return
    
    if file_pattern.search(line):
        match = file_pattern.search(line)
        if match:
            result.add_interesting_file(match.group(1))
        return
    
    if cgi_pattern.search(line):
        match = cgi_pattern.search(line)
        if match:
            result.cgi_dirs.append(match.group(1))
        return
    
    if server_pattern.search(line):
        match = server_pattern.search(line)
        if match:
            result.web_server = match.group(1)
        return
    
    # Check for vulnerabilities
    if vuln_pattern.match(line) and not any(x in line for x in ["Target IP", "Target Hostname", "Port"]):
        vuln = line[2:].strip()
        if vuln and len(vuln) > 5:
            result.add_vulnerability(vuln)
    
    # Extract OSVDB references
    osvdb_matches = osvdb_pattern.findall(line)
    for osvdb in osvdb_matches:
        result.add_osvdb(osvdb)

def display_results_table(result):
    """Display scan results in a beautiful table format"""
    
    # Header Panel
    header = Panel(
        f"[bold cyan]Nikto Scan Results[/bold cyan]\n"
        f"[dim]Target: {result.target} | Duration: {result.get_duration()}[/dim]",
        box=box.HEAVY,
        border_style="cyan"
    )
    console.print(header)
    
    # Statistics Grid
    stats_grid = Table.grid(padding=(0, 2))
    stats_grid.add_column(style="bold white", justify="center")
    stats_grid.add_column(justify="center")
    
    stats_data = [
        ("🔍 Vulnerabilities", f"[red]{len(result.vulnerabilities)}[/red]"),
        ("📁 Interesting Files", f"[yellow]{len(result.interesting_files)}[/yellow]"),
        ("📂 CGI Directories", f"[green]{len(result.cgi_dirs)}[/green]"),
        ("📚 OSVDB References", f"[cyan]{len(result.osvdb_refs)}[/cyan]"),
    ]
    
    stats_row = "  ".join([f"{label}: {value}" for label, value in stats_data])
    console.print(Panel(stats_row, title="[bold]Statistics[/bold]", border_style="blue"))
    console.print()
    
    # Vulnerabilities Table
    if result.vulnerabilities:
        vuln_table = Table(title="[bold red]⚠ Vulnerabilities Found[/bold red]",
                          box=box.ROUNDED,
                          border_style="red",
                          show_header=True,
                          header_style="bold red")
        vuln_table.add_column("#", style="dim", width=4)
        vuln_table.add_column("Finding", style="white", no_wrap=False)
        
        for idx, vuln in enumerate(result.vulnerabilities[:20], 1):
            # Color code based on severity keywords
            vuln_text = vuln
            if any(x in vuln.lower() for x in ["exploit", "remote", "rce", "shell", "command"]):
                vuln_text = f"[bold red]{vuln}[/bold red]"
            elif any(x in vuln.lower() for x in ["xss", "injection", "sql"]):
                vuln_text = f"[yellow]{vuln}[/yellow]"
            elif any(x in vuln.lower() for x in ["info", "disclosure", "version"]):
                vuln_text = f"[dim]{vuln}[/dim]"
            else:
                vuln_text = f"[white]{vuln}[/white]"
            
            vuln_table.add_row(str(idx), vuln_text)
        
        if len(result.vulnerabilities) > 20:
            vuln_table.add_row("...", f"[dim]and {len(result.vulnerabilities)-20} more findings[/dim]")
        
        console.print(vuln_table)
        console.print()
    
    # Interesting Files Table
    if result.interesting_files:
        files_table = Table(title="[bold yellow]📁 Interesting Files/Directories[/bold yellow]",
                           box=box.ROUNDED,
                           border_style="yellow")
        files_table.add_column("Path", style="green", no_wrap=False)
        
        for file in result.interesting_files[:15]:
            files_table.add_row(file)
        
        if len(result.interesting_files) > 15:
            files_table.add_row(f"... and {len(result.interesting_files)-15} more")
        
        console.print(files_table)
        console.print()
    
    # CGI Directories
    if result.cgi_dirs:
        cgi_table = Table(title="[bold green]📂 CGI Directories Found[/bold green]",
                         box=box.ROUNDED,
                         border_style="green")
        cgi_table.add_column("Directory", style="cyan")
        for cgi in result.cgi_dirs:
            cgi_table.add_row(cgi)
        console.print(cgi_table)
        console.print()
    
    # OSVDB References
    if result.osvdb_refs:
        osvdb_text = ", ".join(sorted(result.osvdb_refs)[:10])
        if len(result.osvdb_refs) > 10:
            osvdb_text += f" and {len(result.osvdb_refs)-10} more"
        
        osvdb_panel = Panel(
            f"[cyan]OSVDB References:[/cyan] {osvdb_text}",
            title="[bold]📚 References[/bold]",
            border_style="magenta"
        )
        console.print(osvdb_panel)
        console.print()
    
    # Web Server Info
    if result.web_server:
        server_panel = Panel(
            f"[green]Web Server:[/green] {result.web_server}",
            title="[bold]🖥 Server Information[/bold]",
            border_style="blue"
        )
        console.print(server_panel)

def execute_nikto(cmd, options):
    """Execute nikto and handle output with Rich formatting"""
    result = NiktoResult(options.get("RHOSTS"))
    
    # Show progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False
    ) as progress:
        task = progress.add_task("[cyan]Running Nikto scan...", total=None)
        
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
                
                # Display important findings in real-time
                if line.startswith("+ "):
                    if any(x in line.lower() for x in ["cve", "osvdb", "vulnerab", "exploit", "inject"]):
                        console.print(f"[red]{line}[/red]")
                    elif any(x in line.lower() for x in ["info", "disclos", "version"]):
                        console.print(f"[yellow]{line}[/yellow]")
                    elif any(x in line.lower() for x in ["cgi", "directory", "file"]):
                        console.print(f"[green]{line}[/green]")
                    else:
                        console.print(f"[dim]{line}[/dim]")
                elif line.startswith("- "):
                    console.print(f"[blue]{line}[/blue]")
                elif line.strip():
                    console.print(f"[white]{line}[/white]")
                
                # Parse for structured data
                parse_nikto_output_line(line, result)
            
            process.wait()
            
            if process.returncode != 0 and process.returncode != 1:
                progress.update(task, description="[red]Scan completed with errors")
            else:
                progress.update(task, description="[green]Scan completed")
        
        except subprocess.TimeoutExpired:
            console.print("[red]Nikto scan timed out[/red]")
            return None
        except Exception as e:
            console.print(f"[red]Error running nikto: {str(e)}[/red]")
            return None
    
    result.finish()
    return result

def run(session, options):
    """
    Execute Nikto scan with beautiful output
    """
    console.clear()
    display_banner()
    
    # Check nikto installation
    nikto_path = check_nikto()
    if not nikto_path:
        error_panel = Panel(
            "[red]Nikto is not installed![/red]\n\n"
            "Install it using:\n"
            "  [yellow]• Ubuntu/Debian: sudo apt-get install nikto[/yellow]\n"
            "  [yellow]• Kali Linux: Already installed[/yellow]\n"
            "  [yellow]• macOS: brew install nikto[/yellow]",
            title="[red]Error[/red]",
            border_style="red"
        )
        console.print(error_panel)
        return "[!] Nikto not found"
    
    # Validate required options
    target = options.get("RHOSTS", "").strip()
    if not target:
        console.print("[red]Error: RHOSTS option is required![/red]")
        console.print("[yellow]Usage: set RHOSTS <target>[/yellow]")
        return "[!] Missing required option: RHOSTS"
    
    # Build command
    cmd = [nikto_path]
    
    # Target
    cmd.extend(["-host", target])
    
    # Port
    port = options.get("RPORT", "80")
    ssl = options.get("SSL", "").lower() == "true"
    if port != "80" or ssl:
        cmd.extend(["-port", port])
    
    # Show target info
    vhost = options.get("VHOST", "")
    show_target_info(target, port, ssl, vhost if vhost else None)
    console.print()
    
    # SSL
    if ssl:
        cmd.append("-ssl")
    
    # Tuning
    if options.get("TUNING"):
        cmd.extend(["-Tuning", options["TUNING"]])
    
    # Mutate
    if options.get("MUTATE"):
        cmd.extend(["-mutate", options["MUTATE"]])
    
    # Root directory
    if options.get("ROOT"):
        cmd.extend(["-root", options["ROOT"]])
    
    # CGI dirs
    cgidirs = options.get("CGIDIRS", "all")
    if cgidirs != "all":
        cmd.extend(["-Cgidirs", cgidirs])
    
    # Output file
    if options.get("OUTPUT"):
        output_file = options["OUTPUT"]
        fmt = options.get("FORMAT", "txt")
        if fmt != "txt":
            cmd.extend(["-Format", fmt])
        cmd.extend(["-output", output_file])
    
    # Timeout
    if options.get("TIMEOUT"):
        cmd.extend(["-timeout", options["TIMEOUT"]])
    
    # Max time
    if options.get("MAXTIME"):
        cmd.extend(["-maxtime", options["MAXTIME"]])
    
    # Display options
    if options.get("DISPLAY"):
        cmd.extend(["-Display", options["DISPLAY"]])
    
    # Evasion
    if options.get("EVASION"):
        cmd.extend(["-evasion", options["EVASION"]])
    
    # Follow redirects
    if options.get("FOLLOWREDIRECTS", "").lower() == "true":
        cmd.append("-followredirects")
    
    # No cookies
    if options.get("NOCOOKIES", "").lower() == "true":
        cmd.append("-nocookies")
    
    # No lookup
    if options.get("NOLOOKUP", "").lower() == "true":
        cmd.append("-nolookup")
    
    # Plugins
    if options.get("PLUGINS") and options["PLUGINS"] != "ALL":
        cmd.extend(["-Plugins", options["PLUGINS"]])
    
    # User agent
    if options.get("USERAGENT"):
        cmd.extend(["-useragent", options["USERAGENT"]])
    
    # Authentication
    if options.get("AUTH"):
        cmd.extend(["-id", options["AUTH"]])
    
    # Proxy
    if options.get("PROXY"):
        cmd.extend(["-useproxy", options["PROXY"]])
    
    # Non-interactive
    cmd.append("-nointeractive")
    cmd.append("-nocheck")
    
    # Verbose
    if options.get("VERBOSE", "").lower() == "true":
        cmd.append("-Format")
        cmd.append("csv")
    
    # Show command if verbose
    if options.get("VERBOSE", "").lower() == "true":
        console.print(Panel(
            f"[dim]{' '.join(cmd)}[/dim]",
            title="[bold]Command[/bold]",
            border_style="dim"
        ))
        console.print()
    
    # Run scan
    result = execute_nikto(cmd, options)
    
    if not result:
        return "[!] Scan failed"
    
    # Display results
    console.print()
    display_results_table(result)
    
    # Save raw output if requested
    if options.get("OUTPUT"):
        console.print(f"\n[green]✓ Results saved to: {options['OUTPUT']}[/green]")
    
    # Return summary for AI context
    summary = f"""
Nikto Scan Results for {target}:
- Vulnerabilities found: {len(result.vulnerabilities)}
- Interesting files: {len(result.interesting_files)}
- CGI directories: {len(result.cgi_dirs)}
- OSVDB references: {len(result.osvdb_refs)}

Top vulnerabilities:
{chr(10).join(['- ' + v[:100] for v in result.vulnerabilities[:5]])}
"""
    
    return summary
