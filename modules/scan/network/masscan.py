#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Masscan Module for LazyFramework - ULTRA FIXED
High-speed TCP port scanner with robust interface detection
"""

import subprocess
import shutil
import re
import json
import ipaddress
import os
import glob
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None

console = Console()

MODULE_INFO = {
    "name": "Masscan Port Scanner",
    "description": "Masscan - High-speed asynchronous TCP port scanner with robust interface auto-detection",
    "author": "LazyFramework",
    "license": "GPLv3",
    "platform": "Linux/Unix",
    "arch": "all",
    "rank": "Excellent",
    "dependencies": [],
    "references": [
        "https://github.com/robertdavidgraham/masscan",
        "https://tools.kali.org/information-gathering/masscan"
    ]
}

OPTIONS = {
    "RHOSTS": {
        "description": "Target IP range (e.g., 192.168.1.0/24, 10.0.0.1-10.0.0.255)",
        "required": True,
        "default": ""
    },
    "RPORTS": {
        "description": "Ports to scan (e.g., 80,443,8000-9000, 1-65535)",
        "required": True,
        "default": "1-1000"
    },
    "RATE": {
        "description": "Packets per second rate (e.g., 1000, 100000)",
        "required": False,
        "default": "10000"
    },
    "BANNERS": {
        "description": "Grab banners from open ports",
        "required": False,
        "default": "true"
    },
    "INTERFACE": {
        "description": "Network interface to use (auto-detect if empty)",
        "required": False,
        "default": ""
    },
    "SOURCE_PORT": {
        "description": "Source port number",
        "required": False,
        "default": ""
    },
    "SOURCE_IP": {
        "description": "Source IP address (auto-detect if empty)",
        "required": False,
        "default": ""
    },
    "MAX_RETRIES": {
        "description": "Max retransmissions per port",
        "required": False,
        "default": "2"
    },
    "WAIT": {
        "description": "Time to wait for responses (seconds)",
        "required": False,
        "default": "10"
    },
    "OPEN_ONLY": {
        "description": "Only show open ports",
        "required": False,
        "default": "true"
    },
    "EXCLUDE_IPS": {
        "description": "IP ranges to exclude (comma separated)",
        "required": False,
        "default": ""
    },
    "EXCLUDE_PORTS": {
        "description": "Ports to exclude (comma separated)",
        "required": False,
        "default": ""
    },
    "OUTPUT_BINARY": {
        "description": "Save results in binary format (.bin)",
        "required": False,
        "default": ""
    },
    "OUTPUT_XML": {
        "description": "Save results in XML format",
        "required": False,
        "default": ""
    },
    "OUTPUT_JSON": {
        "description": "Save results in JSON format",
        "required": False,
        "default": ""
    },
    "OUTPUT_LIST": {
        "description": "Save results in list format (IP:Port)",
        "required": False,
        "default": ""
    },
    "VERBOSE": {
        "description": "Verbose output",
        "required": False,
        "default": "false"
    }
}

class MasscanResult:
    """Class to store and display Masscan results"""
    def __init__(self, targets):
        self.targets = targets
        self.start_time = datetime.now()
        self.end_time = None
        self.open_ports: List[Dict] = []
        self.hosts: Dict[str, List[int]] = {}
        self.port_stats: Dict[int, int] = {}
        self.banners: Dict[str, Dict] = {}
        self.raw_output = []
        self.scan_speed = 0
        
    def add_open_port(self, ip, port, proto="tcp", banner=None):
        """Add open port to results"""
        entry = {
            "ip": ip,
            "port": port,
            "protocol": proto,
            "banner": banner
        }
        self.open_ports.append(entry)
        
        if ip not in self.hosts:
            self.hosts[ip] = []
        if port not in self.hosts[ip]:
            self.hosts[ip].append(port)
        
        if port not in self.port_stats:
            self.port_stats[port] = 0
        self.port_stats[port] += 1
        
        if banner:
            if ip not in self.banners:
                self.banners[ip] = {}
            self.banners[ip][port] = banner
    
    def finish(self):
        self.end_time = datetime.now()
    
    def get_duration(self):
        if self.end_time:
            return str(self.end_time - self.start_time).split('.')[0]
        return "In progress"
    
    def get_summary(self):
        return {
            "unique_hosts": len(self.hosts),
            "total_ports": len(self.open_ports),
            "unique_ports": len(self.port_stats),
            "duration": self.get_duration(),
            "scan_speed": self.scan_speed
        }

def check_masscan():
    """Check if masscan is installed"""
    try:
        result = subprocess.run(
            ["masscan", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return "masscan"
    except:
        pass
    
    try:
        result = subprocess.run(["which", "masscan"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except:
        pass
    
    return None

def get_all_network_interfaces_robust():
    """
    Get all network interfaces using multiple methods
    Returns list of dict with interface info
    """
    interfaces = []
    
    # Method 1: Using /sys/class/net (most reliable on Linux)
    try:
        net_path = "/sys/class/net"
        if os.path.exists(net_path):
            for iface in os.listdir(net_path):
                if iface == "lo":
                    continue
                
                # Check if interface is up
                operstate_path = f"{net_path}/{iface}/operstate"
                is_up = False
                if os.path.exists(operstate_path):
                    with open(operstate_path, 'r') as f:
                        is_up = "up" in f.read().lower()
                
                # Get IP addresses
                ips = []
                try:
                    # Try to get IP from /sys
                    result = subprocess.run(
                        ["ip", "-4", "addr", "show", iface],
                        capture_output=True,
                        text=True
                    )
                    ip_matches = re.findall(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', result.stdout)
                    ips = ip_matches
                except:
                    pass
                
                interfaces.append({
                    'name': iface,
                    'ips': ips,
                    'is_up': is_up
                })
    except Exception as e:
        console.print(f"[dim]Debug: /sys/class/net error: {e}[/dim]")
    
    # Method 2: Using ip command
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show"],
            capture_output=True,
            text=True
        )
        
        for line in result.stdout.splitlines():
            # Parse interface name
            match = re.match(r'\d+:\s+(\S+):', line)
            if match:
                iface = match.group(1).split('@')[0]
                if iface == "lo":
                    continue
                
                # Check if already in interfaces
                if not any(i['name'] == iface for i in interfaces):
                    is_up = "UP" in line and "LOWER_UP" in line
                    
                    # Get IP addresses
                    ip_result = subprocess.run(
                        ["ip", "-4", "addr", "show", iface],
                        capture_output=True,
                        text=True
                    )
                    ips = re.findall(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', ip_result.stdout)
                    
                    interfaces.append({
                        'name': iface,
                        'ips': ips,
                        'is_up': is_up
                    })
    except Exception as e:
        console.print(f"[dim]Debug: ip command error: {e}[/dim]")
    
    # Method 3: Using ifconfig (fallback)
    if not interfaces:
        try:
            result = subprocess.run(
                ["ifconfig"],
                capture_output=True,
                text=True
            )
            
            current_iface = None
            current_ips = []
            
            for line in result.stdout.splitlines():
                # Interface name line
                iface_match = re.match(r'^(\S+):', line)
                if iface_match:
                    if current_iface and current_iface != "lo":
                        interfaces.append({
                            'name': current_iface,
                            'ips': current_ips,
                            'is_up': True
                        })
                    current_iface = iface_match.group(1)
                    current_ips = []
                    continue
                
                # IP address line
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)\s+', line)
                if ip_match and current_iface:
                    current_ips.append(ip_match.group(1) + "/32")
            
            # Add last interface
            if current_iface and current_iface != "lo":
                interfaces.append({
                    'name': current_iface,
                    'ips': current_ips,
                    'is_up': True
                })
        except Exception as e:
            console.print(f"[dim]Debug: ifconfig error: {e}[/dim]")
    
    return interfaces

def get_default_interface_robust():
    """
    Smart auto-detection of best network interface
    """
    interfaces = get_all_network_interfaces_robust()
    
    if not interfaces:
        return None, None
    
    # Method 1: Find interface with default route
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True
        )
        
        for line in result.stdout.splitlines():
            parts = line.split()
            for i, part in enumerate(parts):
                if part == "dev" and i+1 < len(parts):
                    default_iface = parts[i+1]
                    for iface in interfaces:
                        if iface['name'] == default_iface and iface['is_up'] and iface['ips']:
                            first_ip = iface['ips'][0].split('/')[0]
                            return default_iface, first_ip
    except:
        pass
    
    # Method 2: Find first interface with IP and UP status
    for iface in interfaces:
        if iface['is_up'] and iface['ips']:
            first_ip = iface['ips'][0].split('/')[0]
            return iface['name'], first_ip
    
    return None, None

def display_available_interfaces():
    """Display all available network interfaces in a nice table"""
    interfaces = get_all_network_interfaces_robust()
    
    if not interfaces:
        console.print("[red]No network interfaces found![/red]")
        console.print("[yellow]Check if you have network connectivity or run with sudo[/yellow]")
        return False
    
    table = Table(title="[bold cyan]Available Network Interfaces[/bold cyan]",
                  box=box.HEAVY_EDGE,
                  border_style="cyan",
                  show_header=True,
                  header_style="bold cyan")
    table.add_column("Interface", style="green", width=20)
    table.add_column("Status", style="yellow", width=12)
    table.add_column("IP Address(es)", style="white")
    
    for iface in interfaces:
        status = "[green]UP[/green]" if iface['is_up'] else "[red]DOWN[/red]"
        ips = "\n".join([ip.split('/')[0] for ip in iface['ips']]) if iface['ips'] else "[dim]no IP[/dim]"
        table.add_row(iface['name'], status, ips)
    
    console.print(table)
    console.print()
    return True

def validate_ip_range(ip_range):
    """Validate IP range format"""
    try:
        if '/' in ip_range:
            ipaddress.ip_network(ip_range, strict=False)
            return True
        elif '-' in ip_range:
            parts = ip_range.split('-')
            if len(parts) == 2:
                ipaddress.ip_address(parts[0].strip())
                ipaddress.ip_address(parts[1].strip())
                return True
        else:
            ipaddress.ip_address(ip_range)
            return True
    except:
        return False
    return False

def parse_masscan_output_line(line, result):
    """Parse masscan output line and extract open ports"""
    
    # Pattern for open port
    pattern1 = re.compile(r'Discovered open port (\d+)/(\w+) on (\d+\.\d+\.\d+\.\d+)')
    banner_pattern = re.compile(r'Banner on port (\d+)/(\w+) on (\d+\.\d+\.\d+\.\d+):\s+(.+)$')
    
    match = pattern1.search(line)
    if match:
        port = int(match.group(1))
        proto = match.group(2)
        ip = match.group(3)
        result.add_open_port(ip, port, proto)
        return
    
    match = banner_pattern.search(line)
    if match:
        port = int(match.group(1))
        proto = match.group(2)
        ip = match.group(3)
        banner = match.group(4)
        result.add_open_port(ip, port, proto, banner)
        return
    
    # Extract scan speed
    speed_match = re.search(r'rate:\s*([\d.]+)', line)
    if speed_match:
        result.scan_speed = float(speed_match.group(1))

def display_results_table(result):
    """Display Masscan results in beautiful table format"""
    
    summary = result.get_summary()
    
    # Header Panel
    header = Panel(
        f"[bold cyan]Masscan Scan Results[/bold cyan]\n"
        f"[dim]Targets: {result.targets} | Duration: {summary['duration']}[/dim]",
        box=box.HEAVY,
        border_style="cyan"
    )
    console.print(header)
    
    # Statistics
    stats_panel = Panel(
        f"[bold green]📊 Scan Statistics[/bold green]\n\n"
        f"  🖥  Unique Hosts:   [bold cyan]{summary['unique_hosts']}[/bold cyan]\n"
        f"  🔌 Total Ports:    [bold yellow]{summary['total_ports']}[/bold yellow]\n"
        f"  🎯 Unique Ports:   [bold magenta]{summary['unique_ports']}[/bold magenta]\n"
        f"  ⚡ Scan Speed:     [bold green]{summary['scan_speed']:.0f} pps[/bold green]",
        border_style="blue"
    )
    console.print(stats_panel)
    console.print()
    
    # Hosts Summary
    if result.hosts:
        host_table = Table(title="[bold cyan]🖥 Hosts with Open Ports[/bold cyan]",
                           box=box.ROUNDED,
                           border_style="cyan",
                           show_header=True,
                           header_style="bold cyan")
        host_table.add_column("IP Address", style="green", width=18)
        host_table.add_column("Open Ports", style="yellow", width=12)
        host_table.add_column("Port List", style="white")
        
        for ip in sorted(result.hosts.keys())[:30]:
            ports = sorted(result.hosts[ip])
            ports_str = ",".join(str(p) for p in ports[:15])
            if len(ports) > 15:
                ports_str += f" +{len(ports)-15}"
            host_table.add_row(ip, str(len(ports)), ports_str)
        
        console.print(host_table)
        console.print()
    
    # Top open ports
    if result.port_stats:
        port_table = Table(title="[bold magenta]📊 Top Open Ports[/bold magenta]",
                           box=box.SIMPLE,
                           border_style="magenta",
                           show_header=True,
                           header_style="bold magenta")
        port_table.add_column("Port", style="cyan", width=10)
        port_table.add_column("Count", style="yellow", width=10)
        port_table.add_column("Service", style="white")
        
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
            135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        
        sorted_ports = sorted(result.port_stats.items(), key=lambda x: x[1], reverse=True)[:15]
        for port, count in sorted_ports:
            service = common_services.get(port, "-")
            port_table.add_row(str(port), str(count), service)
        
        console.print(port_table)

def execute_masscan(cmd, options, result):
    """Execute masscan and parse output"""
    
    console.print("[cyan]Starting Masscan scan...[/cyan]")
    console.print("[dim]Press Ctrl+C to stop[/dim]")
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
            
            if "Discovered open port" in line:
                console.print(f"[green]✓ {line}[/green]")
            elif "Banner" in line:
                console.print(f"[cyan]📋 {line}[/cyan]")
            elif "rate:" in line:
                console.print(f"[dim]{line}[/dim]")
            elif "error" in line.lower() or "failed" in line.lower():
                console.print(f"[red]{line}[/red]")
            elif "warning" in line.lower():
                console.print(f"[yellow]{line}[/yellow]")
            else:
                console.print(f"[dim]{line}[/dim]")
            
            parse_masscan_output_line(line, result)
        
        process.wait()
        
        if process.returncode != 0:
            console.print(f"[red]Masscan exited with code {process.returncode}[/red]")
            return False
        
        return True
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        process.terminate()
        return False
    except Exception as e:
        console.print(f"[red]Error running masscan: {str(e)}[/red]")
        return False

def run(session, options):
    """
    Execute Masscan scan with robust interface detection
    """
    console.clear()
    
    # Banner
    try:
        width = shutil.get_terminal_size().columns
    except (AttributeError, OSError):
        width = 80
    width = min(width, 85)  # Agar tetap rapi di mobile/Termux
    
    title = "M A S S C A N"
    subtitle = "High-Speed Port Scanner"
    
    line = "═" * (width - 2)
    title_pad = (width - len(title) - 2) // 2
    subtitle_pad = (width - len(subtitle) - 2) // 2
    
    console.print(f"\n[bold cyan]╔{line}╗[/bold cyan]")
    console.print(f"[bold cyan]║[/bold cyan]{' ' * title_pad}[bold white]{title}[/bold white]{' ' * (width - len(title) - title_pad - 2)}[bold cyan]║[/bold cyan]")
    console.print(f"[bold cyan]║[/bold cyan]{' ' * subtitle_pad}[bold cyan]{subtitle}[/bold cyan]{' ' * (width - len(subtitle) - subtitle_pad - 2)}[bold cyan]║[/bold cyan]")
    console.print(f"[bold cyan]╚{line}╝[/bold cyan]\n")   
    
    # Check masscan installation
    masscan_path = check_masscan()
    if not masscan_path:
        error_panel = Panel(
            "[red]Masscan is not installed![/red]\n\n"
            "Install it using:\n"
            "  [yellow]• Ubuntu/Debian: sudo apt-get install masscan[/yellow]\n"
            "  [yellow]• Kali Linux: sudo apt-get install masscan[/yellow]",
            title="[red]Error[/red]",
            border_style="red"
        )
        console.print(error_panel)
        return "[!] Masscan not found"
    
    # Validate required options
    targets = options.get("RHOSTS", "").strip()
    if not targets:
        console.print("[red]Error: RHOSTS option is required![/red]")
        console.print("[yellow]Example: set RHOSTS 192.168.1.0/24[/yellow]")
        return "[!] Missing required option: RHOSTS"
    
    # Validate IP range
    ranges = targets.split(',')
    for r in ranges:
        if not validate_ip_range(r.strip()):
            console.print(f"[red]Invalid IP range: {r}[/red]")
            return "[!] Invalid IP range"
    
    ports = options.get("RPORTS", "1-1000").strip()
    if not ports:
        console.print("[red]Error: RPORTS option is required![/red]")
        console.print("[yellow]Example: set RPORTS 80,443,22[/yellow]")
        return "[!] Missing required option: RPORTS"
    
    # Display interfaces
    console.print("[bold cyan]🔍 Scanning for network interfaces...[/bold cyan]")
    has_interfaces = display_available_interfaces()
    
    if not has_interfaces:
        console.print("[red]No interfaces found! Make sure you have network connectivity.[/red]")
        return "[!] No network interfaces"
    
    # Interface detection
    interface = options.get("INTERFACE", "").strip()
    source_ip = options.get("SOURCE_IP", "").strip()
    
    if not interface:
        # Auto-detect best interface
        detected_iface, detected_ip = get_default_interface_robust()
        
        if detected_iface:
            console.print(f"[green]✓ Auto-detected interface: {detected_iface}[/green]")
            console.print(f"[green]✓ Auto-detected source IP: {detected_ip}[/green]")
            interface = detected_iface
            if not source_ip:
                source_ip = detected_ip
        else:
            console.print("[red]✗ Could not auto-detect interface[/red]")
            console.print("[yellow]Please manually set INTERFACE from the list above:[/yellow]")
            console.print("  [cyan]set INTERFACE <interface_name>[/cyan]")
            console.print()
            return "[!] No network interface specified"
    else:
        # Verify user-specified interface exists
        interfaces = get_all_network_interfaces_robust()
        iface_names = [iface['name'] for iface in interfaces]
        if interface not in iface_names:
            console.print(f"[red]Error: Interface '{interface}' not found![/red]")
            console.print("[yellow]Available interfaces:[/yellow]")
            for name in iface_names:
                console.print(f"  [cyan]{name}[/cyan]")
            return "[!] Invalid interface"
    
    # Build command
    cmd = [masscan_path]
    cmd.extend(["-p", ports])
    cmd.extend([targets])
    cmd.extend(["--rate", options.get("RATE", "10000")])
    
    # Interface and source IP (required for masscan)
    cmd.extend(["-e", interface])
    if source_ip:
        cmd.extend(["--source-ip", source_ip])
    else:
        # Try to get source IP from interface if not specified
        interfaces = get_all_network_interfaces_robust()
        for iface in interfaces:
            if iface['name'] == interface and iface['ips']:
                source_ip = iface['ips'][0].split('/')[0]
                cmd.extend(["--source-ip", source_ip])
                break
    
    # Other options
    if options.get("BANNERS", "true").lower() == "true":
        cmd.append("--banners")
    
    if options.get("SOURCE_PORT"):
        cmd.extend(["--source-port", options["SOURCE_PORT"]])
    
    if options.get("MAX_RETRIES"):
        cmd.extend(["--retries", options["MAX_RETRIES"]])
    
    if options.get("WAIT"):
        cmd.extend(["--wait", options["WAIT"]])
    
    if options.get("OPEN_ONLY", "true").lower() == "true":
        cmd.append("--open")
    
    if options.get("EXCLUDE_IPS"):
        for exclude in options["EXCLUDE_IPS"].split(','):
            cmd.extend(["--exclude", exclude.strip()])
    
    if options.get("EXCLUDE_PORTS"):
        cmd.extend(["--exclude-port", options["EXCLUDE_PORTS"]])
    
    # Output
    if options.get("OUTPUT_BINARY"):
        cmd.extend(["-oB", options["OUTPUT_BINARY"]])
    if options.get("OUTPUT_XML"):
        cmd.extend(["-oX", options["OUTPUT_XML"]])
    if options.get("OUTPUT_JSON"):
        cmd.extend(["-oJ", options["OUTPUT_JSON"]])
    if options.get("OUTPUT_LIST"):
        cmd.extend(["-oL", options["OUTPUT_LIST"]])
    
    if options.get("VERBOSE", "false").lower() == "true":
        cmd.append("-v")
    
    # Display config
    config_panel = Panel(
        f"[bold green]Target:[/bold green] {targets}\n"
        f"[bold green]Ports:[/bold green] {ports}\n"
        f"[bold green]Rate:[/bold green] {options.get('RATE', '10000')} pps\n"
        f"[bold green]Interface:[/bold green] {interface}\n"
        f"[bold green]Source IP:[/bold green] {source_ip if source_ip else 'auto'}\n"
        f"[bold green]Banners:[/bold green] {options.get('BANNERS', 'true')}",
        title="[bold cyan]🎯 Scan Configuration[/bold cyan]",
        border_style="cyan"
    )
    console.print(config_panel)
    console.print()
    
    # Root warning
    console.print("[yellow]⚠️  Masscan requires root privileges for raw packets[/yellow]")
    console.print("[dim]If you see errors, run with: sudo lzfconsole[/dim]")
    console.print()
    
    if options.get("VERBOSE", "false").lower() == "true":
        console.print(Panel(f"[dim]{' '.join(cmd)}[/dim]", title="Command", border_style="dim"))
        console.print()
    
    # Confirm before scanning
    console.print("[bold yellow]Ready to scan? (y/N)[/bold yellow] ", end="")
    confirm = input().lower()
    if confirm != 'y':
        console.print("[dim]Scan cancelled[/dim]")
        return "[!] Scan cancelled by user"
    
    console.print()
    
    # Run scan
    result = MasscanResult(targets)
    success = execute_masscan(cmd, options, result)
    result.finish()
    
    if not success:
        return "[!] Scan failed"
    
    console.print()
    
    if not result.open_ports:
        console.print("[yellow]⚠️  No open ports discovered[/yellow]")
        return "[!] No open ports found"
    
    display_results_table(result)
    
    # Save to session
    if "scans" not in session:
        session["scans"] = []
    session["scans"].append({
        "type": "masscan",
        "targets": targets,
        "timestamp": result.start_time.isoformat(),
        "open_ports": len(result.open_ports),
        "hosts": len(result.hosts)
    })
    
    # Save results if output specified
    if options.get("OUTPUT_LIST"):
        with open(options["OUTPUT_LIST"], 'w') as f:
            for entry in result.open_ports:
                f.write(f"{entry['ip']}:{entry['port']}\n")
        console.print(f"[green]✓ Results saved to {options['OUTPUT_LIST']}[/green]")
    
    return f"✓ Scan completed: {len(result.hosts)} hosts, {len(result.open_ports)} open ports"
