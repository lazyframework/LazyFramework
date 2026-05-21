#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import re
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

MODULE_INFO = {
    "name": "SMB Auto Enumeration",
    "description": "SMB Enumeration with automatic domain & user discovery",
    "author": "Lazy Framework",
    "rank": "Excellent",
    "platform": "multi",
    "arch": "multi",
    "dependencies": ["impacket", "smbmap"]
}

OPTIONS = {
    "RHOST": {
        "default": "",
        "required": True,
        "description": "Target IP or hostname"
    },
    "RPORT": {
        "default": 445,
        "required": False,
        "description": "SMB port"
    },
    "USERNAME": {
        "default": "",
        "required": False,
        "description": "SMB username (leave blank for anonymous)"
    },
    "PASSWORD": {
        "default": "",
        "required": False,
        "description": "SMB password (leave blank for anonymous)"
    },
    "DOMAIN": {
        "default": "",
        "required": False,
        "description": "Domain/workgroup override (auto-detected if blank)"
    },
    "RID_RANGE": {
        "default": "500-2000",
        "required": False,
        "description": "RID range for user enumeration"
    },
    "AUTO_MODE": {
        "default": "full",
        "required": False,
        "description": "quick | full"
    }
}

def escape_rich_markup(text):
    """Escape square brackets for Rich rendering"""
    if not isinstance(text, str):
        text = str(text)
    return text.replace('[', '\\[').replace(']', '\\]')

def run(session, options):
    rhost    = str(options.get("RHOST", "")).strip()
    rport    = str(options.get("RPORT", 445))
    username = str(options.get("USERNAME", "")).strip()
    password = str(options.get("PASSWORD", "")).strip()
    domain   = str(options.get("DOMAIN", "")).strip()
    rid_range = options.get("RID_RANGE", "500-2000")
    mode     = options.get("AUTO_MODE", "full").lower()

    if not rhost:
        console.print("[bold red][!] RHOST is required[/bold red]")
        return False

    # ── Auth mode detection ────────────────────────────────────────────────────
    use_auth = bool(username)

    if use_auth:
        console.print(f"[bold green][*] Starting SMB Enumeration on {rhost}:{rport} "
                      f"as '{username}'[/bold green]")
    else:
        console.print(f"[bold green][*] Starting SMB Enumeration on {rhost}:{rport} "
                      f"(anonymous)[/bold green]")

    discovered_domain = domain if domain else "WORKGROUP"
    discovered_users  = []

    # ── Helper: build auth args per tool ──────────────────────────────────────
    def smbclient_auth():
        """Returns list of extra args for smbclient."""
        if use_auth:
            return ["-U", f"{username}%{password}"]
        return ["-N"]

    def smbmap_auth():
        """Returns list of extra args for smbmap."""
        if use_auth:
            args = ["-u", username, "-p", password]
            if discovered_domain and discovered_domain != "WORKGROUP":
                args += ["-d", discovered_domain]
            return args
        return ["-u", "", "-p", ""]   # anonymous

    def impacket_target():
        """Returns 'domain/user:pass@host' string for impacket tools."""
        dom = discovered_domain if discovered_domain else "WORKGROUP"
        if use_auth:
            return f"{dom}/{username}:{password}@{rhost}"
        return f"{dom}/anonymous@{rhost}"

    # ── 1. Domain Discovery ───────────────────────────────────────────────────
    if not domain:
        console.print("\n[yellow][+] Trying to discover Domain Name...[/yellow]")
        try:
            cmd = ["smbclient", "-L", rhost, "-p", rport, "-g"] + smbclient_auth()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr

            domain_patterns = [
                r'Workgroup\s*=\s*(\S+)',
                r'Domain\s*=\s*(\S+)',
                r'(?:Domain|Workgroup):\s*(\S+)',
                r'Server\s+((?!\d+\.\d+\.\d+\.\d+)\S+)'
            ]

            for pattern in domain_patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    discovered_domain = match.group(1).strip()
                    console.print(f"[green][✓] Domain/Workgroup detected: {discovered_domain}[/green]")
                    break
            else:
                try:
                    ncmd = ["nmblookup", "-A", rhost]
                    nresult = subprocess.run(ncmd, capture_output=True, text=True, timeout=5)
                    nmatch = re.search(r'<00>.*?<GROUP>.*?(\S+)', nresult.stdout)
                    if nmatch:
                        discovered_domain = nmatch.group(1)
                        console.print(f"[green][✓] Domain via NetBIOS: {discovered_domain}[/green]")
                    else:
                        console.print("[yellow][!] Could not detect domain, using WORKGROUP[/yellow]")
                except Exception:
                    console.print("[yellow][!] Could not detect domain, using WORKGROUP[/yellow]")

        except subprocess.TimeoutExpired:
            console.print("[yellow][!] smbclient timed out during domain discovery[/yellow]")
        except FileNotFoundError:
            console.print("[yellow][!] smbclient not available[/yellow]")
        except Exception as e:
            console.print(f"[yellow][!] Domain discovery error: {escape_rich_markup(str(e))}[/yellow]")
    else:
        console.print(f"\n[green][✓] Using provided domain: {discovered_domain}[/green]")

    # ── 2. RID Cycling ────────────────────────────────────────────────────────
    if mode == "full":
        console.print(f"\n[yellow][+] RID Cycling ({rid_range})...[/yellow]")

        rid_methods = [
            {
                'name': 'impacket-lookupsid',
                'cmd': ['impacket-lookupsid', impacket_target(), rid_range]
            },
            {
                'name': 'impacket-samrdump',
                'cmd': ['impacket-samrdump', impacket_target()]
            },
            {
                'name': 'enum4linux',
                'cmd': ['enum4linux', '-U', rhost]
                       + (['-u', username, '-p', password] if use_auth else [])
            }
        ]

        for method in rid_methods:
            try:
                result = subprocess.run(
                    method['cmd'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = result.stdout + result.stderr

                user_patterns = [
                    r'([a-zA-Z0-9._-]+)\s+\(RID:\s*\d+\)',
                    r'User:\s+([a-zA-Z0-9._-]+)',
                    r'username:\s*\'([^\']+)\'',
                    r'rid:.*?user:\s*([^\n]+)'
                ]

                users = []
                for pattern in user_patterns:
                    found = re.findall(pattern, output, re.IGNORECASE)
                    if found:
                        found = [u.strip() for u in found
                                 if u.strip() not in ['None', '', discovered_domain]
                                 and not u.strip().endswith('$')]
                        users.extend(found)

                if users:
                    discovered_users.extend(users)
                    discovered_users = list(set(discovered_users))
                    console.print(f"[green][✓] {method['name']} found {len(users)} user(s)[/green]")
                    break

            except subprocess.TimeoutExpired:
                console.print(f"[yellow][-] {method['name']} timed out[/yellow]")
            except FileNotFoundError:
                console.print(f"[yellow][-] {method['name']} not found[/yellow]")
            except Exception as e:
                console.print(f"[dim][-] {method['name']} error: {escape_rich_markup(str(e))}[/dim]")

        if discovered_users:
            console.print(f"[green][✓] Total unique users: {len(discovered_users)}[/green]")
            for user in discovered_users[:20]:
                console.print(f"    • {user}", style="cyan")
            if len(discovered_users) > 20:
                console.print(f"    [dim]... and {len(discovered_users) - 20} more[/dim]")
        else:
            console.print("[yellow][-] No users found via RID cycling[/yellow]")

    # ── 3. Share Enumeration ──────────────────────────────────────────────────
    console.print("\n[bold yellow][+] Enumerating Shares...[/bold yellow]")

    # smbmap
    try:
        cmd = ["smbmap", "-H", rhost, "-p", rport] + smbmap_auth()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        output = result.stdout

        if output and output.strip():
            if "Authentication" in output or ("Error" in output and "disk" not in output.lower()):
                console.print("[yellow][!] smbmap: authentication error[/yellow]")
            elif "disk" in output.lower() or "IPC$" in output:
                console.print(Panel(escape_rich_markup(output),
                                    title="SMBMap Results", border_style="blue"))
            else:
                console.print("[yellow][-] No readable shares found via smbmap[/yellow]")
        else:
            console.print("[yellow][-] smbmap returned no output[/yellow]")

    except subprocess.TimeoutExpired:
        console.print("[yellow][-] smbmap timed out[/yellow]")
    except FileNotFoundError:
        console.print("[yellow][-] smbmap not installed[/yellow]")
    except Exception as e:
        console.print(f"[red][-] smbmap error: {escape_rich_markup(str(e))}[/red]")

    # smbclient fallback
    try:
        cmd = ["smbclient", "-L", rhost, "-p", rport] + smbclient_auth()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = result.stdout

        if output and ("Sharename" in output or "Disk" in output):
            share_section = re.search(r'(?<=Sharename).*?(?=\n\n|\Z)', output, re.DOTALL)
            if share_section:
                console.print(Panel(escape_rich_markup(share_section.group()),
                                    title="SMBClient Shares", border_style="green"))
        elif "NT_STATUS_ACCESS_DENIED" in output:
            console.print("[yellow][!] smbclient: Access denied[/yellow]")
        elif "NT_STATUS_LOGON_FAILURE" in output:
            console.print("[red][!] smbclient: Wrong credentials![/red]")

    except subprocess.TimeoutExpired:
        console.print("[yellow][-] smbclient timed out[/yellow]")
    except FileNotFoundError:
        pass
    except Exception as e:
        console.print(f"[dim][-] smbclient error: {escape_rich_markup(str(e))}[/dim]")

    # ── 4. NULL / Authenticated session check ─────────────────────────────────
    label = "Authenticated" if use_auth else "NULL"
    console.print(f"\n[yellow][+] Checking {label} session on IPC$...[/yellow]")

    null_session_ok = False
    try:
        null_cmd = (
            ["smbclient", f"//{rhost}/IPC$", "-p", rport, "-c", "exit"]
            + smbclient_auth()
        )
        result = subprocess.run(null_cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            null_session_ok = True
            console.print(f"[green][✓] {label} session allowed on IPC$[/green]")
        else:
            err = result.stderr or result.stdout
            if "NT_STATUS_LOGON_FAILURE" in err:
                console.print("[red][!] Login failed — check USERNAME/PASSWORD[/red]")
            else:
                console.print(f"[yellow][-] {label} session not allowed[/yellow]")
    except Exception:
        console.print(f"[dim][-] Could not test {label} session[/dim]")

    # ── 5. Final Summary ───────────────────────────────────────────────────────
    console.print(f"\n[bold green]{'='*50}[/bold green]")
    console.print(f"[bold green][✓] SMB Enumeration completed on {rhost}[/bold green]")
    console.print(f"   {'Domain':<14}: [cyan]{discovered_domain}[/cyan]")
    console.print(f"   {'Auth mode':<14}: [cyan]{'Authenticated' if use_auth else 'Anonymous'}[/cyan]")
    if use_auth:
        console.print(f"   {'Username':<14}: [cyan]{username}[/cyan]")
    console.print(f"   {'Users found':<14}: [cyan]{len(discovered_users)}[/cyan]")
    if discovered_users:
        console.print(f"   {'Sample users':<14}: [cyan]{', '.join(discovered_users[:5])}[/cyan]")

    # Save to session
    if "results" not in session:
        session["results"] = {}

    session["results"][f"smb_{rhost}"] = {
        "domain":       discovered_domain,
        "users":        discovered_users,
        "target":       rhost,
        "username":     username if use_auth else "anonymous",
        "null_session": null_session_ok,
        "timestamp":    subprocess.getoutput("date")
    }

    return True
