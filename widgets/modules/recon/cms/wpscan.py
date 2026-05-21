# modules/recon/wpscan.py
# WPScan Module – LazyFramework (FULL RESPONSIVE + API TOKEN + BRUTEFORCE)

import subprocess
import shutil
import os
import re
from typing import Dict, Any
from rich.table import Table
from rich import box
from rich.console import Console

console = Console(width=70)

MODULE_INFO = {
    "name": "Wordpress Scanner",
    "description": "WordPress scanner - responsive table + API token + bruteforce",
    "author": "Lynx Saiko",
    "category": "recon",
    
}

OPTIONS = {
    "URL": {
        "default": "",
        "required": True,
        "description": "Target URL http/https",
    },
    "MODE": {
        "default": "STANDARD",
        "required": True,
        "choices": ["QUICK", "STANDARD", "AGGRESSIVE", "BRUTEFORCE"],
        "description": "Scan mode",
    },
    "UPDATE_DB": {
        "default": "NO",
        "choices": ["YES", "NO"],
        "description": "Update database WPScan dulu?",
    },
    "MAX_THREADS": {
        "default": "10",
        "description": "Jumlah thread (5-50)",
    },
    "WORDLIST": {
        "default": "",
        "required": False,
        "description": "Path to wordlist",
    },
    "USERNAMES": {
        "default": "admin",
        "required": False,
        "description": "Username user,admin,example",
    },
    "API_TOKEN": {
        "default": "",
        "required": False,
        "description": "WPScan API Token",
    },
}


def strip_ansi(text: str) -> str:
    """Hapus ANSI escape codes dari teks"""
    # Pattern untuk \x1b[XXm
    ansi_pattern = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    text = ansi_pattern.sub('', text)
    
    # Pattern untuk [XXm format (raw dari WPScan)
    raw_ansi_pattern = re.compile(r'\[\d+m')
    text = raw_ansi_pattern.sub('', text)
    
    # Hapus [32m[+][0m pattern
    bracket_pattern = re.compile(r'\[\d+\]\[[+\-!*]\]\[\d+\]')
    text = bracket_pattern.sub('', text)
    
    # Bersihkan sisa-sisa
    text = text.replace('[32m', '').replace('[34m', '').replace('[33m', '')
    text = text.replace('[31m', '').replace('[35m', '').replace('[36m', '')
    text = text.replace('[37m', '').replace('[0m', '').replace('[91m', '')
    text = text.replace('[92m', '').replace('[93m', '').replace('[94m', '')
    text = text.replace('[95m', '').replace('[96m', '').replace('[97m', '')
    
    return text


def colorize_output(line: str) -> str:
    """Colorize output untuk Rich console"""
    line = strip_ansi(line)
    
    if not line:
        return line
    
    # Colorize berdasarkan content
    if '[+]' in line or line.startswith('+'):
        return f"[green]{line}[/]"
    elif '[!]' in line or 'Scan Aborted' in line or 'Warning' in line:
        return f"[yellow]{line}[/]"
    elif '[X]' in line or 'Error' in line or 'failed' in line.lower():
        return f"[red]{line}[/]"
    elif '[*]' in line or 'Updating' in line or 'Enumerating' in line:
        return f"[dim]{line}[/]"
    elif 'Interesting Finding' in line or 'Found By' in line:
        return f"[cyan]{line}[/]"
    elif 'Finished' in line or 'Scan selesai' in line or 'Completed' in line:
        return f"[bold green]{line}[/]"
    elif 'http://' in line or 'https://' in line:
        return f"[blue]{line}[/]"
    else:
        return line


def run(session: Dict[str, Any], options: Dict[str, Any]):
    raw_url = options.get("URL", "").strip()
    mode = options.get("MODE", "STANDARD").upper()
    update_db = options.get("UPDATE_DB", "NO").upper() == "YES"
    threads = options.get("MAX_THREADS", "10")
    wordlist = options.get("WORDLIST", "").strip()
    usernames = options.get("USERNAMES", "admin").strip()
    api_token = options.get("API_TOKEN", "").strip()

    # Normalisasi URL
    if not raw_url:
        console.print("[bold red][X] URL is required![/]")
        return
        
    if not raw_url.startswith(("http://", "https://")):
        url = "https://" + raw_url
    else:
        url = raw_url
    url = url.rstrip("/") + "/"

    # Cek wpscan
    wpscan = shutil.which("wpscan")
    if not wpscan:
        console.print("[bold red][X] wpscan tidak terinstall![/]")
        console.print("[yellow]Install: gem install wpscan[/]")
        console.print("[yellow]Atau: sudo gem install wpscan[/]")
        return

    # Update DB
    if update_db:
        console.print("[cyan][*] Updating WPScan database...[/]")
        try:
            subprocess.run(
                [wpscan, "--update"], 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL,
                timeout=120
            )
            console.print("[green][+] Database updated![/]")
        except subprocess.TimeoutExpired:
            console.print("[yellow][!] Update timeout, continuing...[/]")
        except Exception as e:
            console.print(f"[yellow][!] Update error: {e}[/]")

    # Command utama
    cmd = [
        wpscan,
        "--url", url,
        "--no-banner",
        "--force",
        "--scope",
        "--ignore-main-redirect",
        "--random-user-agent",
        "--max-threads", str(threads),
        "--format", "cli",
    ]

    # Tambah API Token kalau diisi
    if api_token:
        cmd.extend(["--api-token", api_token])
        console.print("[dim][*] Using API Token for vulnerability data[/]")

    # Mode handling
    if mode == "QUICK":
        cmd.extend(["--detection-mode", "passive"])
        cmd.extend(["--enumerate", "vp"])  # only vulnerable plugins
    elif mode == "STANDARD":
        cmd.extend(["--enumerate", "vp,vt,u"])
    elif mode == "AGGRESSIVE":
        cmd.extend([
            "--enumerate", "vp,vt,u,cb,dbe",
            "--plugins-detection", "aggressive"
        ])
    elif mode == "BRUTEFORCE":
        if not wordlist or not os.path.isfile(wordlist):
            console.print("[bold red][X] WORDLIST tidak ditemukan![/]")
            console.print(f"[yellow]Path: {wordlist}[/]")
            console.print("[yellow]Set path yang benar ke file wordlist[/]")
            return
        cmd.extend(["--passwords", wordlist])
        if usernames:
            cmd.extend(["--usernames", usernames])
        else:
            cmd.extend(["--usernames", "admin"])

    # TABEL RESPONSIVE
    table = Table(
        title="[bold cyan]Wordpress Scanner Configuration[/]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        width=console.width,
        expand=True,
    )
    table.add_column("Parameter", style="bold magenta", justify="left", width=18)
    table.add_column("Value", overflow="fold")

    table.add_row("Target", f"[bold white]{url}[/]")
    table.add_row("Mode", f"[bold yellow]{mode}[/]")
    table.add_row("Threads", str(threads))
    table.add_row("Wordlist", wordlist or "[dim]N/A[/]")
    table.add_row("Usernames", usernames or "[dim]admin[/]")
    table.add_row("API Token", "[bold green]Active[/]" if api_token else "[dim]Not used[/]")
    table.add_row("Update DB", "[bold green]YES[/]" if update_db else "[dim]NO[/]")

    console.print(table)
    console.print(f"[dim]Executing Wordpress Scanner ...[/]\n")

    try:
        # Gunakan environment tanpa ANSI
        env = os.environ.copy()
        env['NO_COLOR'] = '1'
        env['TERM'] = 'dumb'
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            env=env
        )

        for line in process.stdout:
            line = line.rstrip()
            if not line:
                continue
            
            # Skip progress bar lines yang terlalu panjang
            if '|' in line and ('=' in line or '-' in line):
                if len(line) > 80 and line.count('|') > 5:
                    continue
            
            # Clean ANSI dan colorize
            clean_line = colorize_output(line)
            console.print(clean_line)

        process.wait()
        
        if process.returncode == 0:
            console.print("\n[bold green][+] WPScan completed successfully![/]")
        else:
            console.print(f"\n[yellow][!] WPScan finished with code: {process.returncode}[/]")

    except KeyboardInterrupt:
        console.print("\n[bold red][X] Cancelled by user[/]")
        if 'process' in locals():
            process.terminate()
    except Exception as e:
        console.print(f"[bold red][X] Error: {e}[/]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/]")
