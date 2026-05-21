# modules/recon/dirbrute.py
# DirBuster Module — FINAL 2025 Edition (Zero Error, Auto Smart Tool)
import subprocess
import shutil
import os
import time
from typing import Dict, Any
from rich.console import Console
from rich.table import Table

MODULE_INFO = {
    "name": "DirBuster",
    "description": "Smart directory & file brute-force (auto tool selection)",
    "author": "LazyFramework Team",
    "rank": "Excellent",
    "category": "recon",
}

OPTIONS = {
    "URL": {
        "default": "",
        "required": True,
        "description": "Target URL (http:// atau https://)",
    },
    "WORDLIST": {
        "default": "common.txt",
        "required": False,
        "description": "Wordlist path (otomatis cari jika kosong)",
    },
    "THREADS": {
        "default": "60",
        "required": False,
        "description": "Jumlah threads (10-300)",
    },
    "EXTENSIONS": {
        "default": "php,html,js,txt,env,bak,zip,config,git,svn",
        "required": False,
        "description": "Ekstensi file (pisah koma)",
    },
    "TOOL": {
        "default": "auto",
        "required": False,
        "description": "Pilih tool: auto, dirsearch, ffuf, gobuster",
        "choices": ["auto", "dirsearch", "ffuf", "gobuster"],
    },
}

COMMON_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/big.txt",
    "/data/data/com.termux/files/usr/share/wordlists/dirb/common.txt",
    "/data/data/com.termux/files/usr/share/seclists/Discovery/Web-Content/common.txt",
]

console = Console()

def _find_wordlist(user_input: str) -> str:
    if user_input and os.path.exists(user_input):
        return user_input
    for path in COMMON_WORDLISTS:
        if os.path.exists(path):
            console.print(f"[dim]Wordlist otomatis: {os.path.basename(path)}[/]")
            return path
    return None

def _detect_best_tool() -> str:
    tools = {}
    if shutil.which("dirsearch"): tools["dirsearch"] = 10   # Paling stabil vs WAF
    if shutil.which("ffuf"):       tools["ffuf"] = 20       # Paling cepat kalau target allow
    if shutil.which("gobuster"):   tools["gobuster"] = 5

    if not tools:
        console.print("[bold red][X] Tidak ada tool terinstall! Install: dirsearch / ffuf / gobuster[/]")
        return None

    # Prioritas: ffuf > dirsearch > gobuster
    best = max(tools, key=tools.get)
    console.print(f"[bold green][+] Tool dipilih otomatis: {best.upper()}[/]")
    return best

def run(session: Dict[str, Any], options: Dict[str, Any]):
    url = options.get("URL", "").strip().rstrip("/")
    wordlist_input = options.get("WORDLIST", "").strip()
    threads = str(options.get("THREADS", "60"))
    exts = options.get("EXTENSIONS", "").replace(" ", "")
    tool_choice = options.get("TOOL", "auto").lower()

    # Validasi URL
    if not url.startswith(("http://", "https://")):
        console.print("[bold red][X] URL harus pakai http:// atau https://[/]")
        return

    # Pilih tool
    if tool_choice == "auto":
        tool = _detect_best_tool()
    else:
        if not shutil.which(tool_choice):
            console.print(f"[bold red][X] Tool '{tool_choice}' tidak terinstall![/]")
            return
        tool = tool_choice
        console.print(f"[bold yellow][*] Tool dipaksa: {tool.upper()}[/]")

    if not tool:
        return

    # Cari wordlist
    wordlist = _find_wordlist(wordlist_input)
    if not wordlist:
        console.print("[bold red][X] Wordlist tidak ditemukan![/]")
        console.print("[dim]Coba install SecLists atau set path manual[/]")
        return

    # Tampilkan config
    table = Table(title="[bold cyan]DirBuster Config — 2025[/]", box=None)
    table.add_column("Parameter", style="bold green")
    table.add_column("Value")
    table.add_row("Target", url)
    table.add_row("Tool", f"[bold yellow]{tool.upper()}[/]")
    table.add_row("Wordlist", os.path.basename(wordlist))
    table.add_row("Threads", threads)
    table.add_row("Extensions", exts or "[dim]None[/]")
    console.print(table)
    console.print()

    # Build command berdasarkan tool (100% anti-stuck & anti-timeout)
    cmd = []
    if tool == "ffuf":
        cmd = [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-w", wordlist, 
            "-t", "15",              # Threads rendah
            "-mc", "200,301,302,403,401,404,500",
            "-ac",                   # MATIIN auto-calibration
            "-p", "1.0",             # Delay 1 detik
            "-timeout", "25",        # Timeout panjang
            "-sf",                   # Simple format
            "-recursion", "false",
            "-noninteractive",
            "-H", "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "-H", "Accept: */*"
        ]
        if exts:
            cmd.extend(["-e", exts])

    elif tool == "dirsearch":
        cmd = [
            "dirsearch", "-u", url, "-w", wordlist,
            "-t", threads,
            "--random-agent",
            "--format=plain",
            "--max-time=600",
            "--timeout=10"
        ]
        if exts:
            cmd.extend(["-e", exts])

    elif tool == "gobuster":
        cmd = [
            "gobuster", "dirb", "-u", url, "-w", wordlist,
            "-t", threads, "-q", "--timeout", "10s", "--no-error"
        ]
        if exts:
            cmd.extend(["-x", exts])

    console.print(f"[dim]Running: {' '.join(cmd)}[/]\n")

    # Jalankan dengan live output
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        findings = []
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue

            # Deteksi hasil dari semua tool
            if any(code in line for code in ["200", "301", "302", "403", "401"]):
                if "http" in line or "/" in line:
                    path = line.split()[-1] if " " in line else line
                    status = "200"
                    if tool == "dirsearch":
                        status = line.split()[0].strip("[]") if line.split() else "200"
                    elif tool == "gobuster":
                        status = line.split()[1].strip("()") if len(line.split()) > 1 else "200"

                    findings.append((status, path))
                    color = "green" if status == "200" else "yellow" if status in ["301","302"] else "red"
                    console.print(f"[{color}][+] {status}[/] {path}")

        process.wait()
        _show_summary(findings)

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Scan dihentikan oleh user[/]")
    except Exception as e:
        console.print(f"\n[bold red][X] Error: {e}[/]")

def _show_summary(findings):
    if not findings:
        console.print("\n[bold white]Tidak ada direktori/file yang ditemukan.[/]")
        return

    table = Table(title="[bold magenta]Scan Summary — Completed[/]")
    table.add_column("Status", width=8)
    table.add_column("Path", style="bold")
    count_200 = sum(1 for s, _ in findings if s == "200")

    for status, path in findings[:50]:
        if status == "200":
            table.add_row("[green]200 OK[/]", path)
        elif status in ["301", "302"]:
            table.add_row("[yellow]30X[/]", path)
        else:
            table.add_row("[red]403/401[/]", path)

    if len(findings) > 50:
        table.add_row("...", f"[dim]+{len(findings)-50} lainnya[/]")

    console.print(table)
    console.print(f"\n[bold green]Found {count_200} direktori aktif[/] • Total: {len(findings)} respon[/]")
    console.print(f"[dim]Scan selesai: {time.strftime('%H:%M:%S')}[/]")
