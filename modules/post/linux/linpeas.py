#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LinPEAS - Linux Privilege Escalation Awesome Script
"""

import subprocess
import os
import re
import time
import base64
import tempfile
import shutil

MODULE_INFO = {
    "name": "linpeas",
    "description": "Linux Privilege Escalation Awesome Script",
    "author": "LazyFramework",
    "license": "GPL v3",
    "platform": "linux",
    "rank": "great",
    "dependencies": []
}

OPTIONS = {
    "RHOST": {
        "description": "Target IP address",
        "required": True,
        "default": ""
    },
    "PORT": {
        "description": "SSH port",
        "required": False,
        "default": "22"
    },
    "USER": {
        "description": "SSH username",
        "required": True,
        "default": ""
    },
    "PASSWORD": {
        "description": "SSH password",
        "required": True,
        "default": ""
    },
    "OUTPUT_DIR": {
        "description": "Output directory",
        "required": False,
        "default": "/tmp/linpeas_results"
    },
    "FAST_MODE": {
        "description": "Skip slow/thorough checks (-s flag). Recommended: True",
        "required": False,
        "default": "True"         # was False — slow checks rarely needed
    },
    "USE_STEALTH": {
        "description": "Suppress ANSI color output (-q flag)",
        "required": False,
        "default": "True"
    },
    "SECTIONS": {
        "description": (
            "Comma-separated LinPEAS sections to run. "
            "Nama valid: system_information,container,cloud,"
            "procs_crons_timers_srvcs_sockets,network_information,"
            "users_information,software_information,"
            "interesting_perms_files,interesting_files,api_keys_regex. "
            "Set ke '' untuk scan semua."
        ),
        "required": False,
        "default": "system_information,users_information,procs_crons_timers_srvcs_sockets,interesting_perms_files,interesting_files"
    },
    "TIMEOUT": {
        "description": "SSH session timeout in seconds (default 300, was hardcoded 600)",
        "required": False,
        "default": "300"
    }
}


def run(session, options):
    rhost = options.get("RHOST", "").strip()
    port = options.get("PORT", "22").strip()
    user = options.get("USER", "").strip()
    password = options.get("PASSWORD", "").strip()
    output_dir = options.get("OUTPUT_DIR", "/tmp/linpeas_results")
    fast_mode = options.get("FAST_MODE", "True").lower() == "true"
    use_stealth = options.get("USE_STEALTH", "True").lower() == "true"
    sections = options.get("SECTIONS", "").strip()
    timeout = int(options.get("TIMEOUT", "300"))

    if not rhost or not user or not password:
        print("[!] RHOST, USER, and PASSWORD are required")
        return False

    print(f"""
[+] LinPEAS Scanner
[+] Target:   {user}@{rhost}:{port}
[+] Output:   {output_dir}
[+] FastMode: {fast_mode}
[+] Sections: {sections if sections else 'all'}
[+] Timeout:  {timeout}s
    """)

    os.makedirs(output_dir, exist_ok=True)

    # Build params
    params = []
    if fast_mode:
        params.append("-s")          # skip slow checks — biggest speedup
    if use_stealth:
        params.append("-q")          # no ANSI colors — cleaner output
    if sections:
        params.extend(["-o", sections])  # only run requested sections
    
    # Get linpeas content
    linpeas_content = get_linpeas_content()
    if not linpeas_content:
        return False
    
    encoded = base64.b64encode(linpeas_content.encode()).decode()
    
    # Command to run — sentinel dicetak setelah linpeas selesai
    # streaming loop akan kill proses begitu sentinel terdeteksi
    SENTINEL = "[Scanner Done]"
    remote_cmd = (
        f"TEMP_DIR=$(mktemp -d); cd $TEMP_DIR; "
        f"echo '{encoded}' | base64 -d > l.sh; chmod +x l.sh; "
        f"./l.sh {' '.join(params)}; "
        f"echo '{SENTINEL}'; "        # ← marker selesai
        f"cd /; rm -rf $TEMP_DIR"
    )

    # Run with expect
    return run_expect(rhost, port, user, password, remote_cmd, output_dir, timeout, SENTINEL)


def run_expect(rhost, port, user, password, remote_cmd, output_dir, timeout=300, sentinel=None):
    """Run SSH using expect script"""

    # Escape characters for expect
    cmd_escaped = remote_cmd.replace('"', '\\"').replace('$', '\\$').replace('`', '\\`').replace('[', '\\[').replace(']', '\\]')
    pass_escaped = password.replace('"', '\\"')

    expect_script = f'''#!/usr/bin/expect -f
set timeout {timeout}
log_user 1
fconfigure stdout -buffering line
set stty_init -echo
set cmd_sent 0
spawn ssh -p {port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{rhost}
expect {{
    "yes/no" {{
        send "yes\\r"
        exp_continue
    }}
    "password:" {{
        send "{pass_escaped}\\r"
        exp_continue
    }}
    "Password:" {{
        send "{pass_escaped}\\r"
        exp_continue
    }}
    -re {{[$#] $}} {{
        if {{$cmd_sent == 0}} {{
            set cmd_sent 1
            send "{cmd_escaped}\\r"
        }}
        exp_continue
    }}
    timeout {{
        send_user "\\nTimeout waiting for response\\n"
        exit 1
    }}
    eof
}}
'''
    
    # Write expect script to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.exp', delete=False) as f:
        f.write(expect_script)
        expect_file = f.name
    
    os.chmod(expect_file, 0o755)
    
    print(f"[+] Connecting to {rhost}:{port}...")
    print("[+] Running LinPEAS (this may take several minutes)...\n")
    
    # Strip ANSI escape codes untuk keperluan filter
    _ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKHF]|\x1b\[[0-9]*[A-Z]')

    # Pattern SSH handshake noise yang harus disuppress
    skip_patterns = [
        "spawn ssh",
        "Warning:",
        "Last login:",
        "Debian GNU/Linux",
        "absolutely NO WARRANTY",
        "permitted by applicable law",
        "failed to read",
        "Authentication failed",
        "The programs included",
        "individual files in",
        "comes with ABSOLUTELY",
        "password:",
        "Password:",
    ]

    def is_noise(line: str) -> bool:
        clean = _ANSI_RE.sub('', line).strip()
        # Shell prompt: lazy@debian:~$ atau root@host:#
        if re.match(r'^\S+@\S+:[~\w/$-]*[#$]\s*$', clean):
            return True
        return any(p.lower() in clean.lower() for p in skip_patterns)

    try:
        # stdbuf -oL paksa expect output line-buffered ke pipe
        # tanpa ini expect block-buffer ~4KB sebelum kirim ke Python
        stdbuf = shutil.which('stdbuf')
        cmd = ['stdbuf', '-oL', expect_file] if stdbuf else [expect_file]

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,             # line-buffered di sisi Python
        )

        clean_lines = []
        start = time.time()

        # Stream each line as it arrives instead of waiting for communicate()
        for raw_line in iter(process.stdout.readline, ''):
            if time.time() - start > timeout + 30:
                process.kill()
                os.unlink(expect_file)
                print(f"\n[-] Timeout after {timeout}s — try increasing TIMEOUT or narrowing SECTIONS")
                return False

            # Sentinel terdeteksi → linpeas selesai, stop langsung
            if sentinel and sentinel in raw_line:
                print("\n[+] LinPEAS selesai.", flush=True)
                process.kill()
                break

            # Strip SSH handshake noise & shell prompts
            if is_noise(raw_line):
                continue
            line = raw_line.rstrip('\n')
            if not line.strip():
                continue

            print(line, flush=True)   # flush=True → appears immediately in terminal
            clean_lines.append(line)

        process.wait()

        # Cleanup
        os.unlink(expect_file)

        if process.returncode != 0:
            stderr_out = process.stderr.read()
            print(f"[-] Connection failed (code: {process.returncode})")
            if stderr_out:
                print(f"[-] Error: {stderr_out[:300]}")
            return False

        clean_output = '\n'.join(clean_lines)
        
        # Save to file
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_dir, f"linpeas_{rhost}_{timestamp}.txt")
        
        with open(output_file, 'w') as f:
            f.write(f"LinPEAS Report\n")
            f.write(f"Target: {rhost}:{port}\n")
            f.write(f"User: {user}\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*80}\n\n")
            f.write(clean_output)
        
        print(f"\n[+] Results saved to: {output_file}")
        
        # Print summary
        print_summary(clean_output)
        
        return True
        
    except subprocess.TimeoutExpired:
        process.kill()
        os.unlink(expect_file)
        print(f"[-] Timeout after {timeout}s — try increasing TIMEOUT or narrowing SECTIONS")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def get_linpeas_content():
    """Get linpeas.sh content — cek lokal dulu, download hanya jika tidak ada."""
    # Direktori module itu sendiri (taruh linpeas.sh di sebelah linpeas.py)
    module_dir = os.path.dirname(os.path.abspath(__file__))

    local_paths = [
        os.path.join(module_dir, "linpeas.sh"),   # ← prioritas utama: sebelah linpeas.py
        "./linpeas.sh",
        "/usr/local/bin/linpeas.sh",
        "/opt/linpeas/linpeas.sh",
        os.path.expanduser("~/linpeas.sh"),
        os.path.expanduser("~/tools/linpeas/linpeas.sh"),
    ]
    
    for path in local_paths:
        if os.path.exists(path):
            print(f"[+] Using local: {path}")
            with open(path, 'r') as f:
                return f.read()
    
    # Download from GitHub
    print("[+] Downloading linpeas.sh from GitHub...")
    try:
        import urllib.request
        url = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as r:
            content = r.read().decode('utf-8')
            print(f"[+] Downloaded {len(content)} bytes")
            return content
    except Exception as e:
        print(f"[-] Download failed: {e}")
        return None


def print_summary(output):
    """Print summary of findings"""
    print("\n" + "="*60)
    print("LINPEAS SUMMARY")
    print("="*60)
    
    findings = []
    
    for line in output.split('\n'):
        line_lower = line.lower()
        
        if 'cve-' in line_lower and 'vulnerable' in line_lower:
            findings.append(('VULNERABILITY', line.strip()))
        elif 'suid' in line_lower and 'root' in line_lower:
            findings.append(('SUID BINARY', line.strip()))
        elif 'sgid' in line_lower and 'root' in line_lower:
            findings.append(('SGID BINARY', line.strip()))
        elif 'writable' in line_lower and 'root' in line_lower:
            findings.append(('WRITABLE FILE', line.strip()))
        elif 'password' in line_lower and ('found' in line_lower or 'found:' in line_lower):
            findings.append(('PASSWORD/CREDENTIAL', line.strip()))
        elif 'docker' in line_lower and ('writable' in line_lower or 'group' in line_lower):
            findings.append(('DOCKER ESCAPE', line.strip()))
        elif 'sudo' in line_lower and 'nopasswd' in line_lower:
            findings.append(('SUDO NOPASSWD', line.strip()))
    
    if findings:
        print("\n[!] IMPORTANT FINDINGS:\n")
        for cat, f in findings[:20]:
            print(f"  [{cat}] {f[:120]}")
    else:
        print("\n[+] No critical findings detected")
        print("[*] Check full report for complete results")
    
    print("\n" + "="*60)