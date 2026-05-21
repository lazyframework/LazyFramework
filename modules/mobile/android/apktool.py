#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MODULE_INFO = {
    "name": "Apktool",
    "description": "Tool for reverse engineering Android APK (decode & rebuild)",
    "author": "LazyFramework",
    "license": "MIT",
    "rank": "Excellent",
    "platform": "linux",
    "arch": "multi",
    "type": "mobile",
    "category": "mobile",
    "dependencies": [],
    "references": [
        "https://apktool.org",
        "https://github.com/iBotPeaches/Apktool"
    ]
}

OPTIONS = {
    "ACTION": {
        "description": "Mode apktool",
        "required": True,
        "default": "decode",
        "choices": ["decode", "build", "install-framework"]
    },
    "INPUT": {
        "description": "Path to file APK (decode) atau folder (untuk build)",
        "required": True,
        "default": "app.apk"
    },
    "OUTPUT": {
        "description": "Output directory/folder (opsional)",
        "required": False,
        "default": ""
    },
    "FORCE": {
        "description": "Force overwrite (use -f)",
        "required": False,
        "default": "false",
        "choices": ["true", "false"]
    },
    "NO_RES": {
        "description": "Jangan decode resources (hanya untuk decode)",
        "required": False,
        "default": "false",
        "choices": ["true", "false"]
    },
    "NO_SRC": {
        "description": "Jangan decode sources/smali (hanya untuk decode)",
        "required": False,
        "default": "false",
        "choices": ["true", "false"]
    },
    "FRAMEWORK_PATH": {
        "description": "Custom framework path",
        "required": False,
        "default": ""
    }
}

def run(session, options):
    action = options.get("ACTION", "decode").lower()
    input_path = options.get("INPUT")
    output = options.get("OUTPUT")
    force = options.get("FORCE", "false").lower() == "true"
    no_res = options.get("NO_RES", "false").lower() == "true"
    no_src = options.get("NO_SRC", "false").lower() == "true"
    fw_path = options.get("FRAMEWORK_PATH", "")

    cmd = "apktool"

    if action == "decode":
        cmd += " d"
        if force:
            cmd += " -f"
        if no_res:
            cmd += " -r"
        if no_src:
            cmd += " -s"
        cmd += f" \"{input_path}\""
        if output:
            cmd += f" -o \"{output}\""

    elif action == "build":
        cmd += " b"
        if force:
            cmd += " -f"
        cmd += f" \"{input_path}\""
        if output:
            cmd += f" -o \"{output}\""

    elif action == "install-framework":
        cmd += " if"
        if fw_path:
            cmd += f" -p \"{fw_path}\""
        cmd += f" \"{input_path}\""

    else:
        print("[-] ACTION tidak dikenali!")
        return False

    print(f"[*] Menjalankan: {cmd}")
    print("=" * 70)

    try:
        import subprocess
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)

        if result.returncode == 0:
            print(f"\n[✓] Apktool {action} berhasil!")
            if action == "decode" and not output:
                print(f"    Output disimpan di folder: {input_path.replace('.apk', '')}")
            return True
        else:
            print(f"\n[✗] Apktool gagal dengan kode: {result.returncode}")
            return False

    except FileNotFoundError:
        print("[-] Apktool tidak ditemukan di sistem!")
        print("    Install dengan: sudo apt install apktool")
        return False
    except subprocess.TimeoutExpired:
        print("[-] Proses timeout (terlalu lama)")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False