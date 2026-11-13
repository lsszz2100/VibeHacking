#!/usr/bin/env python3
"""
Chrome Remote Debugging Session Checker
=======================================
Validates connection to the Windows host Chrome debugging port (default 127.0.0.1:9222).
Retrieves active tabs, devtools webSocket endpoints, and session health.
"""

import sys
import json
import urllib.request
import urllib.error
import argparse

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9222

def check_chrome_session(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
    base_url = f"http://{host}:{port}"
    version_url = f"{base_url}/json/version"
    list_url = f"{base_url}/json/list"
    
    print(f"[*] Checking Chrome Remote Debugging port at {base_url}...")
    
    try:
        req = urllib.request.Request(version_url, headers={"User-Agent": "VibeHacking-RemotePublisher/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                version_info = json.loads(resp.read().decode('utf-8'))
                print("==================================================")
                print("  [SUCCESS] Chrome Remote Debugging Session Active")
                print("==================================================")
                print(f"  Browser    : {version_info.get('Browser', 'Unknown')}")
                print(f"  Protocol   : {version_info.get('Protocol-Version', 'Unknown')}")
                print(f"  User-Agent : {version_info.get('User-Agent', 'Unknown')}")
                print(f"  V8 Version : {version_info.get('V8-Version', 'Unknown')}")
                print("--------------------------------------------------")
    except (urllib.error.URLError, ConnectionRefusedError, TimeoutError) as e:
        print("==================================================")
        print("  [ERROR] Cannot connect to Chrome Debugging Port")
        print("==================================================")
        print(f"  Detail: {e}")
        print("\n[!] How to Launch Windows Chrome with Debugging Port:")
        print('    1. Close existing Chrome instances (or use a dedicated debug profile):')
        print('    2. Run in Windows CMD/PowerShell:')
        print('       start chrome.exe --remote-debugging-port=9222 --user-data-dir="C:\\ChromeDebug"')
        print('    3. WSL2 Note: If running inside WSL2, ensure localhost forwarding or test:')
        print('       curl http://127.0.0.1:9222/json/version')
        print("==================================================")
        return False

    # Check active tabs
    try:
        req = urllib.request.Request(list_url, headers={"User-Agent": "VibeHacking-RemotePublisher/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                tabs = json.loads(resp.read().decode('utf-8'))
                page_tabs = [t for t in tabs if t.get('type') == 'page']
                print(f"[*] Active Web Pages: {len(page_tabs)} tab(s) found.")
                for idx, t in enumerate(page_tabs, 1):
                    title = t.get('title', 'No Title')[:50]
                    url = t.get('url', 'No URL')
                    print(f"    [{idx}] {title} -> {url}")
                return True
    except Exception as e:
        print(f"[-] Warning: Failed to retrieve tab list: {e}")
        return True

def main():
    parser = argparse.ArgumentParser(description="Check Chrome Remote Debugging Session (9222)")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Chrome debugger host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Chrome debugger port (default: 9222)")
    args = parser.parse_args()

    success = check_chrome_session(args.host, args.port)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
