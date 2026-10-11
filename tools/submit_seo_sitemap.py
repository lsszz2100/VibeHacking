#!/usr/bin/env python3
"""
Automated Search Engine Sitemap Ping & IndexNow Submission Utility for VibeHacking.

Notifies major search engines (Google, Bing, Naver, Yandex, Seznam via IndexNow)
whenever new content or challenges are published.
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request
from typing import List

SITE_HOST = "lsszz2100.github.io"
SITE_BASE = f"https://{SITE_HOST}/VibeHacking"
ROOT_SITEMAP = f"{SITE_BASE}/sitemap.xml"
WARGAME_SITEMAP = f"{SITE_BASE}/wargame/sitemap.xml"

INDEXNOW_KEY = "4a8f9c12b7e53d0684a1e90f2b6c7d1e"
INDEXNOW_KEY_LOCATION = f"{SITE_BASE}/{INDEXNOW_KEY}.txt"

TOP_URLS = [
    f"{SITE_BASE}/",
    f"{SITE_BASE}/wargame/",
    f"{SITE_BASE}/#/README",
    f"{SITE_BASE}/#/USAGE",
    f"{SITE_BASE}/#/labs/README",
    f"{SITE_BASE}/wargame/index.html",
]

def ping_search_engine(name: str, endpoint_url: str, dry_run: bool = False) -> bool:
    """Send a GET request to a search engine's sitemap ping endpoint."""
    print(f"[*] Pinging {name}: {endpoint_url}")
    if dry_run:
        print(f"    [DRY-RUN] Skipped network call to {name}.")
        return True

    try:
        req = urllib.request.Request(
            endpoint_url,
            headers={"User-Agent": "VibeHacking-SEO-Automation/1.0 (+https://github.com/lsszz2100/VibeHacking)"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
            print(f"    [+] {name} ping succeeded (HTTP {status})")
            return status in (200, 201, 202, 204)
    except urllib.error.HTTPError as e:
        if e.code in (404, 410):
            print(f"    [i] {name} legacy /ping endpoint is deprecated by {name}. (Modern standard relies on robots.txt Sitemap directive & IndexNow protocol)")
        else:
            print(f"    [-] {name} HTTP error: {e.code} {e.reason}")
        return False
    except Exception as e:
        print(f"    [-] {name} failed: {e}")
        return False

def submit_indexnow(urls: List[str], dry_run: bool = False) -> bool:
    """Submit URLs to IndexNow API (Bing, Naver, Yandex, Seznam)."""
    endpoint = "https://api.indexnow.org/indexnow"
    payload = {
        "host": SITE_HOST,
        "key": INDEXNOW_KEY,
        "keyLocation": INDEXNOW_KEY_LOCATION,
        "urlList": urls
    }
    data = json.dumps(payload).encode("utf-8")

    print(f"[*] Submitting {len(urls)} URLs to IndexNow ({endpoint})...")
    if dry_run:
        print("    [DRY-RUN] Payload:")
        print(json.dumps(payload, indent=4))
        return True

    try:
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": "VibeHacking-IndexNow/1.0"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
            print(f"    [+] IndexNow submitted successfully (HTTP {status})")
            return status in (200, 202)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        print(f"    [-] IndexNow HTTP error: {e.code} {e.reason} -> {body}")
        return False
    except Exception as e:
        print(f"    [-] IndexNow submission failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Submit VibeHacking sitemaps and URLs to search engines.")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without sending actual network requests.")
    args = parser.parse_args()

    print("=" * 65)
    print(" VibeHacking Automated SEO & Sitemap Submission Engine")
    print("=" * 65)
    print(f"Target Site:   {SITE_BASE}")
    print(f"Root Sitemap:  {ROOT_SITEMAP}")
    print(f"Mode:          {'DRY-RUN' if args.dry_run else 'LIVE SUBMISSION'}")
    print("-" * 65)

    # 1. Google Sitemap Ping
    google_url = f"https://www.google.com/ping?sitemap={urllib.parse.quote(ROOT_SITEMAP)}"
    ping_search_engine("Google", google_url, dry_run=args.dry_run)

    # 2. Bing Sitemap Ping
    bing_url = f"https://www.bing.com/ping?sitemap={urllib.parse.quote(ROOT_SITEMAP)}"
    ping_search_engine("Bing", bing_url, dry_run=args.dry_run)

    # 3. IndexNow Instant Indexing
    submit_indexnow(TOP_URLS, dry_run=args.dry_run)

    print("-" * 65)
    print("[+] SEO ping and indexing workflow completed.")
    print("=" * 65)

if __name__ == "__main__":
    main()
