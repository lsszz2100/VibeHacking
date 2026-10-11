#!/usr/bin/env python3
"""
Generate comprehensive XML Sitemaps for VibeHacking GitHub Pages portal and wargame.
Conforms to sitemaps.org protocol 0.9.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET

REPO_ROOT = Path(__file__).resolve().parent.parent
BASE_URL = "https://lsszz2100.github.io/VibeHacking"
TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")

def generate_root_sitemap():
    urlset = ET.Element("urlset", xmlns="http://www.sitemaps.org/schemas/sitemap/0.9")

    # Core portals
    core_entries = [
        {"loc": f"{BASE_URL}/", "priority": "1.0", "changefreq": "daily"},
        {"loc": f"{BASE_URL}/wargame/", "priority": "1.0", "changefreq": "daily"},
        {"loc": f"{BASE_URL}/#/README", "priority": "0.9", "changefreq": "weekly"},
        {"loc": f"{BASE_URL}/#/USAGE", "priority": "0.8", "changefreq": "weekly"},
        {"loc": f"{BASE_URL}/#/labs/README", "priority": "0.9", "changefreq": "weekly"},
        {"loc": f"{BASE_URL}/#/CONTRIBUTING", "priority": "0.5", "changefreq": "monthly"},
        {"loc": f"{BASE_URL}/#/ROADMAP", "priority": "0.6", "changefreq": "monthly"},
        {"loc": f"{BASE_URL}/#/SECURITY", "priority": "0.6", "changefreq": "monthly"},
    ]

    for item in core_entries:
        u = ET.SubElement(urlset, "url")
        ET.SubElement(u, "loc").text = item["loc"]
        ET.SubElement(u, "lastmod").text = TODAY
        ET.SubElement(u, "changefreq").text = item["changefreq"]
        ET.SubElement(u, "priority").text = item["priority"]

    # 75 Sections
    for p in sorted(REPO_ROOT.glob("[0-9][0-9]_*/README.md")):
        rel = p.relative_to(REPO_ROOT)
        sec_dir = rel.parent.name
        loc = f"{BASE_URL}/#/{sec_dir}/README"
        u = ET.SubElement(urlset, "url")
        ET.SubElement(u, "loc").text = loc
        ET.SubElement(u, "lastmod").text = TODAY
        ET.SubElement(u, "changefreq").text = "weekly"
        ET.SubElement(u, "priority").text = "0.8"

    # 38 Labs
    for p in sorted(REPO_ROOT.glob("labs/lab[0-9][0-9]/README.md")):
        rel = p.relative_to(REPO_ROOT)
        loc = f"{BASE_URL}/#/{rel.parent}/README"
        u = ET.SubElement(urlset, "url")
        ET.SubElement(u, "loc").text = loc
        ET.SubElement(u, "lastmod").text = TODAY
        ET.SubElement(u, "changefreq").text = "weekly"
        ET.SubElement(u, "priority").text = "0.75"

    tree = ET.ElementTree(urlset)
    ET.indent(tree, space="  ", level=0)
    out_path = REPO_ROOT / "sitemap.xml"
    with open(out_path, "wb") as f:
        f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
        tree.write(f, encoding="utf-8", xml_declaration=False)
    print(f"[+] Root sitemap generated with {len(urlset)} entries -> {out_path}")

def generate_wargame_sitemap():
    urlset = ET.Element("urlset", xmlns="http://www.sitemaps.org/schemas/sitemap/0.9")

    entries = [
        {"loc": f"{BASE_URL}/wargame/", "priority": "1.0", "changefreq": "daily"},
        {"loc": f"{BASE_URL}/wargame/index.html", "priority": "0.9", "changefreq": "daily"},
        {"loc": f"{BASE_URL}/wargame/manifest.json", "priority": "0.5", "changefreq": "monthly"},
    ]

    for item in entries:
        u = ET.SubElement(urlset, "url")
        ET.SubElement(u, "loc").text = item["loc"]
        ET.SubElement(u, "lastmod").text = TODAY
        ET.SubElement(u, "changefreq").text = item["changefreq"]
        ET.SubElement(u, "priority").text = item["priority"]

    tree = ET.ElementTree(urlset)
    ET.indent(tree, space="  ", level=0)
    out_path = REPO_ROOT / "wargame" / "sitemap.xml"
    with open(out_path, "wb") as f:
        f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
        tree.write(f, encoding="utf-8", xml_declaration=False)
    print(f"[+] Wargame sitemap generated with {len(urlset)} entries -> {out_path}")

if __name__ == "__main__":
    generate_root_sitemap()
    generate_wargame_sitemap()
