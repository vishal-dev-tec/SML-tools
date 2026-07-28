"""
SML Scanner - Tool Registry
============================
Defines every wrapped scanning tool: binary name, command template,
category, timeout, and required target format. Add new tools here only.

Categories:
    RECON      - passive/active information gathering (whois, dns, osint)
    PORTSCAN   - port/service discovery
    WEB        - web application fingerprinting/vuln scanning
    TLS        - SSL/TLS configuration auditing
    NETSVC     - network service enumeration (SMB, SNMP)
    VULN       - CVE/template-based vulnerability matching
"""

from dataclasses import dataclass, field
from enum import Enum


class Category(Enum):
    RECON = "Reconnaissance"
    PORTSCAN = "Port & Service Scan"
    WEB = "Web Application"
    TLS = "TLS/SSL Audit"
    NETSVC = "Network Service Enumeration"
    VULN = "Vulnerability Matching"


@dataclass
class ToolSpec:
    key: str                 # internal id, also used for raw log filename
    binary: str               # binary name to check with `which`
    display_name: str
    category: Category
    # {target} = raw target, {host} = hostname/ip only, {url} = http(s) url,
    # {outdir} = per-scan output directory
    cmd_template: list        # list form for subprocess, no shell=True
    timeout_sec: int
    requires_url: bool = False   # tool needs http(s):// target, not bare host
    notes: str = ""
    planner_hint: str = ""       # one-line "run this when..." fed to the AI planner


# NOTE: exact flags assume Kali/BlackArch/Arch(AUR) standard packages.
# On CachyOS: nmap, whois, bind-tools (dig), openssl are in [core]/[extra].
# whatweb, nikto, sslscan, dnsrecon, theharvester, amass, nuclei, enum4linux,
# ffuf, wpscan, testssl.sh, gobuster are AUR packages — install before running.

TOOLS: list[ToolSpec] = [
    # ---------------- RECON ----------------
    ToolSpec(
        key="whois",
        binary="whois",
        display_name="WHOIS Domain Lookup",
        category=Category.RECON,
        cmd_template=["whois", "{host}"],
        timeout_sec=30,
        notes="Registrar, creation/expiry dates, nameservers.",
    ),
    ToolSpec(
        key="dig",
        binary="dig",
        display_name="DNS Record Enumeration (dig)",
        category=Category.RECON,
        cmd_template=["dig", "{host}", "ANY", "+noall", "+answer"],
        timeout_sec=20,
    ),
    ToolSpec(
        key="dnsrecon",
        binary="dnsrecon",
        display_name="DNSRecon Subdomain/Zone Enumeration",
        category=Category.RECON,
        cmd_template=["dnsrecon", "-d", "{host}"],
        timeout_sec=120,
    ),
    ToolSpec(
        key="theharvester",
        binary="theHarvester",
        display_name="theHarvester OSINT (emails/subdomains)",
        category=Category.RECON,
        cmd_template=["theHarvester", "-d", "{host}", "-l", "200", "-b", "duckduckgo"],
        timeout_sec=180,
    ),
    ToolSpec(
        key="amass",
        binary="amass",
        display_name="Amass Subdomain Enumeration (passive)",
        category=Category.RECON,
        cmd_template=["amass", "enum", "-passive", "-d", "{host}"],
        timeout_sec=180,
    ),

    # ---------------- PORTSCAN ----------------
    ToolSpec(
        key="nmap_quick",
        binary="nmap",
        display_name="Nmap Fast Triage Scan (top 1000 ports)",
        category=Category.PORTSCAN,
        cmd_template=["nmap", "-sV", "-T4", "--top-ports", "1000", "--open", "{host}"],
        timeout_sec=120,
        notes="Fast initial fingerprint used to feed the AI planner — not part of the deep suite, use nmap_tcp for that.",
    ),
    ToolSpec(
        key="nmap_tcp",
        binary="nmap",
        display_name="Nmap Deep TCP Scan (all ports, OS+version, vuln scripts)",
        category=Category.PORTSCAN,
        cmd_template=[
            "nmap", "-A", "-p-", "-T4", "--open",
            "--script", "default,vuln,discovery",
            "{host}",
        ],
        timeout_sec=1800,
        notes="Full 65535 ports, OS detection, traceroute, default+vuln+discovery NSE scripts. This is the long pole of the scan — 10-25min depending on target and host responsiveness.",
    ),
    ToolSpec(
        key="nmap_udp",
        binary="nmap",
        display_name="Nmap Top-500 UDP Scan",
        category=Category.PORTSCAN,
        cmd_template=["nmap", "-sU", "--top-ports", "500", "-sV", "-T4", "{host}"],
        timeout_sec=900,
    ),
    ToolSpec(
        key="masscan",
        binary="masscan",
        display_name="Masscan High-Speed Port Sweep",
        category=Category.PORTSCAN,
        cmd_template=["masscan", "{host}", "-p1-65535", "--rate", "1000"],
        timeout_sec=300,
        notes="Requires root/CAP_NET_RAW.",
    ),

    # ---------------- WEB ----------------
    ToolSpec(
        key="whatweb",
        binary="whatweb",
        display_name="WhatWeb Technology Fingerprint",
        category=Category.WEB,
        cmd_template=["whatweb", "-a", "4", "-v", "{url}"],
        timeout_sec=90,
        requires_url=True,
        notes="Aggression level 4 = most thorough (heavier, more requests).",
    ),
    ToolSpec(
        key="nikto",
        binary="nikto",
        display_name="Nikto Deep Web Vulnerability Scan",
        category=Category.WEB,
        cmd_template=["nikto", "-h", "{url}", "-Tuning", "x", "-Display", "V"],
        timeout_sec=1200,
        requires_url=True,
        notes="-Tuning x runs every test category including ones off by default.",
    ),
    ToolSpec(
        key="gobuster",
        binary="gobuster",
        display_name="Gobuster Deep Directory/File Brute-force",
        category=Category.WEB,
        cmd_template=[
            "gobuster", "dir", "-u", "{url}",
            "-w", "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "-x", "php,html,js,txt,bak,zip,config,json,old,sql",
            "-q", "-t", "60",
        ],
        timeout_sec=1500,
        requires_url=True,
        notes="Needs seclists package (much larger wordlist than dirb/common.txt) — this alone can run 15-20min.",
    ),
    ToolSpec(
        key="ffuf",
        binary="ffuf",
        display_name="ffuf Recursive Web Fuzzer",
        category=Category.WEB,
        cmd_template=[
            "ffuf", "-u", "{url}/FUZZ",
            "-w", "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "-e", ".php,.html,.js,.txt,.bak,.json",
            "-recursion", "-recursion-depth", "2",
            "-of", "json", "-o", "{outdir}/ffuf.json", "-s",
        ],
        timeout_sec=1500,
        requires_url=True,
        notes="Recursive fuzzing into discovered directories, up to depth 2.",
    ),
    ToolSpec(
        key="wpscan",
        binary="wpscan",
        display_name="WPScan WordPress Deep Audit",
        category=Category.WEB,
        cmd_template=[
            "wpscan", "--url", "{url}", "--no-banner", "--random-user-agent",
            "--enumerate", "vp,vt,tt,cb,dbe,u",
            "--plugins-detection", "aggressive",
        ],
        timeout_sec=600,
        requires_url=True,
        notes="Enumerates vulnerable plugins/themes, timthumbs, config backups, db exports, users. Only meaningful if target runs WordPress.",
    ),
    ToolSpec(
        key="httpx",
        binary="httpx",
        display_name="httpx HTTP Probe & Tech Stack",
        category=Category.WEB,
        cmd_template=[
            "httpx", "-u", "{url}", "-title", "-tech-detect", "-status-code",
            "-web-server", "-content-length", "-follow-redirects", "-silent",
        ],
        timeout_sec=60,
        requires_url=True,
        notes="ProjectDiscovery — fast tech/header/status fingerprint, cheap to run before the heavier crawlers.",
    ),
    ToolSpec(
        key="katana",
        binary="katana",
        display_name="Katana Deep Web Crawler",
        category=Category.WEB,
        cmd_template=[
            "katana", "-u", "{url}", "-depth", "3", "-jc", "-silent",
        ],
        timeout_sec=600,
        requires_url=True,
        notes="ProjectDiscovery — JS-aware crawler, surfaces endpoints gobuster/ffuf wordlists would miss.",
    ),
    ToolSpec(
        key="gau",
        binary="gau",
        display_name="GAU Historical URL Enumeration",
        category=Category.WEB,
        cmd_template=["gau", "--threads", "5", "{host}"],
        timeout_sec=180,
        notes="Pulls known URLs from Wayback Machine/OTX/CommonCrawl — passive, no requests hit the target directly.",
    ),

    # ---------------- TLS ----------------
    ToolSpec(
        key="sslscan",
        binary="sslscan",
        display_name="SSLScan Cipher/Protocol Audit",
        category=Category.TLS,
        cmd_template=["sslscan", "{host}"],
        timeout_sec=90,
    ),
    ToolSpec(
        key="testssl",
        binary="testssl.sh",
        display_name="testssl.sh Full TLS Audit",
        category=Category.TLS,
        cmd_template=["testssl.sh", "--full", "--color", "0", "{host}"],
        timeout_sec=900,
        notes="--full runs every check (protocols, ciphers, vulns like Heartbleed/ROBOT/BEAST, cert chain, HSTS) instead of the quick subset.",
    ),

    # ---------------- NETSVC ----------------
    ToolSpec(
        key="enum4linux",
        binary="enum4linux",
        display_name="enum4linux SMB/NetBIOS Enumeration",
        category=Category.NETSVC,
        cmd_template=["enum4linux", "-a", "{host}"],
        timeout_sec=180,
    ),
    ToolSpec(
        key="snmpwalk",
        binary="snmpwalk",
        display_name="SNMP Walk (public community)",
        category=Category.NETSVC,
        cmd_template=["snmpwalk", "-v2c", "-c", "public", "{host}"],
        timeout_sec=60,
    ),

    # ---------------- VULN ----------------
    ToolSpec(
        key="nuclei",
        binary="nuclei",
        display_name="Nuclei Full Template Vulnerability Scan",
        category=Category.VULN,
        cmd_template=[
            "nuclei", "-u", "{url}",
            "-severity", "info,low,medium,high,critical",
            "-tags", "cve,exposure,misconfig,tech,default-login,takeover,exposed-panel",
            "-silent",
        ],
        timeout_sec=1200,
        requires_url=True,
        notes="Every severity + broad tag set instead of the medium+ subset. Requires `nuclei -update-templates` run beforehand.",
    ),

    # ---------------- WEB3 ----------------
    ToolSpec(
        key="web3_rpc_probe",
        binary="curl",
        display_name="Web3 JSON-RPC Exposure Probe",
        category=Category.VULN,
        cmd_template=[
            "curl", "-s", "-m", "8", "-X", "POST",
            "-H", "Content-Type: application/json",
            "--data", '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}',
            "{url}:8545",
        ],
        timeout_sec=15,
        notes=(
            "Checks for an unauthenticated Ethereum/EVM JSON-RPC node on :8545 — a real, "
            "common misconfiguration (exposed node = wallet drain / chain data leak risk). "
            "A JSON response containing 'result' means the RPC is open to anyone. "
            "For actual smart contract source/bytecode auditing (reentrancy, overflow, access "
            "control bugs), that's a separate offline workflow — see README for slither/mythril."
        ),
    ),
]


def get_tool(key: str) -> ToolSpec:
    for t in TOOLS:
        if t.key == key:
            return t
    raise KeyError(f"Unknown tool key: {key}")


def all_keys() -> list[str]:
    return [t.key for t in TOOLS]
