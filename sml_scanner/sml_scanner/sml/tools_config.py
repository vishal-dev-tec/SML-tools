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
        key="nmap_tcp",
        binary="nmap",
        display_name="Nmap TCP Service/Version Scan",
        category=Category.PORTSCAN,
        cmd_template=["nmap", "-sV", "-sC", "-T4", "-p-", "--open", "{host}"],
        timeout_sec=900,
        notes="Full port range, default scripts, version detection.",
    ),
    ToolSpec(
        key="nmap_udp",
        binary="nmap",
        display_name="Nmap Top-100 UDP Scan",
        category=Category.PORTSCAN,
        cmd_template=["nmap", "-sU", "--top-ports", "100", "-T4", "{host}"],
        timeout_sec=600,
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
        cmd_template=["whatweb", "-a", "3", "{url}"],
        timeout_sec=60,
        requires_url=True,
    ),
    ToolSpec(
        key="nikto",
        binary="nikto",
        display_name="Nikto Web Vulnerability Scan",
        category=Category.WEB,
        cmd_template=["nikto", "-h", "{url}"],
        timeout_sec=600,
        requires_url=True,
    ),
    ToolSpec(
        key="gobuster",
        binary="gobuster",
        display_name="Gobuster Directory/File Brute-force",
        category=Category.WEB,
        cmd_template=[
            "gobuster", "dir", "-u", "{url}",
            "-w", "/usr/share/wordlists/dirb/common.txt",
            "-q", "-t", "40",
        ],
        timeout_sec=300,
        requires_url=True,
        notes="Wordlist path assumes seclists/dirb installed.",
    ),
    ToolSpec(
        key="ffuf",
        binary="ffuf",
        display_name="ffuf Web Fuzzer",
        category=Category.WEB,
        cmd_template=[
            "ffuf", "-u", "{url}/FUZZ",
            "-w", "/usr/share/wordlists/dirb/common.txt",
            "-of", "json", "-o", "{outdir}/ffuf.json", "-s",
        ],
        timeout_sec=300,
        requires_url=True,
    ),
    ToolSpec(
        key="wpscan",
        binary="wpscan",
        display_name="WPScan WordPress Audit",
        category=Category.WEB,
        cmd_template=["wpscan", "--url", "{url}", "--no-banner", "--random-user-agent"],
        timeout_sec=300,
        requires_url=True,
        notes="Only meaningful if target runs WordPress; harmless no-op otherwise.",
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
        display_name="testssl.sh Deep TLS Audit",
        category=Category.TLS,
        cmd_template=["testssl.sh", "--quiet", "--color", "0", "{host}"],
        timeout_sec=300,
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
        display_name="Nuclei Template-Based Vulnerability Scan",
        category=Category.VULN,
        cmd_template=["nuclei", "-u", "{url}", "-severity", "low,medium,high,critical", "-silent"],
        timeout_sec=600,
        requires_url=True,
        notes="Requires `nuclei -update-templates` run beforehand.",
    ),
]


def get_tool(key: str) -> ToolSpec:
    for t in TOOLS:
        if t.key == key:
            return t
    raise KeyError(f"Unknown tool key: {key}")


def all_keys() -> list[str]:
    return [t.key for t in TOOLS]
