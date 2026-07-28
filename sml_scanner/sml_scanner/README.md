# SML Scanner

Multi-tool recon/vulnerability scan aggregator. Runs ~18 industry-standard
scanning tools against a single target, captures output, and compiles a
structured PDF report. Built for authorized lab/CTF use — the SML Pentesting
Arsenal, Pillar C.

## Scope decision

This build wraps **reconnaissance and vulnerability-detection** tools only
(port/service discovery, web/DNS/TLS/SMB/SNMP enumeration, template-based CVE
matching). It deliberately excludes active exploitation and credential
brute-force tools (sqlmap in attack mode, hydra, metasploit modules). That
keeps the tool legally and ethically clean to run against anything you own or
are authorized to test, and gives you a stable base to extend later if you
add an explicit "authorized exploitation" module with its own consent gate.

## Install (CachyOS / Arch)

```bash
# Core repos
sudo pacman -S nmap masscan whois bind gnu-netcat openssl \
                nikto sslscan enum4linux net-snmp

# AUR (use paru/yay)
paru -S whatweb dnsrecon theharvester amass gobuster ffuf \
        wpscan testssl.sh-git nuclei seclists

# nuclei needs its template repo pulled once
nuclei -update-templates
```

Any tool not installed is auto-skipped (reported as "Skipped" in the PDF,
not a crash) — you don't need all 18 to run the suite.

## Setup

```bash
cd sml_scanner
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Full suite, interactive authorization prompt
python3 -m sml.scanner 192.168.56.10

# Full suite against a web target, skip prompt (you've already confirmed authorization)
python3 -m sml.scanner https://target.lab -y

# Only run specific tools
python3 -m sml.scanner 192.168.56.10 -t nmap_tcp,whatweb,nikto,nuclei -y

# Lower concurrency on constrained hardware (e.g. testing from the Poco X6 Pro over Termux)
python3 -m sml.scanner 192.168.56.10 -y -w 2

# Custom output dir + operator name for the report
python3 -m sml.scanner 192.168.56.10 -y -o ./reports/run1 --operator "ED"
```

List all tool keys:
```bash
python3 -m sml.scanner --help
```

## Output

```
sml_reports/<target>_<timestamp>/
├── sml_report_<target>_<timestamp>.pdf   # the report
└── raw_logs/
    ├── nmap_tcp.log                       # full stdout/stderr per tool
    ├── whatweb.log
    └── ...
```

The PDF has: cover page (target, timing, operator) → executive summary table
(every tool + status at a glance) → per-category sections with full captured
output (truncated at 6000 chars/tool to keep file size sane — full output
always in `raw_logs/`).

## Architecture

```
sml/
├── tools_config.py    # tool registry — add new tools here only
├── utils.py            # subprocess execution, timeout handling, target parsing
├── scanner.py           # orchestrator: parallel execution, CLI
└── report_generator.py  # reportlab PDF rendering
```

## Extending: adding a new tool

Add a `ToolSpec` entry to `sml/tools_config.py`. Nothing else needs to
change — the orchestrator, parallel runner, and PDF report all pick it up
automatically via the registry.

```python
ToolSpec(
    key="mytool",
    binary="mytool",
    display_name="My Custom Tool",
    category=Category.VULN,
    cmd_template=["mytool", "--target", "{host}", "--fast"],
    timeout_sec=120,
    requires_url=False,
)
```

## Design notes

- **No `shell=True` anywhere** — every command runs as an argv list, so
  target strings can never break out into shell injection.
- **Bounded parallelism** (`ThreadPoolExecutor`, default 4 workers) — tune
  `-w` down on the Poco X6 Pro / constrained hardware; tune up on your
  Windows/CachyOS dev boxes.
- **Every failure mode is captured, never crashes the run**: missing binary,
  timeout, non-zero exit, and unexpected exception all degrade to a labeled
  section in the report instead of aborting the whole scan.
- **Authorization gate is in the code path**, not just documentation — `-y`
  is required to skip the interactive confirmation, so accidental scans
  against the wrong host require a conscious flag.

## Roadmap fit (from your blueprint)

- Rust rewrite candidate: `utils.py`'s subprocess runner + `scanner.py`'s
  concurrency layer are the natural first port — a `tokio`-based async
  runner would let you scale worker count much higher for the CAT6
  air-gapped lab without Python's GIL/thread overhead. `tools_config.py`
  stays as a declarative registry (could become a TOML file consumed by
  both the Python and Rust versions).
- Agathiyan AI hook: feed `raw_logs/*.log` into a local Ollama call
  (`agathiyan_model`) as a post-scan pass to auto-summarize findings in
  Tamil before/alongside the PDF — natural next feature once the base
  pipeline is stable on your testbed.
