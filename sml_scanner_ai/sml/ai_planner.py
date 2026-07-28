"""
SML Scanner - AI Adaptive Planner
====================================
Runs a fast triage probe (nmap top-1000 + httpx + whois/dig), feeds the
findings to a small local LLM via Ollama, and gets back a tailored list of
which of the remaining tools are actually worth running against THIS
target — instead of blindly firing all 22.

Model: qwen3:0.6b (or any small instruct model you point it at). At Q4_K_M
quantization this is roughly 400-500MB, fits your <700MB budget, and Qwen3
was specifically trained for agentic/tool-selection tasks, which is exactly
this job.

    ollama pull qwen3:0.6b

Falls back to a conservative default tool set if Ollama is unreachable or
the model output can't be parsed — the scan never silently does nothing.
"""

import json
import re
import urllib.request
import urllib.error

from .tools_config import TOOLS, Category, get_tool, all_keys

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "qwen3:0.6b"

# Tools always excluded from AI selection — either they ARE the triage
# phase itself, or they're cheap/passive enough to always be worth running.
ALWAYS_RUN = ["whois", "dig", "httpx"]
TRIAGE_ONLY = ["nmap_quick"]

# Safe fallback if the model/Ollama is unavailable — mirrors what a careful
# human would pick without any target-specific info: broad but not wasteful.
FALLBACK_TOOLS = [
    "dnsrecon", "nmap_tcp", "whatweb", "nikto", "gobuster",
    "nuclei", "sslscan", "testssl",
]


def _catalog_text() -> str:
    """Build the tool catalog description fed to the model, excluding
    triage-phase and always-run tools since those aren't the model's
    decision to make."""
    lines = []
    for t in TOOLS:
        if t.key in ALWAYS_RUN or t.key in TRIAGE_ONLY:
            continue
        hint = t.planner_hint or t.notes or t.display_name
        lines.append(f"- {t.key} [{t.category.value}]: {hint}")
    return "\n".join(lines)


def _build_prompt(triage_summary: str) -> str:
    return f"""You are a security scan planner. Given triage results for a
target, select which tools from the catalog below are worth running.
Only pick tools relevant to what was actually found — e.g. don't pick
enum4linux if SMB port 445 wasn't seen open, don't pick wpscan unless
something suggests WordPress, don't pick web3_rpc_probe unless port 8545
or blockchain-related signals appear, don't pick UDP/SNMP tools against a
plain web target.

TRIAGE RESULTS:
{triage_summary}

TOOL CATALOG:
{_catalog_text()}

Respond with ONLY a JSON array of tool key strings, nothing else. Example:
["nmap_tcp","whatweb","nikto","nuclei"]"""


def _extract_json_array(text: str) -> list:
    """Model output may include stray text/markdown fences; pull out the
    first [...] array found."""
    match = re.search(r"\[.*?\]", text, re.DOTALL)
    if not match:
        raise ValueError("no JSON array found in model output")
    return json.loads(match.group(0))


def query_ollama(prompt: str, model: str, timeout_sec: int = 60) -> str:
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1},
    }).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_URL, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return body.get("response", "")


def summarize_triage(triage_results: dict) -> str:
    """triage_results: {tool_key: ExecResult}. Build a compact plain-text
    summary — small models do better with less noise than raw tool dumps."""
    parts = []
    for key, result in triage_results.items():
        if result.status != "ok":
            parts.append(f"[{key}] {result.status}")
            continue
        out = (result.stdout or "").strip()
        # cap per-tool excerpt so the prompt stays small for a 0.6B model
        excerpt = out[:1500]
        parts.append(f"[{key}]\n{excerpt}")
    return "\n\n".join(parts)


def plan_tools(triage_results: dict, model: str = DEFAULT_MODEL) -> tuple[list[str], str]:
    """Returns (selected_tool_keys, reasoning_note_for_report).
    Never raises — degrades to FALLBACK_TOOLS on any failure."""
    summary = summarize_triage(triage_results)
    prompt = _build_prompt(summary)

    try:
        raw = query_ollama(prompt, model)
        keys = _extract_json_array(raw)
        valid_keys = [k for k in keys if isinstance(k, str) and k in all_keys()
                      and k not in ALWAYS_RUN and k not in TRIAGE_ONLY]
        if not valid_keys:
            raise ValueError("model returned no valid/usable tool keys")
        note = f"AI planner ({model}) selected {len(valid_keys)} tool(s) based on triage: {', '.join(valid_keys)}"
        return valid_keys, note
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError, OSError) as e:
        note = (
            f"AI planner unavailable or returned unusable output ({e!r}) — "
            f"fell back to default tool set: {', '.join(FALLBACK_TOOLS)}"
        )
        return list(FALLBACK_TOOLS), note
