"""
SML Scanner - Orchestrator
=============================
Coordinates execution of the tool suite against a single target and hands
results to the report generator. Designed to run on Arch/CachyOS or Kali
with tools pre-installed (see README for package lists).
"""

import argparse
import concurrent.futures
import datetime
import sys
from pathlib import Path

from .tools_config import TOOLS, get_tool, all_keys
from .utils import run_tool, normalize_target, ExecResult
from .report_generator import build_report


def confirm_authorization(target: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    print(f"\n[!] You are about to run an active scan suite against: {target}")
    print("[!] Only proceed if you own this target or hold explicit written")
    print("    authorization to test it. Unauthorized scanning may be illegal.")
    reply = input("Type 'yes' to confirm authorization and continue: ").strip().lower()
    return reply == "yes"


def build_argv(tool_key: str, target_info: dict, outdir: Path) -> list[str] | None:
    spec = get_tool(tool_key)
    if spec.requires_url:
        fmt_target = target_info["url"]
    else:
        fmt_target = target_info["host"]

    argv = []
    for token in spec.cmd_template:
        token = token.replace("{host}", target_info["host"])
        token = token.replace("{url}", target_info["url"])
        token = token.replace("{target}", fmt_target)
        token = token.replace("{outdir}", str(outdir))
        argv.append(token)
    return argv


def run_suite(
    raw_target: str,
    selected_keys: list[str],
    outdir: Path,
    max_workers: int = 4,
    progress_cb=None,
) -> list[ExecResult]:
    """Run selected tools with bounded parallelism. Heavy long scans (nmap full
    range, nikto, testssl) naturally serialize behind the worker pool cap."""
    target_info = normalize_target(raw_target)
    outdir.mkdir(parents=True, exist_ok=True)
    raw_log_dir = outdir / "raw_logs"
    raw_log_dir.mkdir(exist_ok=True)

    results: list[ExecResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {}
        for key in selected_keys:
            spec = get_tool(key)
            argv = build_argv(key, target_info, outdir)
            fut = pool.submit(run_tool, key, spec.display_name, argv, spec.timeout_sec)
            futures[fut] = spec

        for fut in concurrent.futures.as_completed(futures):
            spec = futures[fut]
            result = fut.result()
            results.append(result)
            (raw_log_dir / f"{spec.key}.log").write_text(
                f"COMMAND: {result.command}\nSTATUS: {result.status}\n"
                f"RETURNCODE: {result.returncode}\nDURATION: {result.duration_sec:.2f}s\n"
                f"--- STDOUT ---\n{result.stdout}\n--- STDERR ---\n{result.stderr}\n"
            )
            if progress_cb:
                progress_cb(result)

    # preserve declared TOOLS order in the final report rather than completion order
    order = {k: i for i, k in enumerate(selected_keys)}
    results.sort(key=lambda r: order.get(r.tool_key, 999))
    return results


def main():
    parser = argparse.ArgumentParser(
        description="SML Scanner - multi-tool recon/vuln aggregator with PDF reporting.",
    )
    parser.add_argument("target", help="Target host, IP, or URL (e.g. 192.168.1.10 or https://target.lab)")
    parser.add_argument(
        "-o", "--outdir", default=None,
        help="Output directory (default: ./sml_reports/<target>_<timestamp>/)",
    )
    parser.add_argument(
        "-t", "--tools", default="all",
        help=f"Comma-separated tool keys to run, or 'all'. Available: {', '.join(all_keys())}",
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=4,
        help="Max concurrent tools (default 4). Lower this on constrained hardware.",
    )
    parser.add_argument("-y", "--yes", action="store_true", help="Skip interactive authorization prompt.")
    parser.add_argument("--operator", default="SML Scanner", help="Name/handle recorded in the report.")
    args = parser.parse_args()

    if not confirm_authorization(args.target, args.yes):
        print("[-] Authorization not confirmed. Aborting.")
        sys.exit(1)

    selected_keys = all_keys() if args.tools == "all" else [k.strip() for k in args.tools.split(",")]
    invalid = [k for k in selected_keys if k not in all_keys()]
    if invalid:
        print(f"[-] Unknown tool key(s): {invalid}")
        print(f"    Available: {', '.join(all_keys())}")
        sys.exit(1)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = args.target.replace("://", "_").replace("/", "_").replace(":", "_")
    outdir = Path(args.outdir) if args.outdir else Path(f"./sml_reports/{safe_target}_{ts}")

    print(f"[*] Target: {args.target}")
    print(f"[*] Running {len(selected_keys)} tool(s) with up to {args.workers} in parallel...")
    print(f"[*] Output directory: {outdir}\n")

    def progress(result: ExecResult):
        icon = {"ok": "[+]", "timeout": "[~]", "missing_binary": "[.]", "error": "[-]"}[result.status]
        print(f"{icon} {result.display_name:<45} {result.status:<15} {result.duration_sec:6.1f}s")

    scan_started = datetime.datetime.now()
    results = run_suite(args.target, selected_keys, outdir, max_workers=args.workers, progress_cb=progress)
    scan_finished = datetime.datetime.now()

    pdf_path = outdir / f"sml_report_{safe_target}_{ts}.pdf"
    build_report(
        target=args.target,
        results=results,
        output_path=str(pdf_path),
        scan_started=scan_started,
        scan_finished=scan_finished,
        operator=args.operator,
    )

    ok_count = sum(1 for r in results if r.status == "ok")
    skipped = sum(1 for r in results if r.status == "missing_binary")
    print(f"\n[*] Done. {ok_count}/{len(results)} tools completed, {skipped} skipped (not installed).")
    print(f"[*] PDF report: {pdf_path}")
    print(f"[*] Raw logs:   {outdir / 'raw_logs'}")


if __name__ == "__main__":
    main()
