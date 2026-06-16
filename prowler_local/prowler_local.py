#!/usr/bin/env python3
"""
prowler_local.py — Local Prowler. All 608 AWS checks, zero installation, 100% local.

Embeds Prowler's check source code (github.com/prowler-cloud/prowler)
and runs it with a minimal boto3 provider shim. No prowler package needed.

Usage:
  python prowler_local.py scan --profile my-sso-profile
  python prowler_local.py scan --config accounts.json
  python prowler_local.py dashboard
  python prowler_local.py list-checks --service iam
"""
from __future__ import annotations
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import click

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from rich.console import Console
    from rich.table   import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    console  = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    console  = None


def log(msg, style="white"):
    if HAS_RICH:
        console.print(f"[{style}]{msg}[/]")
    else:
        print(msg)


def load_accounts(config_path: str) -> tuple:
    if not os.path.exists(config_path):
        return [], "eu-west-1"
    with open(config_path, encoding="utf-8") as f:
        cfg = json.load(f)
    default_regions = cfg.get("default_regions", ["eu-west-1"])
    accounts = []
    for entry in cfg.get("accounts", []):
        accounts.append({
            "id":      str(entry["id"]),
            "name":    str(entry["name"]),
            "profile": str(entry.get("profile", entry.get("sso_profile", ""))),
            "regions": entry.get("regions", default_regions),
            "skip":    entry.get("skip", False),
        })
    return accounts, default_regions


@click.group()
def cli():
    """🔐 Prowler Local — 608 AWS checks, 100% local, based on Prowler GitHub source."""
    pass


@cli.command()
@click.option("--config",       default="accounts.json",
              help="Path to accounts.json")
@click.option("--profile",      default=None,
              help="Single AWS SSO profile (bypasses accounts.json)")
@click.option("--account-id",   default="unknown",
              help="Account ID when using --profile")
@click.option("--account-name", default=None,
              help="Account name when using --profile")
@click.option("--regions",      default="eu-west-1",
              help="Comma-separated regions (e.g. eu-west-1,eu-west-3)")
@click.option("--services",     default=None,
              help="Comma-separated services to run (e.g. iam,s3,cloudtrail)")
@click.option("--skip",         default=None,
              help="Comma-separated check IDs to skip")
@click.option("--output",       default="./output",
              help="Output directory for CSV results")
@click.option("--workers",      default=3, type=int,
              help="Parallel account workers (default: 3)")
@click.option("--fail-only",    is_flag=True,
              help="Only export FAIL/WARNING results")
@click.option("--auditor",      default=os.environ.get("USERNAME","unknown"))
def scan(config, profile, account_id, account_name, regions, services,
         skip, output, workers, fail_only, auditor):
    """Run all 608 Prowler checks against AWS accounts."""
    from run_checks import run_account, save_csv, discover_checks

    regions_list  = [r.strip() for r in regions.split(",")]
    services_list = [s.strip() for s in services.split(",")] if services else None
    skip_list     = [s.strip() for s in skip.split(",")]     if skip     else []

    # Build account list
    if profile:
        accounts = [{
            "id":      account_id,
            "name":    account_name or profile,
            "profile": profile,
            "regions": regions_list,
            "skip":    False,
        }]
    else:
        accounts, default_regions = load_accounts(config)
        if not accounts:
            log(f"No accounts in {config}. Use --profile for a single account.", "yellow")
            sys.exit(1)

    active = [a for a in accounts if not a.get("skip")]

    # Count checks to run
    checks = discover_checks(services_filter=services_list)

    log(f"\n{'='*60}", "cyan")
    log(f"  🔐 Prowler Local", "bold white")
    log(f"  Source   : github.com/prowler-cloud/prowler (embedded)", "white")
    log(f"  Accounts : {len(active)}", "white")
    log(f"  Regions  : {', '.join(regions_list)}", "white")
    log(f"  Checks   : {len(checks)}", "white")
    log(f"  Services : {services or 'all (83)'}", "white")
    log(f"  Auditor  : {auditor}", "white")
    log(f"{'='*60}\n", "cyan")

    os.makedirs(output, exist_ok=True)
    all_rows = []
    start    = time.time()

    def scan_one(acc):
        return run_account(
            account_id   = acc["id"],
            account_name = acc["name"],
            profile      = acc.get("profile") or None,
            regions      = acc.get("regions", regions_list),
            services     = services_list,
            skip_checks  = skip_list,
            log_fn       = log,
        )

    if len(active) == 1:
        # Single account - no threading needed
        acc = active[0]
        log(f"  → {acc['name']} ({acc['id']})", "cyan")
        rows = scan_one(acc)
        if fail_only:
            rows = [r for r in rows if r.get("STATUS") in ("FAIL","WARNING")]
        all_rows.extend(rows)
    else:
        with ThreadPoolExecutor(max_workers=min(workers, len(active))) as ex:
            futures = {ex.submit(scan_one, acc): acc for acc in active}
            for fut in as_completed(futures):
                acc = futures[fut]
                try:
                    rows = fut.result()
                    if fail_only:
                        rows = [r for r in rows if r.get("STATUS") in ("FAIL","WARNING")]
                    all_rows.extend(rows)
                    fails = sum(1 for r in rows if r.get("STATUS") == "FAIL")
                    log(f"  ✓ {acc['name']}: {len(rows)} findings, {fails} failures", "green")
                except Exception as e:
                    log(f"  ✗ {acc['name']}: {e}", "red")

    # Save
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    csv_path  = os.path.join(output, f"prowler_{timestamp}.csv")
    save_csv(all_rows, csv_path)
    elapsed = time.time() - start

    total  = len(all_rows)
    passes = sum(1 for r in all_rows if r.get("STATUS") == "PASS")
    fails  = sum(1 for r in all_rows if r.get("STATUS") == "FAIL")
    crits  = sum(1 for r in all_rows if r.get("STATUS") == "FAIL"
                 and r.get("SEVERITY") == "critical")

    log(f"\n{'='*60}", "cyan")
    log(f"  Total findings : {total}", "white")
    log(f"  PASS           : {passes}", "green")
    log(f"  FAIL           : {fails}", "red")
    log(f"  Critical FAILs : {crits}", "bold red")
    log(f"  Elapsed        : {elapsed:.1f}s", "white")
    log(f"\n  Output → {csv_path}", "green")
    log(f"  Dashboard → python prowler_local.py dashboard", "cyan")
    log(f"{'='*60}\n", "cyan")

    sys.exit(1 if crits > 0 else 0)


@cli.command()
@click.option("--port",   default=8050, type=int)
@click.option("--debug",  is_flag=True)
@click.option("--output", default="./output",
              help="Folder with CSV results")
def dashboard(port, debug, output):
    """Launch local Dash dashboard to explore findings."""
    os.environ["PROWLER_OUTPUT"] = os.path.abspath(output)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    # Import and run the dashboard app
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "dashboard_app",
        os.path.join(os.path.dirname(__file__), "dashboard_app.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.run_dashboard(port=port, debug=debug)


@cli.command("list-checks")
@click.option("--service",   default=None, help="Filter by service")
@click.option("--severity",  default=None, help="Filter by severity")
@click.option("--as-json",   is_flag=True, help="Output as JSON")
def list_checks(service, severity, as_json):
    """List all available checks from embedded Prowler catalog."""
    from run_checks import discover_checks
    import json

    svc_filter = [service] if service else None
    checks = discover_checks(services_filter=svc_filter)

    if severity:
        checks = [c for c in checks
                  if c["metadata"].get("Severity","").lower() == severity.lower()]

    if as_json:
        print(json.dumps([
            {"check_id": c["check_id"],
             "title":    c["metadata"].get("CheckTitle",""),
             "service":  c["service"],
             "severity": c["metadata"].get("Severity","")}
            for c in checks
        ], indent=2))
        return

    if HAS_RICH:
        t = Table(show_header=True, header_style="bold cyan")
        t.add_column("Check ID",   style="cyan",   no_wrap=True, max_width=55)
        t.add_column("Service",    style="yellow",  max_width=20)
        t.add_column("Severity",   max_width=12)
        t.add_column("Title",      max_width=50)
        sev_map = {"critical":"bold red","high":"red","medium":"yellow","low":"green"}
        for c in checks:
            sev = c["metadata"].get("Severity","")
            t.add_row(
                c["check_id"],
                c["service"],
                f"[{sev_map.get(sev,'white')}]{sev}[/]",
                c["metadata"].get("CheckTitle","")[:50],
            )
        console.print(t)
        console.print(f"\n[cyan]{len(checks)} checks available[/]")
    else:
        for c in checks:
            sev = c["metadata"].get("Severity","")
            title = c["metadata"].get("CheckTitle","")[:50]
            print(f"{c['check_id']:55s} {c['service']:20s} {sev:12s} {title}")
        print(f"\n{len(checks)} checks available")


@cli.command("summary")
def summary():
    """Show check counts by service and severity."""
    from run_checks import discover_checks
    checks = discover_checks()

    by_svc = {}
    by_sev = {}
    for c in checks:
        s = c["service"]
        v = c["metadata"].get("Severity","")
        by_svc[s] = by_svc.get(s, 0) + 1
        by_sev[v] = by_sev.get(v, 0) + 1

    log(f"\nTotal: {len(checks)} checks across {len(by_svc)} services", "bold white")
    log("\nBy severity:", "cyan")
    for sev in ["critical","high","medium","low","informational"]:
        log(f"  {sev:15s}: {by_sev.get(sev, 0)}")
    log("\nTop services:", "cyan")
    for svc, count in sorted(by_svc.items(), key=lambda x: -x[1])[:20]:
        log(f"  {svc:30s}: {count}")


if __name__ == "__main__":
    cli()
