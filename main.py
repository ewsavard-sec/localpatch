"""
main.py — Entry point for LocalPatch.

Usage:
    python main.py                     Launch the GUI
    python main.py --scan              Run a scan (no GUI), update state, exit
    python main.py --auto              Scan, then deploy anything past the
                                        delay window, exit. This is what the
                                        scheduled task calls.
    python main.py --setup-schedule    Register the daily scheduled task
    python main.py --remove-schedule   Remove the daily scheduled task
"""

import argparse
import json
from pathlib import Path

import state
import scanner
import cve_matcher
import deployer
import scheduler
import patch_store

CONFIG_PATH = Path(__file__).parent / "config.json"
CONFIG_EXAMPLE_PATH = Path(__file__).parent / "config.example.json"

DEFAULT_CONFIG = {
    "delay_days": 7,
    "auto_run_enabled": False,
    "run_time": "09:00",
    "nvd_api_key": "",
    "retention_days": 180,
}


def load_config():
    if not CONFIG_PATH.exists() and CONFIG_EXAMPLE_PATH.exists():
        CONFIG_PATH.write_text(CONFIG_EXAMPLE_PATH.read_text())
    if CONFIG_PATH.exists():
        return {**DEFAULT_CONFIG, **json.loads(CONFIG_PATH.read_text())}
    return dict(DEFAULT_CONFIG)


def run_scan(cfg):
    state.init_db()
    installed = {a["Id"]: a for a in scanner.scan_installed()}
    upgrades = {a["Id"]: a for a in scanner.scan_upgrades()}
    matcher = cve_matcher.CveMatcher(api_key=cfg.get("nvd_api_key") or None)

    for pkg_id, app in installed.items():
        available = upgrades.get(pkg_id, {}).get("Available")
        state.upsert_app(
            package_id=pkg_id, name=app["Name"], source=app.get("Source", ""),
            installed_version=app["Version"], available_version=available,
        )
        cves = matcher.lookup(app["Name"], app["Version"])
        state.set_cves(pkg_id, cves)

    print(f"Scanned {len(installed)} apps, {len(upgrades)} updates available.")


def run_auto(cfg):
    run_scan(cfg)
    eligible = state.get_eligible_for_autodeploy(cfg["delay_days"])
    print(f"{len(eligible)} update(s) past the {cfg['delay_days']}-day delay window.")
    for app in eligible:
        package_id, version = app["package_id"], app["available_version"]
        result = patch_store.verify_and_record(package_id, version, cfg)
        if not result.verified:
            state.mark_deployed(package_id, version, success=False)
            print(f"  {app['name']}: BLOCKED — failed verification ({result.reason})")
            continue
        success, log = deployer.deploy(package_id)
        state.mark_deployed(package_id, version, success)
        print(f"  {app['name']}: {'OK' if success else 'FAILED'}")

    run_purge(cfg)


def run_purge(cfg):
    summary = patch_store.purge_expired(cfg.get("retention_days", 180))
    print(f"Purged {summary['count']} cached patch(es), freed {summary['bytes_freed']} bytes.")
    for item in summary["purged"]:
        print(f"  {item['package_id']} {item['version']} (age {item['age_days']} days)")


def main():
    parser = argparse.ArgumentParser(description="LocalPatch — local patch manager")
    parser.add_argument("--scan", action="store_true", help="Run a scan only")
    parser.add_argument("--auto", action="store_true", help="Scan + auto-deploy eligible updates")
    parser.add_argument("--setup-schedule", action="store_true")
    parser.add_argument("--remove-schedule", action="store_true")
    parser.add_argument("--purge", action="store_true", help="Delete cached patches older than retention_days")
    args = parser.parse_args()

    cfg = load_config()

    if args.setup_schedule:
        scheduler.enable(cfg.get("run_time", "09:00"))
        print("Scheduled task created.")
    elif args.remove_schedule:
        scheduler.disable()
        print("Scheduled task removed.")
    elif args.purge:
        state.init_db()
        run_purge(cfg)
    elif args.scan:
        run_scan(cfg)
    elif args.auto:
        run_auto(cfg)
    else:
        import gui
        gui.main()


if __name__ == "__main__":
    main()
