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
import traceback
from pathlib import Path

import state
import scanner
import cve_matcher
import deployer
import scheduler
import patch_store
import app_log
import notifier

CONFIG_PATH = Path(__file__).parent / "config.json"
CONFIG_EXAMPLE_PATH = Path(__file__).parent / "config.example.json"

DEFAULT_CONFIG = {
    "delay_days": 7,
    "auto_run_enabled": False,
    "run_time": "09:00",
    "nvd_api_key": "",
    "retention_days": 180,
    "notify_new_cves": True,
    # Defaults to False: when `winget download` can't be used, patch_store
    # falls back to trusting winget's own manifest-reported hash instead
    # of independently downloading and hashing a file. That's a real, but
    # materially weaker, guarantee -- see patch_store._fallback_manifest_only.
    # Leave this off unless you've accepted that tradeoff explicitly.
    "allow_manifest_only_verification": False,
    # Mirrors patch_store.verify_and_record's own default -- kept True so a
    # fresh install (or a config.json predating this key) is at least as
    # strict as patch_store's fallback, not silently weaker than it.
    "require_valid_signature": True,
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
    # Snapshot pre-scan CVE state once, up front -- diffed per-app below so
    # a notification only fires for genuinely new CVEs, not the same known
    # one every scan.
    prev_apps_by_id = {a["package_id"]: a for a in state.get_all_apps()}
    matcher = cve_matcher.CveMatcher(api_key=cfg.get("nvd_api_key") or None)

    for pkg_id, app in installed.items():
        available = upgrades.get(pkg_id, {}).get("Available")
        release_date = None
        if available:
            # scanner.get_release_date() is a `winget show` subprocess call
            # per package -- if the prior scan already saw this exact
            # available_version and recorded a non-empty release_date for
            # it, that date is still correct (a version's release date
            # doesn't change), so reuse it instead of re-shelling out to
            # winget for a result we already know.
            prev = prev_apps_by_id.get(pkg_id) or {}
            if prev.get("available_version") == available and prev.get("release_date"):
                release_date = prev["release_date"]
            else:
                release_date = scanner.get_release_date(pkg_id, available)
        state.upsert_app(
            package_id=pkg_id, name=app["Name"], source=app.get("Source", ""),
            installed_version=app["Version"], available_version=available,
            release_date=release_date,
        )
        cves = matcher.lookup(app["Name"], app["Version"])
        if cfg.get("notify_new_cves", True):
            prev_cves = json.loads((prev_apps_by_id.get(pkg_id) or {}).get("cves") or "[]")
            new_cves = notifier.diff_new_cves(prev_cves, cves)
            if new_cves:
                notifier.notify_new_cves(app["Name"], new_cves)
        state.set_cves(pkg_id, cves)

    print(f"Scanned {len(installed)} apps, {len(upgrades)} updates available.")


def run_auto(cfg):
    run_scan(cfg)
    eligible = state.get_eligible_for_autodeploy(cfg["delay_days"])
    print(f"{len(eligible)} update(s) past the {cfg['delay_days']}-day delay window.")
    for app in eligible:
        package_id, version = app["package_id"], app["available_version"]
        name = app["name"]
        try:
            result = patch_store.verify_and_record(package_id, version, cfg)
            if not result.verified:
                state.mark_deployed(package_id, version, success=False)
                app_log.warning(f"Blocked deploy: {name} {version} -- {result.reason}")
                print(f"  {name}: BLOCKED — failed verification ({result.reason})")
                continue
            success, log = deployer.deploy(package_id, version)
            state.mark_deployed(package_id, version, success)
            if success:
                app_log.info(f"Deployed: {name} {version}")
            else:
                app_log.error(f"Deploy failed: {name} {version} -- winget output: {log.strip()[-1000:]}")
            print(f"  {name}: {'OK' if success else 'FAILED'}")
        except Exception as e:
            state.mark_deployed(package_id, version, success=False)
            app_log.error(f"Unexpected error deploying {name} {version}: {e}\n{traceback.format_exc()}")
            print(f"  {name}: ERROR — {e} (see localpatch.log)")

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

    try:
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
    except Exception as e:
        # Logged in addition to the normal traceback so an unattended
        # scheduled run (nobody watching the console) still leaves a record.
        app_log.error(f"Fatal error in main(): {e}\n{traceback.format_exc()}")
        raise


if __name__ == "__main__":
    main()
