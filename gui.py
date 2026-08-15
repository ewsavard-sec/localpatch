"""
gui.py — Tkinter desktop UI for LocalPatch.
"""

import json
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

import state
import scanner
import cve_matcher
import deployer
import scheduler

CONFIG_PATH = Path(__file__).parent / "config.json"

DEFAULT_CONFIG = {
    "delay_days": 7,
    "auto_run_enabled": False,
    "run_time": "09:00",
    "nvd_api_key": "",
}


def load_config():
    if CONFIG_PATH.exists():
        return {**DEFAULT_CONFIG, **json.loads(CONFIG_PATH.read_text())}
    return dict(DEFAULT_CONFIG)


def save_config(cfg):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


class LocalPatchApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LocalPatch")
        self.root.geometry("980x560")
        self.cfg = load_config()

        self._build_toolbar()
        self._build_table()
        self._build_statusbar()

        state.init_db()
        self.refresh_table()

    # ---------- UI construction ----------

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=8)
        bar.pack(fill="x")

        ttk.Button(bar, text="Scan Now", command=self.on_scan).pack(side="left", padx=4)
        ttk.Button(bar, text="Deploy Selected", command=self.on_deploy_selected).pack(side="left", padx=4)
        ttk.Button(bar, text="Deploy All Eligible", command=self.on_deploy_eligible).pack(side="left", padx=4)
        ttk.Button(bar, text="Settings", command=self.on_settings).pack(side="right", padx=4)

    def _build_table(self):
        columns = ("name", "installed", "available", "days_left", "cves", "status")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", selectmode="extended")
        headings = {
            "name": "Application", "installed": "Installed", "available": "Available",
            "days_left": "Days Until Auto-Deploy", "cves": "Known CVEs", "status": "Status",
        }
        widths = {"name": 260, "installed": 110, "available": 110, "days_left": 160, "cves": 220, "status": 90}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.tree.tag_configure("critical", background="#fdecea")
        self.tree.tag_configure("high", background="#fff3e0")
        self.tree.tag_configure("clean", background="#ffffff")

    def _build_statusbar(self):
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(self.root, textvariable=self.status_var, anchor="w", padding=4).pack(fill="x")

    # ---------- Actions ----------

    def on_scan(self):
        self.status_var.set("Scanning installed software and checking for updates...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        installed = {a["Id"]: a for a in scanner.scan_installed()}
        upgrades = {a["Id"]: a for a in scanner.scan_upgrades()}

        matcher = cve_matcher.CveMatcher(api_key=self.cfg.get("nvd_api_key") or None)

        for pkg_id, app in installed.items():
            available = upgrades.get(pkg_id, {}).get("Available")
            state.upsert_app(
                package_id=pkg_id, name=app["Name"], source=app.get("Source", ""),
                installed_version=app["Version"], available_version=available,
            )
            cves = matcher.lookup(app["Name"], app["Version"])
            state.set_cves(pkg_id, cves)

        self.root.after(0, lambda: self.status_var.set(
            f"Scan complete. {len(installed)} apps checked, {len(upgrades)} updates found."))
        self.root.after(0, self.refresh_table)

    def on_deploy_selected(self):
        self._deploy_many(self.tree.selection())

    def on_deploy_eligible(self):
        eligible = state.get_eligible_for_autodeploy(self.cfg["delay_days"])
        if not eligible:
            messagebox.showinfo("LocalPatch", "No apps are past their delay window yet.")
            return
        self._deploy_many([a["package_id"] for a in eligible])

    def _deploy_many(self, iids):
        iids = list(iids)
        if not iids:
            return
        if not messagebox.askyesno("Confirm Deployment", f"Deploy {len(iids)} update(s) now?"):
            return
        self.status_var.set(f"Deploying {len(iids)} update(s)...")
        threading.Thread(target=self._deploy_worker, args=(iids,), daemon=True).start()

    def _deploy_worker(self, package_ids):
        apps_by_id = {a["package_id"]: a for a in state.get_all_apps()}
        for pkg_id in package_ids:
            success, log = deployer.deploy(pkg_id)
            version = apps_by_id.get(pkg_id, {}).get("available_version", "unknown")
            state.mark_deployed(pkg_id, version, success)
        self.root.after(0, lambda: self.status_var.set("Deployment finished."))
        self.root.after(0, self.refresh_table)

    def on_settings(self):
        win = tk.Toplevel(self.root)
        win.title("Settings")
        win.geometry("380x260")
        win.resizable(False, False)

        ttk.Label(win, text="Delay before auto-deploying a new version (days):").pack(anchor="w", padx=12, pady=(12, 2))
        delay_var = tk.IntVar(value=self.cfg["delay_days"])
        ttk.Spinbox(win, from_=0, to=30, textvariable=delay_var, width=6).pack(anchor="w", padx=12)

        ttk.Label(win, text="Daily auto-run time (24h, HH:MM):").pack(anchor="w", padx=12, pady=(12, 2))
        time_var = tk.StringVar(value=self.cfg["run_time"])
        ttk.Entry(win, textvariable=time_var, width=8).pack(anchor="w", padx=12)

        auto_var = tk.BooleanVar(value=self.cfg["auto_run_enabled"])
        ttk.Checkbutton(win, text="Enable automatic daily scan + deploy", variable=auto_var).pack(anchor="w", padx=12, pady=12)

        ttk.Label(win, text="NVD API key (optional, raises rate limit):").pack(anchor="w", padx=12, pady=(0, 2))
        key_var = tk.StringVar(value=self.cfg.get("nvd_api_key", ""))
        ttk.Entry(win, textvariable=key_var, width=36, show="*").pack(anchor="w", padx=12)

        def save_and_close():
            self.cfg["delay_days"] = delay_var.get()
            self.cfg["run_time"] = time_var.get()
            self.cfg["auto_run_enabled"] = auto_var.get()
            self.cfg["nvd_api_key"] = key_var.get()
            save_config(self.cfg)
            try:
                if auto_var.get():
                    scheduler.enable(time_var.get())
                else:
                    scheduler.disable()
            except Exception as e:
                messagebox.showerror("Scheduler error", str(e))
            win.destroy()
            self.refresh_table()

        ttk.Button(win, text="Save", command=save_and_close).pack(pady=8)

    # ---------- Rendering ----------

    def refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        for app in state.get_all_apps():
            if not app["available_version"] or app["available_version"] == app["installed_version"]:
                continue  # only show apps with a pending update

            cves = json.loads(app["cves"] or "[]")
            cve_text = ", ".join(c["id"] for c in cves) if cves else "-"
            severities = [c["severity"] for c in cves]
            tag = "clean"
            if "CRITICAL" in severities:
                tag = "critical"
            elif "HIGH" in severities:
                tag = "high"

            days_left = self._days_left(app)
            status = app["deploy_status"]

            self.tree.insert("", "end", iid=app["package_id"], tags=(tag,), values=(
                app["name"], app["installed_version"], app["available_version"],
                days_left, cve_text, status,
            ))

    def _days_left(self, app):
        if not app["first_seen_available"]:
            return "-"
        first_seen_ts = time.mktime(time.strptime(app["first_seen_available"], "%Y-%m-%dT%H:%M:%S"))
        elapsed_days = (time.time() - first_seen_ts) / 86400
        remaining = self.cfg["delay_days"] - elapsed_days
        return "Eligible now" if remaining <= 0 else f"{remaining:.1f}"


def main():
    root = tk.Tk()
    LocalPatchApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
