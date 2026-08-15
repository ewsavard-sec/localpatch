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
import patch_store

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
        ttk.Button(bar, text="View Verification Log", command=self.on_view_verification_log).pack(side="left", padx=4)
        ttk.Button(bar, text="Settings", command=self.on_settings).pack(side="right", padx=4)

    def _build_table(self):
        columns = ("name", "installed", "available", "days_left", "cves", "verification", "status")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", selectmode="extended")
        headings = {
            "name": "Application", "installed": "Installed", "available": "Available",
            "days_left": "Days Until Auto-Deploy", "cves": "Known CVEs",
            "verification": "Verification", "status": "Status",
        }
        widths = {"name": 220, "installed": 100, "available": 100, "days_left": 150,
                  "cves": 180, "verification": 160, "status": 80}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.tree.tag_configure("critical", background="#fdecea")
        self.tree.tag_configure("high", background="#fff3e0")
        self.tree.tag_configure("clean", background="#ffffff")
        self.tree.tag_configure("verify_failed", foreground="#b00020", font=("Segoe UI", 9, "bold"))

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

        cache = {(e["package_id"], e["version"]): e for e in state.get_patch_cache_entries()}
        deployable, blocked = [], []
        for app in eligible:
            entry = cache.get((app["package_id"], app["available_version"]))
            if entry and not entry["verified"]:
                blocked.append(app["name"])
            else:
                deployable.append(app["package_id"])

        if blocked:
            messagebox.showwarning(
                "Some updates excluded",
                "These apps previously failed verification and are excluded from "
                "Deploy All Eligible — review them individually via View Verification Log:\n\n"
                + "\n".join(blocked),
            )
        if not deployable:
            return
        self._deploy_many(deployable)

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
        blocked = 0
        for pkg_id in package_ids:
            version = apps_by_id.get(pkg_id, {}).get("available_version", "unknown")
            result = patch_store.verify_and_record(pkg_id, version, self.cfg)
            if not result.verified:
                state.mark_deployed(pkg_id, version, success=False)
                blocked += 1
                continue
            success, log = deployer.deploy(pkg_id)
            state.mark_deployed(pkg_id, version, success)
        summary = "Deployment finished."
        if blocked:
            summary += f" {blocked} blocked by verification — see Verification column."
        self.root.after(0, lambda: self.status_var.set(summary))
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

    def on_view_verification_log(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("LocalPatch", "Select an app first.")
            return
        pkg_id = selection[0]
        app = next((a for a in state.get_all_apps() if a["package_id"] == pkg_id), None)
        if not app:
            return
        entry = self._verification_cache.get((pkg_id, app["available_version"]))

        win = tk.Toplevel(self.root)
        win.title(f"Verification Log — {app['name']}")
        win.geometry("480x380")
        win.resizable(False, False)

        frame = ttk.Frame(win, padding=16)
        frame.pack(fill="both", expand=True)

        if entry is None:
            ttk.Label(frame, text="No verification has been attempted for this version yet.",
                      wraplength=440).pack(anchor="w")
            return

        rows = [
            ("Package", pkg_id),
            ("Version", entry["version"]),
            ("Result", "Verified" if entry["verified"] else "Failed"),
            ("Verification mode", entry["verification_mode"]),
            ("Expected SHA256", entry["expected_sha256"] or "-"),
            ("Actual SHA256", entry["actual_sha256"] or "-"),
            ("Hash match", "Yes" if entry["hash_match"] else "No"),
            ("Signature status", entry["signature_status"] or "-"),
            ("Signer subject", entry["signer_subject"] or "(none)"),
            ("Checked at", entry["downloaded_at"]),
            ("File path", entry["file_path"] or "-"),
        ]
        for i, (label, value) in enumerate(rows):
            ttk.Label(frame, text=f"{label}:", font=("Segoe UI", 9, "bold")).grid(
                row=i, column=0, sticky="ne", pady=2)
            ttk.Label(frame, text=str(value), wraplength=320, justify="left").grid(
                row=i, column=1, sticky="w", padx=(8, 0), pady=2)

    # ---------- Rendering ----------

    @staticmethod
    def _verification_label(entry):
        """Returns (label, is_failed) for the Verification column."""
        if entry is None:
            return "Not checked yet", False
        if entry["verified"]:
            return "Verified", False
        if not entry["hash_match"]:
            return "Failed — hash mismatch", True
        return "Failed — unsigned", True

    def refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        self._verification_cache = {(e["package_id"], e["version"]): e for e in state.get_patch_cache_entries()}

        for app in state.get_all_apps():
            if not app["available_version"] or app["available_version"] == app["installed_version"]:
                continue  # only show apps with a pending update

            cves = json.loads(app["cves"] or "[]")
            cve_text = ", ".join(c["id"] for c in cves) if cves else "-"
            severities = [c["severity"] for c in cves]
            sev_tag = "clean"
            if "CRITICAL" in severities:
                sev_tag = "critical"
            elif "HIGH" in severities:
                sev_tag = "high"

            entry = self._verification_cache.get((app["package_id"], app["available_version"]))
            verification_label, verify_failed = self._verification_label(entry)

            days_left = self._days_left(app)
            status = app["deploy_status"]

            tags = (("verify_failed",) if verify_failed else ()) + (sev_tag,)
            self.tree.insert("", "end", iid=app["package_id"], tags=tags, values=(
                app["name"], app["installed_version"], app["available_version"],
                days_left, cve_text, verification_label, status,
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
