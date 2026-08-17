"""
gui.py — Tkinter desktop UI for LocalPatch.

Color palette and typography sourced from the ui-ux-pro-max design-system
generator (`security tool developer utility dashboard` -> Dark Mode (OLED),
JetBrains Mono / IBM Plex Sans) and adapted to what ttk's 'clam' theme can
actually render -- Consolas substitutes for JetBrains Mono since it ships
with Windows and needs no extra font install.
"""

import json
import time
import threading
import traceback
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

import state
import scanner
import cve_matcher
import deployer
import scheduler
import patch_store
import app_log

CONFIG_PATH = Path(__file__).parent / "config.json"
CONFIG_EXAMPLE_PATH = Path(__file__).parent / "config.example.json"

COLORS = {
    "bg": "#0F172A",
    "surface": "#1B2336",
    "surface_alt": "#171E30",
    "text": "#F8FAFC",
    "muted": "#94A3B8",
    "border": "#475569",
    "primary": "#1E293B",
    "accent": "#22C55E",
    "accent_fg": "#0F172A",
    "danger": "#EF4444",
    "warning": "#F59E0B",
}

FONT_UI = ("Segoe UI", 9)
FONT_UI_BOLD = ("Segoe UI", 9, "bold")
FONT_MONO = ("Consolas", 9)

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


def save_config(cfg):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


class LocalPatchApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LocalPatch")
        self.root.geometry("1040x600")
        self.root.minsize(860, 440)
        self.cfg = load_config()

        self._apply_theme()
        self._build_toolbar()
        self._build_table()
        self._build_statusbar()

        # Route every uncaught exception raised inside a Tk callback (button
        # clicks, etc.) into the Status Log instead of just stderr -- this
        # is on top of the explicit try/except in the background worker
        # threads below, which Tk's own hook does NOT cover.
        self.root.report_callback_exception = self._handle_tk_exception

        state.init_db()
        self.refresh_table()

    # ---------- Theming ----------

    def _apply_theme(self):
        self.root.configure(background=COLORS["bg"])

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=COLORS["bg"])
        style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=FONT_UI)
        style.configure("TCheckbutton", background=COLORS["bg"], foreground=COLORS["text"], font=FONT_UI)

        style.configure("TButton", font=FONT_UI, padding=(10, 6),
                         background=COLORS["surface"], foreground=COLORS["text"],
                         bordercolor=COLORS["border"], focuscolor=COLORS["accent"])
        style.map("TButton",
                   background=[("active", COLORS["border"]), ("pressed", COLORS["border"])])

        style.configure("Accent.TButton", font=FONT_UI_BOLD, padding=(10, 6),
                         background=COLORS["accent"], foreground=COLORS["accent_fg"],
                         bordercolor=COLORS["accent"])
        style.map("Accent.TButton",
                   background=[("active", "#1CA750"), ("pressed", "#189245")])

        style.configure("TMenubutton", font=FONT_UI, padding=(10, 6),
                         background=COLORS["surface"], foreground=COLORS["text"],
                         bordercolor=COLORS["border"], arrowcolor=COLORS["text"])
        style.map("TMenubutton", background=[("active", COLORS["border"])])

        style.configure("TEntry", fieldbackground=COLORS["surface"], foreground=COLORS["text"],
                         bordercolor=COLORS["border"], insertcolor=COLORS["text"])
        style.configure("TSpinbox", fieldbackground=COLORS["surface"], foreground=COLORS["text"],
                         background=COLORS["surface"], bordercolor=COLORS["border"],
                         arrowcolor=COLORS["text"])

        style.configure("Treeview", font=FONT_MONO, rowheight=26,
                         background=COLORS["surface"], fieldbackground=COLORS["surface"],
                         foreground=COLORS["text"], bordercolor=COLORS["border"], borderwidth=0)
        style.configure("Treeview.Heading", font=FONT_UI_BOLD,
                         background=COLORS["surface_alt"], foreground=COLORS["muted"],
                         bordercolor=COLORS["border"], relief="flat")
        style.map("Treeview.Heading", background=[("active", COLORS["border"])])
        style.map("Treeview",
                   background=[("selected", COLORS["primary"])],
                   foreground=[("selected", COLORS["text"])])

        style.configure("Vertical.TScrollbar", background=COLORS["surface"],
                         troughcolor=COLORS["bg"], bordercolor=COLORS["border"], arrowcolor=COLORS["muted"])
        style.configure("Horizontal.TScrollbar", background=COLORS["surface"],
                         troughcolor=COLORS["bg"], bordercolor=COLORS["border"], arrowcolor=COLORS["muted"])

    def _style_dialog(self, win):
        """Applies the app's dark background to a Toplevel (ttk styles apply globally already)."""
        win.configure(background=COLORS["bg"])

    # ---------- UI construction ----------

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=10)
        bar.pack(fill="x")

        ttk.Button(bar, text="Scan Now", style="Accent.TButton", command=self.on_scan).pack(side="left", padx=(0, 6))
        ttk.Button(bar, text="Deploy Selected", command=self.on_deploy_selected).pack(side="left", padx=6)
        ttk.Button(bar, text="Deploy All Eligible", command=self.on_deploy_eligible).pack(side="left", padx=6)

        logs_menu = tk.Menu(self.root, tearoff=False, background=COLORS["surface"],
                             foreground=COLORS["text"], activebackground=COLORS["border"],
                             activeforeground=COLORS["text"], borderwidth=0)
        logs_menu.add_command(label="Verification Log (selected app)", command=self.on_view_verification_log)
        logs_menu.add_command(label="Status Log (all events)", command=self.on_view_status_log)
        ttk.Menubutton(bar, text="View Logs", menu=logs_menu).pack(side="left", padx=6)

        ttk.Button(bar, text="Settings", command=self.on_settings).pack(side="right")

    def _build_table(self):
        table_frame = ttk.Frame(self.root)
        table_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        columns = ("name", "installed", "available", "days_left", "cves", "verification", "status")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="extended")
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
        self.tree.grid(row=0, column=0, sticky="nsew")

        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=yscroll.set)

        # Dark-mode tints: subtle color washes rather than the light-mode
        # pastels a white-background app would use, so severity is still
        # readable against the dark surface instead of glowing.
        self.tree.tag_configure("critical", background="#3A1520")
        self.tree.tag_configure("high", background="#3A2A12")
        self.tree.tag_configure("clean", background=COLORS["surface"])
        self.tree.tag_configure("verify_failed", foreground=COLORS["danger"], font=FONT_UI_BOLD)

    def _build_statusbar(self):
        bar = ttk.Frame(self.root, style="TFrame")
        bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready.")
        self.status_label = tk.Label(
            bar, textvariable=self.status_var, anchor="w", padx=10, pady=6,
            background=COLORS["surface_alt"], foreground=COLORS["muted"], font=FONT_UI,
        )
        self.status_label.pack(fill="x")

    def _set_status(self, text, kind="info"):
        color = {"info": COLORS["muted"], "success": COLORS["accent"], "error": COLORS["danger"]}.get(kind, COLORS["muted"])
        self.status_var.set(text)
        self.status_label.configure(foreground=color)

    def _handle_tk_exception(self, exc_type, exc_value, tb):
        app_log.error("Unhandled UI error: " + "".join(traceback.format_exception(exc_type, exc_value, tb)))
        self._set_status("An unexpected error occurred — see View Logs > Status Log.", "error")

    # ---------- Actions ----------

    def on_scan(self):
        self._set_status("Scanning installed software and checking for updates...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
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

            app_log.info(f"Scan complete: {len(installed)} apps checked, {len(upgrades)} updates found.")
            self.root.after(0, lambda: self._set_status(
                f"Scan complete. {len(installed)} apps checked, {len(upgrades)} updates found.", "success"))
        except Exception as e:
            app_log.error(f"Scan failed: {e}\n{traceback.format_exc()}")
            self.root.after(0, lambda: self._set_status(
                "Scan failed — see View Logs > Status Log.", "error"))
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
        self._set_status(f"Deploying {len(iids)} update(s)...")
        threading.Thread(target=self._deploy_worker, args=(iids,), daemon=True).start()

    def _deploy_worker(self, package_ids):
        apps_by_id = {a["package_id"]: a for a in state.get_all_apps()}
        blocked = 0
        failed = 0
        deployed = 0
        for pkg_id in package_ids:
            version = apps_by_id.get(pkg_id, {}).get("available_version", "unknown")
            name = apps_by_id.get(pkg_id, {}).get("name", pkg_id)
            try:
                result = patch_store.verify_and_record(pkg_id, version, self.cfg)
                if not result.verified:
                    state.mark_deployed(pkg_id, version, success=False)
                    app_log.warning(f"Blocked deploy: {name} {version} -- {result.reason}")
                    blocked += 1
                    continue
                success, log = deployer.deploy(pkg_id)
                state.mark_deployed(pkg_id, version, success)
                if success:
                    app_log.info(f"Deployed: {name} {version}")
                    deployed += 1
                else:
                    app_log.error(f"Deploy failed: {name} {version} -- winget output: {log.strip()[-1000:]}")
                    failed += 1
            except Exception as e:
                state.mark_deployed(pkg_id, version, success=False)
                app_log.error(f"Unexpected error deploying {name} {version}: {e}\n{traceback.format_exc()}")
                failed += 1

        summary = f"Deployment finished. {deployed} deployed."
        kind = "success"
        extras = []
        if blocked:
            extras.append(f"{blocked} blocked by verification")
        if failed:
            extras.append(f"{failed} failed")
            kind = "error"
        if extras:
            summary += " " + ", ".join(extras) + " — see View Logs > Status Log."
        self.root.after(0, lambda: self._set_status(summary, kind))
        self.root.after(0, self.refresh_table)

    def on_settings(self):
        win = tk.Toplevel(self.root)
        self._style_dialog(win)
        win.title("Settings")
        win.geometry("400x420")
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

        ttk.Label(win, text="Keep cached patch downloads for (days):").pack(anchor="w", padx=12, pady=(12, 2))
        retention_var = tk.IntVar(value=self.cfg.get("retention_days", 180))
        ttk.Spinbox(win, from_=30, to=730, textvariable=retention_var, width=6).pack(anchor="w", padx=12)

        def save_and_close():
            self.cfg["delay_days"] = delay_var.get()
            self.cfg["run_time"] = time_var.get()
            self.cfg["auto_run_enabled"] = auto_var.get()
            self.cfg["nvd_api_key"] = key_var.get()
            self.cfg["retention_days"] = retention_var.get()
            save_config(self.cfg)
            try:
                if auto_var.get():
                    scheduler.enable(time_var.get())
                else:
                    scheduler.disable()
            except Exception as e:
                app_log.error(f"Scheduler error: {e}\n{traceback.format_exc()}")
                messagebox.showerror("Scheduler error", str(e))
            win.destroy()
            self.refresh_table()

        def cleanup_now():
            self.cfg["retention_days"] = retention_var.get()
            summary = patch_store.purge_expired(self.cfg["retention_days"])
            app_log.info(f"Manual cleanup: purged {summary['count']} cached patch(es), "
                         f"freed {summary['bytes_freed']} bytes.")
            messagebox.showinfo(
                "Cleanup complete",
                f"Purged {summary['count']} cached patch(es), "
                f"freed {summary['bytes_freed'] / 1024:.1f} KB.",
            )
            self.refresh_table()

        ttk.Button(win, text="Clean Up Old Patches Now", command=cleanup_now).pack(anchor="w", padx=12, pady=(16, 4))

        ttk.Button(win, text="Save", style="Accent.TButton", command=save_and_close).pack(pady=12)

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
        self._style_dialog(win)
        win.title(f"Verification Log — {app['name']}")
        win.geometry("520x480")
        win.resizable(False, False)

        frame = ttk.Frame(win, padding=16)
        frame.pack(fill="both", expand=True)

        if entry is None:
            ttk.Label(frame, text="No verification has been attempted for this version yet.",
                      wraplength=440).pack(anchor="w")
            return

        result_text = "Verified" if entry["verified"] else "Failed"
        rows = [
            ("Package", pkg_id),
            ("Version", entry["version"]),
            ("Result", result_text),
            ("Reason", entry["reason"] or "-"),
            ("Verification mode", entry["verification_mode"]),
            ("Expected SHA256", entry["expected_sha256"] or "-"),
            ("Actual SHA256", entry["actual_sha256"] or "-"),
            ("Hash match", "Yes" if entry["hash_match"] else "No"),
            ("Signature status", entry["signature_status"] or "-"),
            ("Signature message", entry["signature_message"] or "-"),
            ("Signer subject", entry["signer_subject"] or "(none)"),
            ("Checked at", entry["downloaded_at"]),
            ("File path", entry["file_path"] or "-"),
        ]
        for i, (label, value) in enumerate(rows):
            ttk.Label(frame, text=f"{label}:", font=FONT_UI_BOLD).grid(
                row=i, column=0, sticky="ne", pady=2)
            value_color = COLORS["accent"] if (label == "Result" and entry["verified"]) else \
                          COLORS["danger"] if label == "Result" else COLORS["text"]
            tk.Label(frame, text=str(value), wraplength=360, justify="left",
                     background=COLORS["bg"], foreground=value_color, font=FONT_UI).grid(
                row=i, column=1, sticky="w", padx=(8, 0), pady=2)

    def on_view_status_log(self):
        win = tk.Toplevel(self.root)
        self._style_dialog(win)
        win.title("Status Log")
        win.geometry("780x440")
        win.minsize(420, 220)
        win.rowconfigure(0, weight=1)
        win.columnconfigure(0, weight=1)

        frame = ttk.Frame(win, padding=(12, 12, 12, 0))
        frame.grid(row=0, column=0, sticky="nsew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        text = tk.Text(frame, wrap="none", font=FONT_MONO, state="disabled",
                        background=COLORS["surface"], foreground=COLORS["text"],
                        insertbackground=COLORS["text"], borderwidth=0, highlightthickness=0)
        text.grid(row=0, column=0, sticky="nsew")

        yscroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
        xscroll.grid(row=1, column=0, sticky="ew")
        text.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

        text.tag_configure("ERROR", foreground=COLORS["danger"])
        text.tag_configure("WARNING", foreground=COLORS["warning"])
        text.tag_configure("INFO", foreground=COLORS["muted"])

        def refresh():
            text.configure(state="normal")
            text.delete("1.0", "end")
            lines = app_log.get_recent_lines(1000)
            if not lines:
                text.insert("end", "No events logged yet.")
            for line in lines:
                tag = "ERROR" if "[ERROR]" in line else "WARNING" if "[WARNING]" in line else "INFO"
                text.insert("end", line + "\n", tag)
            text.see("end")
            text.configure(state="disabled")

        btn_bar = ttk.Frame(win, padding=12)
        btn_bar.grid(row=1, column=0, sticky="ew")
        ttk.Button(btn_bar, text="Refresh", command=refresh).pack(side="left")
        tk.Label(btn_bar, text=f"Log file: {app_log.LOG_PATH}", background=COLORS["bg"],
                 foreground=COLORS["muted"], font=("Segoe UI", 8)).pack(side="right")

        refresh()

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
