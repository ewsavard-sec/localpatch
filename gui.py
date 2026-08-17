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

# 4/8px spacing scale -- every pack/grid pad below is one of these.
SPACE = {"xs": 4, "sm": 8, "md": 12, "lg": 16, "xl": 24}

FONT_TITLE = ("Segoe UI", 16, "bold")
FONT_SUBTITLE = ("Segoe UI", 9)
FONT_UI = ("Segoe UI", 10)
FONT_UI_BOLD = ("Segoe UI", 10, "bold")
FONT_MONO = ("Consolas", 10)
FONT_STAT_VALUE = ("Segoe UI", 16, "bold")
FONT_STAT_LABEL = ("Segoe UI", 8, "bold")

DEFAULT_CONFIG = {
    "delay_days": 7,
    "auto_run_enabled": False,
    "run_time": "09:00",
    "nvd_api_key": "",
    "retention_days": 180,
}

TABLE_COLUMNS = ("name", "installed", "available", "days_left", "cves", "verification", "status")
TABLE_HEADINGS = {
    "name": "Application", "installed": "Installed", "available": "Available",
    "days_left": "Days Until Auto-Deploy", "cves": "Known CVEs",
    "verification": "Verification", "status": "Status",
}
TABLE_WIDTHS = {
    "name": 230, "installed": 110, "available": 110, "days_left": 175,
    "cves": 190, "verification": 175, "status": 90,
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
        self.root.geometry("1100x760")
        self.root.minsize(920, 560)
        self.cfg = load_config()
        self._scan_active = False
        self._scan_cancel_event = None
        # Soonest-eligible-first by default -- the most actionable rows surface at the top.
        self._sort_state = {"column": "days_left", "reverse": False}

        self._apply_theme()
        self._build_header()
        self._build_toolbar()
        self._build_dashboard()
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
        style.map("TCheckbutton", background=[("active", COLORS["bg"])])

        style.configure("Header.TFrame", background=COLORS["surface_alt"])
        style.configure("HeaderTitle.TLabel", background=COLORS["surface_alt"],
                         foreground=COLORS["text"], font=FONT_TITLE)
        style.configure("HeaderSubtitle.TLabel", background=COLORS["surface_alt"],
                         foreground=COLORS["muted"], font=FONT_SUBTITLE)

        style.configure("TButton", font=FONT_UI, padding=(12, 7),
                         background=COLORS["surface"], foreground=COLORS["text"],
                         bordercolor=COLORS["border"], focuscolor=COLORS["accent"])
        style.map("TButton",
                   background=[("active", COLORS["border"]), ("pressed", COLORS["border"])],
                   foreground=[("disabled", COLORS["muted"])])

        # Primary action -- there is exactly one per screen (Scan Now).
        style.configure("Accent.TButton", font=FONT_UI_BOLD, padding=(12, 7),
                         background=COLORS["accent"], foreground=COLORS["accent_fg"],
                         bordercolor=COLORS["accent"])
        style.map("Accent.TButton",
                   background=[("active", "#1CA750"), ("pressed", "#189245"),
                               ("disabled", COLORS["surface"])],
                   foreground=[("disabled", COLORS["muted"])])

        # Destructive/interrupt action -- outlined red so it reads as "stop", not just gray-disabled.
        style.configure("Danger.TButton", font=FONT_UI, padding=(12, 7),
                         background=COLORS["surface"], foreground=COLORS["danger"],
                         bordercolor=COLORS["danger"])
        style.map("Danger.TButton",
                   background=[("active", "#3A1520"), ("pressed", "#3A1520"),
                               ("disabled", COLORS["surface"])],
                   foreground=[("disabled", COLORS["muted"])],
                   bordercolor=[("disabled", COLORS["border"])])

        style.configure("TMenubutton", font=FONT_UI, padding=(12, 7),
                         background=COLORS["surface"], foreground=COLORS["text"],
                         bordercolor=COLORS["border"], arrowcolor=COLORS["text"])
        style.map("TMenubutton", background=[("active", COLORS["border"])])

        style.configure("TEntry", fieldbackground=COLORS["surface"], foreground=COLORS["text"],
                         bordercolor=COLORS["border"], insertcolor=COLORS["text"])
        style.configure("TSpinbox", fieldbackground=COLORS["surface"], foreground=COLORS["text"],
                         background=COLORS["surface"], bordercolor=COLORS["border"],
                         arrowcolor=COLORS["text"])

        style.configure("TLabelframe", background=COLORS["bg"], bordercolor=COLORS["border"])
        style.configure("TLabelframe.Label", background=COLORS["bg"], foreground=COLORS["muted"],
                         font=FONT_UI_BOLD)

        style.configure("Treeview", font=FONT_MONO, rowheight=28,
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
        style.configure("TSeparator", background=COLORS["border"])

        style.configure("StatusBar.TFrame", background=COLORS["surface_alt"])
        style.configure("TProgressbar", troughcolor=COLORS["surface_alt"], background=COLORS["accent"],
                         bordercolor=COLORS["surface_alt"], lightcolor=COLORS["accent"], darkcolor=COLORS["accent"])

    def _style_dialog(self, win):
        """Applies the app's dark background to a Toplevel (ttk styles apply globally already)."""
        win.configure(background=COLORS["bg"])

    # ---------- UI construction ----------

    def _build_header(self):
        header = ttk.Frame(self.root, style="Header.TFrame", padding=(SPACE["lg"], SPACE["md"]))
        header.pack(fill="x")

        title_box = ttk.Frame(header, style="Header.TFrame")
        title_box.pack(side="left")
        ttk.Label(title_box, text="LocalPatch", style="HeaderTitle.TLabel").pack(anchor="w")
        ttk.Label(title_box, text="Local software inventory & patch verification",
                  style="HeaderSubtitle.TLabel").pack(anchor="w")

        stats_box = ttk.Frame(header, style="Header.TFrame")
        stats_box.pack(side="right")

        self.stat_pending_var = tk.StringVar(value="0")
        self.stat_critical_var = tk.StringVar(value="0")
        self.stat_unverified_var = tk.StringVar(value="0")

        self._build_stat(stats_box, self.stat_pending_var, "PENDING UPDATES", COLORS["text"])
        ttk.Separator(stats_box, orient="vertical").pack(side="left", fill="y", padx=SPACE["lg"])
        self._build_stat(stats_box, self.stat_critical_var, "CRITICAL CVEs", COLORS["danger"])
        ttk.Separator(stats_box, orient="vertical").pack(side="left", fill="y", padx=SPACE["lg"])
        self._build_stat(stats_box, self.stat_unverified_var, "NOT VERIFIED", COLORS["warning"])

        ttk.Separator(self.root, orient="horizontal").pack(fill="x")

    @staticmethod
    def _build_stat(parent, var, label, color):
        box = ttk.Frame(parent, style="Header.TFrame")
        box.pack(side="left")
        tk.Label(box, textvariable=var, font=FONT_STAT_VALUE,
                 background=COLORS["surface_alt"], foreground=color).pack(anchor="e")
        tk.Label(box, text=label, font=FONT_STAT_LABEL,
                 background=COLORS["surface_alt"], foreground=COLORS["muted"]).pack(anchor="e")

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(SPACE["lg"], SPACE["sm"]))
        bar.pack(fill="x")

        self.scan_button = ttk.Button(bar, text="Scan Now", style="Accent.TButton",
                                       cursor="hand2", command=self.on_scan)
        self.scan_button.pack(side="left")

        self.stop_scan_button = ttk.Button(bar, text="Stop Scan", style="Danger.TButton",
                                            cursor="hand2", command=self.on_stop_scan)
        self.stop_scan_button.state(["disabled"])
        self.stop_scan_button.pack(side="left", padx=(SPACE["sm"], 0))

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=SPACE["lg"])

        ttk.Button(bar, text="Deploy Selected", cursor="hand2",
                   command=self.on_deploy_selected).pack(side="left")
        ttk.Button(bar, text="Deploy All Eligible", cursor="hand2",
                   command=self.on_deploy_eligible).pack(side="left", padx=(SPACE["sm"], 0))

        ttk.Button(bar, text="Settings", cursor="hand2", command=self.on_settings).pack(side="right")

        logs_menu = tk.Menu(self.root, tearoff=False, background=COLORS["surface"],
                             foreground=COLORS["text"], activebackground=COLORS["border"],
                             activeforeground=COLORS["text"], borderwidth=0)
        logs_menu.add_command(label="Verification Log (selected app)", command=self.on_view_verification_log)
        logs_menu.add_command(label="Status Log (all events)", command=self.on_view_status_log)
        ttk.Menubutton(bar, text="View Logs", menu=logs_menu, cursor="hand2").pack(
            side="right", padx=(0, SPACE["sm"]))

    def _build_dashboard(self):
        """
        A row of summary cards above the applications table -- the
        dashboard-first layout, adapted from a network vulnerability
        console's style. LocalPatch tracks one machine, not a fleet, so
        this reports on the whole local inventory (not just apps with a
        pending update, which is what the table below filters to) rather
        than a per-computer breakdown. No chart widgets -- colored status
        rows only, in the same spirit as the reference's category list.
        """
        row = ttk.Frame(self.root, padding=(SPACE["lg"], 0, SPACE["lg"], SPACE["lg"]))
        row.pack(fill="x")
        row.columnconfigure(0, weight=1, uniform="card")
        row.columnconfigure(1, weight=1, uniform="card")
        row.columnconfigure(2, weight=1, uniform="card")

        self.status_card = self._make_card(row, "Update Status")
        self.status_card.grid(row=0, column=0, sticky="nsew", padx=(0, SPACE["sm"]))

        self.severity_card = self._make_card(row, "Vulnerability Severity")
        self.severity_card.grid(row=0, column=1, sticky="nsew", padx=SPACE["sm"])

        self.risk_card = self._make_card(row, "Most At-Risk Applications")
        self.risk_card.grid(row=0, column=2, sticky="nsew", padx=(SPACE["sm"], 0))

    @staticmethod
    def _make_card(parent, title):
        card = tk.Frame(parent, background=COLORS["surface"],
                         highlightbackground=COLORS["border"], highlightthickness=1, bd=0)
        tk.Label(card, text=title.upper(), font=FONT_STAT_LABEL,
                 background=COLORS["surface"], foreground=COLORS["muted"]).pack(
            anchor="w", padx=SPACE["md"], pady=(SPACE["md"], SPACE["sm"]))
        body = tk.Frame(card, background=COLORS["surface"])
        body.pack(fill="both", expand=True, padx=SPACE["md"], pady=(0, SPACE["md"]))
        card.body = body
        return card

    @staticmethod
    def _dashboard_row(parent, count, label):
        color = COLORS["muted"] if count == 0 else COLORS["danger"]
        line = tk.Frame(parent, background=COLORS["surface"])
        line.pack(fill="x", pady=2)
        tk.Label(line, text="●", font=FONT_UI, background=COLORS["surface"],
                 foreground=color).pack(side="left")
        tk.Label(line, text=str(count), font=FONT_UI_BOLD, width=3, anchor="w",
                 background=COLORS["surface"], foreground=COLORS["text"]).pack(
            side="left", padx=(SPACE["xs"], SPACE["xs"]))
        tk.Label(line, text=label, font=FONT_UI, background=COLORS["surface"],
                 foreground=COLORS["muted"]).pack(side="left")

    def _empty_card_note(self, parent, text):
        tk.Label(parent, text=text, font=FONT_UI, background=COLORS["surface"],
                 foreground=COLORS["muted"], wraplength=240, justify="left").pack(
            anchor="w", pady=SPACE["xs"])

    def refresh_dashboard(self):
        for card in (self.status_card, self.severity_card, self.risk_card):
            for child in card.body.winfo_children():
                child.destroy()

        apps = state.get_all_apps()
        cache_entries = state.get_patch_cache_entries()

        def cves_of(app):
            return json.loads(app["cves"] or "[]")

        pending = [a for a in apps if a["available_version"] and a["available_version"] != a["installed_version"]]
        severity_counts = {}
        critical_apps, high_apps = set(), set()
        for a in apps:
            for c in cves_of(a):
                sev = c.get("severity") or "UNKNOWN"
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                if sev == "CRITICAL":
                    critical_apps.add(a["package_id"])
                elif sev == "HIGH":
                    high_apps.add(a["package_id"])

        verify_failed = sum(1 for e in cache_entries if not e["verified"])
        deploy_failed = sum(1 for a in apps if a["deploy_status"] == "failed")

        # --- Update Status ---
        self._dashboard_row(self.status_card.body, len(pending), "Pending Updates")
        self._dashboard_row(self.status_card.body, len(critical_apps), "Apps with Critical CVEs")
        self._dashboard_row(self.status_card.body, len(high_apps), "Apps with High CVEs")
        self._dashboard_row(self.status_card.body, verify_failed, "Verification Failures")
        self._dashboard_row(self.status_card.body, deploy_failed, "Deploy Failures")

        # --- Vulnerability Severity ---
        sev_order = [("CRITICAL", "Critical"), ("HIGH", "High"), ("MEDIUM", "Medium"),
                     ("LOW", "Low"), ("UNKNOWN", "Unknown")]
        if not severity_counts:
            self._empty_card_note(self.severity_card.body, "No known CVEs across your current inventory.")
        else:
            for key, label in sev_order:
                if severity_counts.get(key):
                    self._dashboard_row(self.severity_card.body, severity_counts[key], f"{label} CVEs")

        # --- Most At-Risk Applications ---
        def risk_key(a):
            cves = cves_of(a)
            crit = sum(1 for c in cves if c.get("severity") == "CRITICAL")
            high = sum(1 for c in cves if c.get("severity") == "HIGH")
            return (-crit, -high, -len(cves))

        top_risk = [a for a in apps if cves_of(a)]
        top_risk.sort(key=risk_key)
        top_risk = top_risk[:5]

        if not top_risk:
            self._empty_card_note(self.risk_card.body, "No apps with known CVEs.")
        else:
            for a in top_risk:
                cves = cves_of(a)
                sevs = {c.get("severity") for c in cves}
                color = COLORS["danger"] if "CRITICAL" in sevs else \
                    COLORS["warning"] if "HIGH" in sevs else COLORS["muted"]
                line = tk.Frame(self.risk_card.body, background=COLORS["surface"])
                line.pack(fill="x", pady=2)
                tk.Label(line, text="●", font=FONT_UI, background=COLORS["surface"],
                         foreground=color).pack(side="left")
                tk.Label(line, text=a["name"], font=FONT_UI, background=COLORS["surface"],
                         foreground=COLORS["text"]).pack(side="left", padx=(SPACE["xs"], SPACE["sm"]))
                tk.Label(line, text=f"{len(cves)} CVE{'s' if len(cves) != 1 else ''}", font=FONT_UI,
                         background=COLORS["surface"], foreground=COLORS["muted"]).pack(side="right")

    def _build_table(self):
        table_frame = ttk.Frame(self.root)
        table_frame.pack(fill="both", expand=True, padx=SPACE["lg"], pady=(0, SPACE["lg"]))
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(table_frame, columns=TABLE_COLUMNS, show="headings", selectmode="extended")
        for col in TABLE_COLUMNS:
            self.tree.heading(col, text=TABLE_HEADINGS[col], command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=TABLE_WIDTHS[col], anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")

        self.yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.yscroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=self.yscroll.set)

        # Dark-mode tints: subtle color washes rather than the light-mode
        # pastels a white-background app would use, so severity is still
        # readable against the dark surface instead of glowing. Rows with
        # no CVE hit alternate between two near-identical shades (zebra
        # striping) so long lists stay scannable without competing with
        # the severity tint on the rows that actually need attention.
        self.tree.tag_configure("critical", background="#3A1520")
        self.tree.tag_configure("high", background="#3A2A12")
        self.tree.tag_configure("clean_even", background=COLORS["surface"])
        self.tree.tag_configure("clean_odd", background=COLORS["surface_alt"])
        self.tree.tag_configure("verify_failed", foreground=COLORS["danger"], font=FONT_UI_BOLD)

        # Empty state -- shares the same grid cell as the table and swaps
        # in via grid()/grid_remove() whenever there's nothing to show,
        # whether that's "no scan run yet" or "everything is patched."
        self.empty_state = ttk.Frame(table_frame)
        inner = ttk.Frame(self.empty_state)
        inner.place(relx=0.5, rely=0.42, anchor="center")
        tk.Label(inner, text="✓", font=("Segoe UI", 30, "bold"),
                 background=COLORS["bg"], foreground=COLORS["accent"]).pack()
        tk.Label(inner, text="No pending updates", font=("Segoe UI", 13, "bold"),
                 background=COLORS["bg"], foreground=COLORS["text"]).pack(pady=(SPACE["sm"], SPACE["xs"]))
        tk.Label(inner, text="Run a scan to check installed software for updates and known CVEs.",
                 font=FONT_UI, background=COLORS["bg"], foreground=COLORS["muted"]).pack()

    def _build_statusbar(self):
        bar = ttk.Frame(self.root, style="StatusBar.TFrame")
        bar.pack(fill="x", side="bottom")

        self.progress = ttk.Progressbar(bar, orient="horizontal", length=220, mode="determinate")
        # Not packed here -- only shown while a scan is running (see
        # _start_scan_progress / _finish_scan_progress).

        self.status_var = tk.StringVar(value="Ready.")
        self.status_label = tk.Label(
            bar, textvariable=self.status_var, anchor="w", padx=SPACE["md"], pady=SPACE["sm"],
            background=COLORS["surface_alt"], foreground=COLORS["muted"], font=FONT_UI,
        )
        self.status_label.pack(side="left", fill="x", expand=True)

    def _set_status(self, text, kind="info"):
        color = {"info": COLORS["muted"], "success": COLORS["accent"], "error": COLORS["danger"]}.get(kind, COLORS["muted"])
        self.status_var.set(text)
        self.status_label.configure(foreground=color)

    @staticmethod
    def _format_duration(seconds):
        seconds = max(int(seconds), 0)
        if seconds < 60:
            return f"{seconds}s"
        minutes, secs = divmod(seconds, 60)
        if minutes < 60:
            return f"{minutes}m {secs}s"
        hours, minutes = divmod(minutes, 60)
        return f"{hours}h {minutes}m"

    def _start_scan_progress(self, total, est_seconds):
        if total == 0:
            self.progress.pack_forget()
            return
        self.progress.configure(mode="determinate", maximum=total, value=0)
        self.progress.pack(side="right", padx=SPACE["md"], pady=SPACE["sm"])
        self._set_status(f"Scanning 0/{total} apps... est. {self._format_duration(est_seconds)}")

    def _update_scan_progress(self, i, total, name, remaining_seconds):
        self.progress.configure(value=i)
        self._set_status(f"Scanning {i}/{total}: {name}... ~{self._format_duration(remaining_seconds)} remaining")

    def _finish_scan_progress(self, text, kind):
        self.progress.stop()
        self.progress.pack_forget()
        self._set_status(text, kind)

    def _handle_tk_exception(self, exc_type, exc_value, tb):
        app_log.error("Unhandled UI error: " + "".join(traceback.format_exception(exc_type, exc_value, tb)))
        self._set_status("An unexpected error occurred — see View Logs > Status Log.", "error")

    # ---------- Actions ----------

    def on_scan(self):
        if self._scan_active:
            return
        self._scan_active = True
        self._scan_cancel_event = threading.Event()
        self.scan_button.state(["disabled"])
        self.stop_scan_button.state(["!disabled"])

        self.progress.configure(mode="indeterminate")
        self.progress.pack(side="right", padx=SPACE["md"], pady=SPACE["sm"])
        self.progress.start(12)
        self._set_status("Scanning installed software...")
        threading.Thread(target=self._scan_worker, args=(self._scan_cancel_event,), daemon=True).start()

    def on_stop_scan(self):
        if self._scan_cancel_event is not None:
            self._scan_cancel_event.set()
            self.stop_scan_button.state(["disabled"])
            self._set_status("Stopping scan... (finishing the app currently being checked)")

    def _reset_scan_buttons(self):
        self._scan_active = False
        self._scan_cancel_event = None
        self.scan_button.state(["!disabled"])
        self.stop_scan_button.state(["disabled"])

    def _scan_worker(self, cancel_event):
        cancelled = False
        checked = 0
        total = 0
        try:
            installed = {a["Id"]: a for a in scanner.scan_installed()}
            upgrades = {a["Id"]: a for a in scanner.scan_upgrades()}

            matcher = cve_matcher.CveMatcher(api_key=self.cfg.get("nvd_api_key") or None)
            total = len(installed)
            # Up to two throttled NVD requests per app (CPE lookup + CVE
            # lookup) -- a conservative upper-bound estimate before any
            # apps have actually been processed. Refined below as real
            # per-app timing data comes in.
            est_seconds = total * matcher.min_interval * 2
            self.root.after(0, self.progress.stop)
            self.root.after(0, lambda: self._start_scan_progress(total, est_seconds))

            start = time.time()
            for i, (pkg_id, app) in enumerate(installed.items(), start=1):
                # Checked once per app rather than mid-NVD-request -- Stop
                # takes effect after the app currently being checked
                # finishes (up to ~13s without an API key), not instantly.
                if cancel_event.is_set():
                    cancelled = True
                    break

                available = upgrades.get(pkg_id, {}).get("Available")
                state.upsert_app(
                    package_id=pkg_id, name=app["Name"], source=app.get("Source", ""),
                    installed_version=app["Version"], available_version=available,
                )
                cves = matcher.lookup(app["Name"], app["Version"])
                state.set_cves(pkg_id, cves)
                checked = i

                elapsed = time.time() - start
                remaining = (elapsed / i) * (total - i)  # adapts to observed per-app rate
                self.root.after(0, lambda i=i, name=app["Name"], remaining=remaining:
                                 self._update_scan_progress(i, total, name, remaining))
                # Populate the table with this app immediately rather than
                # waiting for the whole scan to finish -- refresh_table()
                # preserves selection/scroll so this doesn't feel janky.
                self.root.after(0, self.refresh_table)

            if cancelled:
                app_log.warning(f"Scan stopped by user after {checked}/{total} apps.")
                self.root.after(0, lambda: self._finish_scan_progress(
                    f"Scan stopped. {checked}/{total} apps checked before stopping.", "info"))
            else:
                app_log.info(f"Scan complete: {len(installed)} apps checked, {len(upgrades)} updates found.")
                self.root.after(0, lambda: self._finish_scan_progress(
                    f"Scan complete. {len(installed)} apps checked, {len(upgrades)} updates found.", "success"))
        except Exception as e:
            app_log.error(f"Scan failed: {e}\n{traceback.format_exc()}")
            self.root.after(0, lambda: self._finish_scan_progress(
                "Scan failed — see View Logs > Status Log.", "error"))
        self.root.after(0, self._reset_scan_buttons)
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
        win.geometry("440x580")
        win.resizable(False, False)

        container = ttk.Frame(win, padding=SPACE["lg"])
        container.pack(fill="both", expand=True)

        schedule_frame = ttk.LabelFrame(container, text="Scan Schedule", padding=SPACE["md"])
        schedule_frame.pack(fill="x", pady=(0, SPACE["md"]))

        ttk.Label(schedule_frame, text="Delay before auto-deploying a new version (days):").pack(anchor="w")
        delay_var = tk.IntVar(value=self.cfg["delay_days"])
        ttk.Spinbox(schedule_frame, from_=0, to=30, textvariable=delay_var, width=6).pack(
            anchor="w", pady=(SPACE["xs"], SPACE["md"]))

        ttk.Label(schedule_frame, text="Daily auto-run time (24h, HH:MM):").pack(anchor="w")
        time_var = tk.StringVar(value=self.cfg["run_time"])
        ttk.Entry(schedule_frame, textvariable=time_var, width=8).pack(
            anchor="w", pady=(SPACE["xs"], SPACE["md"]))

        auto_var = tk.BooleanVar(value=self.cfg["auto_run_enabled"])
        ttk.Checkbutton(schedule_frame, text="Enable automatic daily scan + deploy",
                         variable=auto_var).pack(anchor="w")

        security_frame = ttk.LabelFrame(container, text="Security & Verification", padding=SPACE["md"])
        security_frame.pack(fill="x", pady=(0, SPACE["md"]))

        ttk.Label(security_frame, text="NVD API key (optional, raises rate limit):").pack(anchor="w")
        key_var = tk.StringVar(value=self.cfg.get("nvd_api_key", ""))
        ttk.Entry(security_frame, textvariable=key_var, width=36, show="*").pack(
            anchor="w", pady=(SPACE["xs"], 0))

        storage_frame = ttk.LabelFrame(container, text="Storage", padding=SPACE["md"])
        storage_frame.pack(fill="x", pady=(0, SPACE["md"]))

        ttk.Label(storage_frame, text="Keep cached patch downloads for (days):").pack(anchor="w")
        retention_var = tk.IntVar(value=self.cfg.get("retention_days", 180))
        ttk.Spinbox(storage_frame, from_=30, to=730, textvariable=retention_var, width=6).pack(
            anchor="w", pady=(SPACE["xs"], SPACE["md"]))

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

        ttk.Button(storage_frame, text="Clean Up Old Patches Now", cursor="hand2",
                   command=cleanup_now).pack(anchor="w")

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

        ttk.Button(container, text="Save", style="Accent.TButton", cursor="hand2",
                   command=save_and_close).pack(pady=(SPACE["xs"], 0))

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
        win.geometry("520x500")
        win.resizable(False, False)

        frame = ttk.Frame(win, padding=SPACE["lg"])
        frame.pack(fill="both", expand=True)

        if entry is None:
            ttk.Label(frame, text="No verification has been attempted for this version yet.",
                      wraplength=440).pack(anchor="w")
            return

        pill_color = COLORS["accent"] if entry["verified"] else COLORS["danger"]
        pill_text = "✓ Verified" if entry["verified"] else "✗ Failed"
        tk.Label(frame, text=pill_text, font=FONT_UI_BOLD, background=pill_color,
                 foreground=COLORS["accent_fg"] if entry["verified"] else COLORS["text"],
                 padx=SPACE["md"], pady=SPACE["xs"]).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, SPACE["md"]))

        rows = [
            ("Package", pkg_id),
            ("Version", entry["version"]),
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
        for i, (label, value) in enumerate(rows, start=1):
            ttk.Label(frame, text=f"{label}:", font=FONT_UI_BOLD).grid(
                row=i, column=0, sticky="ne", pady=2)
            tk.Label(frame, text=str(value), wraplength=360, justify="left",
                     background=COLORS["bg"], foreground=COLORS["text"], font=FONT_UI).grid(
                row=i, column=1, sticky="w", padx=(SPACE["sm"], 0), pady=2)

    def on_view_status_log(self):
        win = tk.Toplevel(self.root)
        self._style_dialog(win)
        win.title("Status Log")
        win.geometry("780x440")
        win.minsize(420, 220)
        win.rowconfigure(0, weight=1)
        win.columnconfigure(0, weight=1)

        frame = ttk.Frame(win, padding=(SPACE["md"], SPACE["md"], SPACE["md"], 0))
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

        btn_bar = ttk.Frame(win, padding=SPACE["md"])
        btn_bar.grid(row=1, column=0, sticky="ew")
        ttk.Button(btn_bar, text="Refresh", cursor="hand2", command=refresh).pack(side="left")
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

    def _sort_by(self, col):
        if self._sort_state["column"] == col:
            self._sort_state["reverse"] = not self._sort_state["reverse"]
        else:
            self._sort_state["column"] = col
            self._sort_state["reverse"] = False
        self.refresh_table()

    @staticmethod
    def _sort_key(col, row):
        if col == "days_left":
            val = row["days_left"]
            if val == "Eligible now":
                return -1.0
            if val == "-":
                return float("inf")
            try:
                return float(val)
            except ValueError:
                return float("inf")
        if col == "cves":
            return row["_cve_count"]
        val = row.get(col, "")
        return val.lower() if isinstance(val, str) else val

    def _toggle_empty_state(self, is_empty):
        if is_empty:
            self.tree.grid_remove()
            self.yscroll.grid_remove()
            self.empty_state.grid(row=0, column=0, columnspan=2, sticky="nsew")
        else:
            self.empty_state.grid_remove()
            self.tree.grid(row=0, column=0, sticky="nsew")
            self.yscroll.grid(row=0, column=1, sticky="ns")

    def refresh_table(self):
        # Called repeatedly during a live scan (once per app), not just
        # once at the end -- preserve selection/scroll position across
        # rebuilds so the table doesn't jump around under the user while
        # a scan is still running.
        selected = self.tree.selection()
        scroll_pos = self.tree.yview()

        self._verification_cache = {(e["package_id"], e["version"]): e for e in state.get_patch_cache_entries()}

        rows = []
        critical_count = 0
        unverified_count = 0

        for app in state.get_all_apps():
            if not app["available_version"] or app["available_version"] == app["installed_version"]:
                continue  # only show apps with a pending update

            cves = json.loads(app["cves"] or "[]")
            cve_text = ", ".join(c["id"] for c in cves) if cves else "-"
            severities = [c["severity"] for c in cves]
            sev_tag = "clean"
            if "CRITICAL" in severities:
                sev_tag = "critical"
                critical_count += 1
            elif "HIGH" in severities:
                sev_tag = "high"

            entry = self._verification_cache.get((app["package_id"], app["available_version"]))
            verification_label, verify_failed = self._verification_label(entry)
            if not (entry and entry["verified"]):
                unverified_count += 1

            rows.append({
                "package_id": app["package_id"],
                "name": app["name"],
                "installed": app["installed_version"],
                "available": app["available_version"],
                "days_left": self._days_left(app),
                "cves": cve_text,
                "_cve_count": len(cves),
                "verification": verification_label,
                "status": app["deploy_status"],
                "_sev_tag": sev_tag,
                "_verify_failed": verify_failed,
            })

        self.stat_pending_var.set(str(len(rows)))
        self.stat_critical_var.set(str(critical_count))
        self.stat_unverified_var.set(str(unverified_count))

        sort_col = self._sort_state["column"]
        rows.sort(key=lambda r: self._sort_key(sort_col, r), reverse=self._sort_state["reverse"])

        for col in TABLE_COLUMNS:
            text = TABLE_HEADINGS[col]
            if col == sort_col:
                text += "  ▼" if self._sort_state["reverse"] else "  ▲"
            self.tree.heading(col, text=text)

        self.tree.delete(*self.tree.get_children())
        clean_index = 0
        for row in rows:
            if row["_sev_tag"] == "clean":
                band_tag = "clean_even" if clean_index % 2 == 0 else "clean_odd"
                clean_index += 1
            else:
                band_tag = row["_sev_tag"]
            tags = (("verify_failed",) if row["_verify_failed"] else ()) + (band_tag,)
            self.tree.insert("", "end", iid=row["package_id"], tags=tags, values=(
                row["name"], row["installed"], row["available"],
                row["days_left"], row["cves"], row["verification"], row["status"],
            ))

        self._toggle_empty_state(len(rows) == 0)

        for iid in selected:
            if self.tree.exists(iid):
                self.tree.selection_add(iid)
        self.tree.yview_moveto(scroll_pos[0])

        self.refresh_dashboard()

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
