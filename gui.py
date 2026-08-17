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
import notifier

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
FONT_STAT_LABEL = ("Segoe UI", 9, "bold")

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

TABLE_COLUMNS = ("name", "installed", "available", "days_left", "cves", "verification", "status")
TABLE_HEADINGS = {
    "name": "Application", "installed": "Installed", "available": "Available",
    "days_left": "Days Until Auto-Deploy", "cves": "Known CVEs",
    "verification": "Verification", "status": "Status",
}
TABLE_WIDTHS = {
    "name": 230, "installed": 110, "available": 110, "days_left": 150,
    "cves": 150, "verification": 175, "status": 90,
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
        self._deploy_active = False
        self._scan_cancel_event = None
        # True once a scan has completed (successfully, not cancelled/errored)
        # in this session -- lets the empty state distinguish "never scanned"
        # from "just scanned, genuinely nothing pending" (see U8/_toggle_empty_state).
        self._has_scanned = False
        # Soonest-eligible-first by default -- the most actionable rows surface at the top.
        self._sort_state = {"column": "days_left", "reverse": False}

        self._apply_theme()
        self._build_header()
        self._build_toolbar()
        self._build_dashboard()
        self._build_table()
        self._build_statusbar()
        self._update_button_states()

        # Route every uncaught exception raised inside a Tk callback (button
        # clicks, etc.) into the Status Log instead of just stderr -- this
        # is on top of the explicit try/except in the background worker
        # threads below, which Tk's own hook does NOT cover.
        self.root.report_callback_exception = self._handle_tk_exception

        state.init_db()
        self._reconcile_interrupted_deploys()
        self.refresh_table()

    def _reconcile_interrupted_deploys(self):
        """
        If the app was closed (or crashed) while a deploy was mid-flight,
        the affected row's deploy_status was left at 'deploying' forever --
        nothing else ever transitions it out of that state, so the table
        would show a permanently-stuck "In Progress". Sweep on startup,
        before the first refresh_table(), so that never happens. There's no
        WM_DELETE_WINDOW handler that could do this more gracefully on the
        way out, since a hard crash wouldn't hit it anyway -- reconciling on
        the way back in covers both cases.
        """
        with state.get_conn() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM apps WHERE deploy_status='deploying'"
            ).fetchone()[0]
            if count:
                conn.execute("UPDATE apps SET deploy_status='failed' WHERE deploy_status='deploying'")
        if count:
            app_log.warning(
                f"Reset {count} app(s) stuck in 'deploying' status -- interrupted "
                f"(app was closed or crashed) mid-deploy on a previous run."
            )

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

        self.deploy_selected_button = ttk.Button(bar, text="Deploy Selected", cursor="hand2",
                                                  command=self.on_deploy_selected)
        self.deploy_selected_button.pack(side="left")
        # "Deploy Ready Now" / "Deploy All (Skip Delay)" describe the actual
        # behavior difference directly -- "Eligible" vs "Shown" required
        # reading the code to tell apart. Method names (on_deploy_eligible /
        # on_deploy_all_shown) are unchanged; only the button labels moved.
        self.deploy_eligible_button = ttk.Button(bar, text="Deploy Ready Now", cursor="hand2",
                                                  command=self.on_deploy_eligible)
        self.deploy_eligible_button.pack(side="left", padx=(SPACE["sm"], 0))
        self.deploy_all_shown_button = ttk.Button(bar, text="Deploy All (Skip Delay)", cursor="hand2",
                                                   command=self.on_deploy_all_shown)
        self.deploy_all_shown_button.pack(side="left", padx=(SPACE["sm"], 0))

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
        # Labels spell out "(all installed)" / "(all time)" explicitly --
        # this card covers the WHOLE local inventory (see the docstring
        # above), not just apps with a pending update like the header stat
        # tiles do, so a near-identical unscoped label next to the header's
        # "CRITICAL CVEs" / "NOT VERIFIED" would read as a bug (same-looking
        # number, different scope, no visible reason why they'd differ).
        # The header already owns the unambiguous "what's actionable right
        # now" pending-updates count, so it isn't duplicated here.
        self._dashboard_row(self.status_card.body, len(critical_apps), "Apps with Critical CVEs (all installed)")
        self._dashboard_row(self.status_card.body, len(high_apps), "Apps with High CVEs (all installed)")
        self._dashboard_row(self.status_card.body, verify_failed, "Verification Failures (all time)")
        self._dashboard_row(self.status_card.body, deploy_failed, "Deploy Failures (all time)")

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
        # Column widths above are trimmed so the common case fits without
        # this at the default 1100px window width, but root.minsize(920,...)
        # is narrower than TABLE_WIDTHS' sum -- without a horizontal
        # scrollbar, Verification and Status (arguably the most important
        # columns) could get scrolled off-screen with no way back to them.
        self.xscroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.xscroll.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=self.yscroll.set, xscrollcommand=self.xscroll.set)

        # Dark-mode tints: subtle color washes rather than the light-mode
        # pastels a white-background app would use, so severity is still
        # readable against the dark surface instead of glowing. Rows with
        # no CVE hit alternate between two near-identical shades (zebra
        # striping) so long lists stay scannable without competing with
        # the severity tint on the rows that actually need attention.
        self.tree.tag_configure("critical", background="#3A1520")
        self.tree.tag_configure("high", background="#3A2A12")
        # MEDIUM/LOW severity previously fell through to "clean" -- visually
        # identical to an app with zero known CVEs, which reads as "no
        # color = no risk" even though real (lower-severity) CVEs exist.
        # #F8FAFC text on this background is ~14.3:1 -- comfortably above
        # WCAG AA's 4.5:1 -- and it's visually distinct from critical's red
        # tint and high's orange tint (dim olive/amber, not a top-tier alarm
        # color).
        self.tree.tag_configure("medium_low", background="#1E2A1A")
        self.tree.tag_configure("clean_even", background=COLORS["surface"])
        self.tree.tag_configure("clean_odd", background=COLORS["surface_alt"])
        # NOTE: this only ever affects text color, deliberately -- see the
        # comment on _verification_label for why "failed" is signaled via a
        # glyph in the cell value instead of (also) tinting the row red.
        # #FCA5A5 (vs. the original #EF4444) measures ~7.3-8.8:1 against the
        # backgrounds this can combine with (critical/high/clean row tints)
        # -- #EF4444 measured only 3.67-4.27:1 against critical/high tints,
        # under WCAG AA's 4.5:1 floor for normal text. See gui.py's fix
        # notes / conversation history for the full relative-luminance math.
        self.tree.tag_configure("verify_failed", foreground="#FCA5A5", font=FONT_UI_BOLD)

        # Empty state -- shares the same grid cell as the table and swaps
        # in via grid()/grid_remove() whenever there's nothing to show,
        # whether that's "no scan run yet" or "everything is patched." The
        # title/subtitle are kept as instance attrs (not fire-and-forget
        # locals) so _toggle_empty_state can reword them based on whether a
        # scan has actually run yet this session (see _has_scanned / U8).
        self.empty_state = ttk.Frame(table_frame)
        inner = ttk.Frame(self.empty_state)
        inner.place(relx=0.5, rely=0.42, anchor="center")
        tk.Label(inner, text="✓", font=("Segoe UI", 30, "bold"),
                 background=COLORS["bg"], foreground=COLORS["accent"]).pack()
        self.empty_state_title = tk.Label(inner, text="No pending updates", font=("Segoe UI", 13, "bold"),
                                           background=COLORS["bg"], foreground=COLORS["text"])
        self.empty_state_title.pack(pady=(SPACE["sm"], SPACE["xs"]))
        self.empty_state_subtitle = tk.Label(
            inner, text="Run a scan to check installed software for updates and known CVEs.",
            font=FONT_UI, background=COLORS["bg"], foreground=COLORS["muted"])
        self.empty_state_subtitle.pack()

    def _build_statusbar(self):
        bar = ttk.Frame(self.root, style="StatusBar.TFrame")
        bar.pack(fill="x", side="bottom")

        self.progress = ttk.Progressbar(bar, orient="horizontal", length=220, mode="determinate")
        # Not packed here -- only shown while a scan/deploy is running (see
        # _start_scan_progress/_start_deploy_progress and _finish_progress).

        text_box = tk.Frame(bar, background=COLORS["surface_alt"])
        text_box.pack(side="left", fill="x", expand=True, padx=SPACE["md"], pady=(SPACE["xs"], SPACE["xs"]))

        self.status_var = tk.StringVar(value="Ready.")
        self.status_label = tk.Label(
            text_box, textvariable=self.status_var, anchor="w",
            background=COLORS["surface_alt"], foreground=COLORS["muted"], font=FONT_UI,
        )
        self.status_label.pack(anchor="w", fill="x")

        # Secondary line -- patch progress count, start time, elapsed, etc.
        # Blank and takes no visible space when there's nothing to show.
        self.status_detail_var = tk.StringVar(value="")
        self.status_detail_label = tk.Label(
            text_box, textvariable=self.status_detail_var, anchor="w",
            background=COLORS["surface_alt"], foreground=COLORS["muted"], font=("Segoe UI", 9),
        )
        self.status_detail_label.pack(anchor="w", fill="x")

    def _set_status(self, text, kind="info", detail=""):
        color = {"info": COLORS["muted"], "success": COLORS["accent"], "error": COLORS["danger"]}.get(kind, COLORS["muted"])
        self.status_var.set(text)
        self.status_label.configure(foreground=color)
        self.status_detail_var.set(detail)

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

    def _start_deploy_progress(self, total):
        self.progress.configure(mode="determinate", maximum=total, value=0)
        self.progress.pack(side="right", padx=SPACE["md"], pady=SPACE["sm"])

    def _update_deploy_progress(self, i, total, name, version, phase, started_at, elapsed):
        self.progress.configure(value=i - 1 + (0.5 if phase == "installing" else 0))
        verb = "Verifying" if phase == "verifying" else "Installing"
        self._set_status(
            f"{verb} {name} ({version})...",
            detail=f"Patch {i} of {total}  •  Started {started_at}  •  Elapsed {self._format_duration(elapsed)}",
        )

    def _finish_progress(self, text, kind, detail=""):
        self.progress.stop()
        self.progress.pack_forget()
        self._set_status(text, kind, detail)

    def _handle_tk_exception(self, exc_type, exc_value, tb):
        app_log.error("Unhandled UI error: " + "".join(traceback.format_exception(exc_type, exc_value, tb)))
        self._set_status("An unexpected error occurred — see View Logs > Status Log.", "error")

    # ---------- Actions ----------

    def _set_busy(self):
        """
        The single source of truth for scan/deploy button enablement --
        called any time self._scan_active or self._deploy_active changes.
        Scanning and deploying are mutually exclusive (verify_and_record and
        the scan's own state reads/writes weren't designed to interleave),
        so either one being active disables Scan Now and all three Deploy
        buttons. Stop Scan is the exception: it's only ever meaningful (and
        enabled) while a scan specifically is running.
        """
        busy = self._scan_active or self._deploy_active
        self.scan_button.state(["disabled"] if busy else ["!disabled"])
        self.stop_scan_button.state(["!disabled"] if self._scan_active else ["disabled"])
        for btn in (self.deploy_selected_button, self.deploy_eligible_button, self.deploy_all_shown_button):
            btn.state(["disabled"] if busy else ["!disabled"])

    # Kept as an alias so __init__'s call site reads naturally either way.
    _update_button_states = _set_busy

    def on_scan(self):
        if self._scan_active or self._deploy_active:
            return
        self._scan_active = True
        self._scan_cancel_event = threading.Event()
        self._set_busy()

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
        self._set_busy()

    def _scan_worker(self, cancel_event):
        cancelled = False
        checked = 0
        total = 0
        try:
            # Snapshot once per scan, not read fresh from self.cfg every
            # iteration -- otherwise a Settings change (NVD key, notify
            # toggle) made while a scan is mid-flight would invisibly apply
            # different behavior to apps checked later in the SAME scan
            # than to the ones already checked.
            cfg_snapshot = dict(self.cfg)
            installed = {a["Id"]: a for a in scanner.scan_installed()}
            upgrades = {a["Id"]: a for a in scanner.scan_upgrades()}
            # Snapshot pre-scan CVE state once, up front -- diffed per-app
            # below so a notification only fires for genuinely new CVEs,
            # not the same known one every scan.
            prev_apps_by_id = {a["package_id"]: a for a in state.get_all_apps()}

            matcher = cve_matcher.CveMatcher(api_key=cfg_snapshot.get("nvd_api_key") or None)
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
                if available:
                    # get_release_date shells out (~0.66s) -- only worth
                    # paying for when the available version actually changed
                    # since the last scan; a release date never changes for
                    # a version we've already looked up.
                    prev = prev_apps_by_id.get(pkg_id) or {}
                    if prev.get("available_version") == available and prev.get("release_date"):
                        release_date = prev["release_date"]
                    else:
                        release_date = scanner.get_release_date(pkg_id, available)
                else:
                    release_date = None
                state.upsert_app(
                    package_id=pkg_id, name=app["Name"], source=app.get("Source", ""),
                    installed_version=app["Version"], available_version=available,
                    release_date=release_date,
                )
                cves = matcher.lookup(app["Name"], app["Version"])
                if cfg_snapshot.get("notify_new_cves", True):
                    prev_cves = json.loads((prev_apps_by_id.get(pkg_id) or {}).get("cves") or "[]")
                    new_cves = notifier.diff_new_cves(prev_cves, cves)
                    if new_cves:
                        notifier.notify_new_cves(app["Name"], new_cves)
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
                self.root.after(0, lambda: self._finish_progress(
                    f"Scan stopped. {checked}/{total} apps checked before stopping.", "info"))
            else:
                app_log.info(f"Scan complete: {len(installed)} apps checked, {len(upgrades)} updates found.")
                self._has_scanned = True
                self.root.after(0, lambda: self._finish_progress(
                    f"Scan complete. {len(installed)} apps checked, {len(upgrades)} updates found.", "success"))
        except Exception as e:
            app_log.error(f"Scan failed: {e}\n{traceback.format_exc()}")
            self.root.after(0, lambda: self._finish_progress(
                "Scan failed — see View Logs > Status Log.", "error"))
        self.root.after(0, self._reset_scan_buttons)
        self.root.after(0, self.refresh_table)

    def on_deploy_selected(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("LocalPatch", "Select at least one app first.")
            return
        self._deploy_many(selection)

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

    def on_deploy_all_shown(self):
        """
        Deploys every app currently in the table -- i.e. everything with a
        pending update, regardless of the delay-window burn-in period.
        Equivalent to selecting every row and hitting Deploy Selected (which
        already bypasses the delay for manually-picked apps), just in one
        click instead of many. 'Deploy All Eligible' is untouched and still
        respects the delay window.
        """
        shown_ids = list(self.tree.get_children())
        if not shown_ids:
            messagebox.showinfo("LocalPatch", "No apps with a pending update to deploy.")
            return

        apps_by_id = {a["package_id"]: a for a in state.get_all_apps()}
        cache = {(e["package_id"], e["version"]): e for e in state.get_patch_cache_entries()}
        deployable, blocked = [], []
        for pkg_id in shown_ids:
            app = apps_by_id.get(pkg_id)
            if not app:
                continue
            entry = cache.get((pkg_id, app["available_version"]))
            if entry and not entry["verified"]:
                blocked.append(app["name"])
            else:
                deployable.append(pkg_id)

        if blocked:
            messagebox.showwarning(
                "Some updates excluded",
                "These apps previously failed verification and are excluded from "
                "Deploy All Shown — review them individually via View Verification Log:\n\n"
                + "\n".join(blocked),
            )
        if not deployable:
            return
        self._deploy_many(deployable)

    def _deploy_many(self, iids):
        iids = list(iids)
        if not iids:
            return
        if self._scan_active or self._deploy_active:
            # Buttons are disabled while busy (see _set_busy), so this is a
            # defensive backstop, not the primary guard -- but it's cheap
            # insurance against a second deploy sneaking in through a stale
            # callback or a race between click and disable.
            messagebox.showinfo("LocalPatch", "A scan or deployment is already in progress.")
            return
        if not messagebox.askyesno("Confirm Deployment", f"Deploy {len(iids)} update(s) now?"):
            return
        self._deploy_active = True
        self._set_busy()
        self.root.after(0, lambda: self._start_deploy_progress(len(iids)))
        self._set_status(f"Deploying {len(iids)} update(s)...")
        threading.Thread(target=self._deploy_worker, args=(iids,), daemon=True).start()

    def _deploy_worker(self, package_ids):
        try:
            # Snapshot once per batch, not read fresh from self.cfg every
            # iteration -- otherwise a Settings change made mid-batch (e.g.
            # toggling require_valid_signature) would invisibly apply
            # different verification rules to later apps in the SAME
            # confirmed batch than it did to earlier ones.
            cfg_snapshot = dict(self.cfg)
            apps_by_id = {a["package_id"]: a for a in state.get_all_apps()}
            blocked = 0
            failed = 0
            deployed = 0
            total = len(package_ids)
            start = time.time()
            started_at = time.strftime("%H:%M:%S", time.localtime(start))

            for i, pkg_id in enumerate(package_ids, start=1):
                version = apps_by_id.get(pkg_id, {}).get("available_version", "unknown")
                name = apps_by_id.get(pkg_id, {}).get("name", pkg_id)

                # "In Progress" in the Status column from the moment this app
                # starts, not just once it's done -- and refresh right away so
                # it's visible before the (potentially slow) verify/install work
                # even begins.
                state.mark_deploying(pkg_id)
                self.root.after(0, lambda i=i, name=name, version=version:
                                 self._update_deploy_progress(i, total, name, version, "verifying",
                                                               started_at, time.time() - start))
                self.root.after(0, self.refresh_table)

                try:
                    result = patch_store.verify_and_record(pkg_id, version, cfg_snapshot)
                    # Verification column updates the instant the result is
                    # known, independent of whether the install step (next)
                    # even runs.
                    self.root.after(0, self.refresh_table)

                    if not result.verified:
                        state.mark_deployed(pkg_id, version, success=False)
                        app_log.warning(f"Blocked deploy: {name} {version} -- {result.reason}")
                        blocked += 1
                        self.root.after(0, self.refresh_table)
                        continue

                    self.root.after(0, lambda i=i, name=name, version=version:
                                     self._update_deploy_progress(i, total, name, version, "installing",
                                                                   started_at, time.time() - start))

                    success, log = deployer.deploy(pkg_id, version)
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

                self.root.after(0, self.refresh_table)

            elapsed_total = self._format_duration(time.time() - start)
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
            detail = f"{total} patch{'es' if total != 1 else ''} scanned  •  Started {started_at}  •  Elapsed {elapsed_total}"
            self.root.after(0, lambda: self._finish_progress(summary, kind, detail))
        finally:
            # Covers success, the caught per-app exceptions above (which
            # don't propagate), and any unexpected exception that somehow
            # escapes the loop -- either way, Scan Now and the Deploy
            # buttons must not stay disabled forever.
            self._deploy_active = False
            self.root.after(0, self._set_busy)
            self.root.after(0, self.refresh_table)

    def on_settings(self):
        win = tk.Toplevel(self.root)
        self._style_dialog(win)
        win.title("Settings")
        win.geometry("460x620")
        win.minsize(420, 320)
        win.resizable(True, True)

        # Scrollable content: this dialog has grown a new LabelFrame/checkbox
        # almost every round of fixes, and a fixed-height non-resizable
        # window kept clipping content at the bottom (confirmed via a real
        # screenshot -- the manifest-only checkbox's hint text was cut off).
        # A Canvas+inner-Frame scroll region can't overflow again regardless
        # of how many more settings get added later. Save stays outside the
        # scroll area so it's always reachable without scrolling to it.
        save_bar = ttk.Frame(win, padding=(SPACE["lg"], SPACE["sm"], SPACE["lg"], SPACE["lg"]))
        save_bar.pack(side="bottom", fill="x")

        vscroll = ttk.Scrollbar(win, orient="vertical")
        vscroll.pack(side="right", fill="y")

        canvas = tk.Canvas(win, background=COLORS["bg"], highlightthickness=0,
                            yscrollcommand=vscroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        vscroll.configure(command=canvas.yview)

        container = ttk.Frame(canvas, padding=SPACE["lg"])
        canvas_window = canvas.create_window((0, 0), window=container, anchor="nw")

        def _on_container_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        container.bind("<Configure>", _on_container_configure)

        def _on_canvas_configure(event):
            canvas.itemconfig(canvas_window, width=event.width)
        canvas.bind("<Configure>", _on_canvas_configure)

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)

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
        tk.Label(
            schedule_frame,
            text="Runs elevated so the daily run installs updates without a UAC prompt. "
                 "Toggling this asks for administrator approval once, here — manual "
                 "Deploy clicks in this window still prompt, as expected.",
            font=("Segoe UI", 9), wraplength=340, justify="left",
            background=COLORS["bg"], foreground=COLORS["muted"],
        ).pack(anchor="w", pady=(SPACE["xs"], 0))

        security_frame = ttk.LabelFrame(container, text="Security & Verification", padding=SPACE["md"])
        security_frame.pack(fill="x", pady=(0, SPACE["md"]))

        ttk.Label(security_frame, text="NVD API key (optional, raises rate limit):").pack(anchor="w")
        key_var = tk.StringVar(value=self.cfg.get("nvd_api_key", ""))
        ttk.Entry(security_frame, textvariable=key_var, width=36, show="*").pack(
            anchor="w", pady=(SPACE["xs"], 0))

        require_sig_var = tk.BooleanVar(value=self.cfg.get("require_valid_signature", True))
        ttk.Checkbutton(security_frame, text="Require a valid Authenticode signature before deploying",
                         variable=require_sig_var).pack(anchor="w", pady=(SPACE["md"], 0))
        tk.Label(
            security_frame,
            text="Recommended. Disabling this allows verified-but-unsigned installers to "
                 "deploy (advisory-only signature check).",
            font=("Segoe UI", 9), wraplength=340, justify="left",
            background=COLORS["bg"], foreground=COLORS["muted"],
        ).pack(anchor="w", pady=(SPACE["xs"], 0))

        manifest_only_var = tk.BooleanVar(value=self.cfg.get("allow_manifest_only_verification", False))
        ttk.Checkbutton(security_frame,
                         text="Allow manifest-only verification when winget download isn't available",
                         variable=manifest_only_var).pack(anchor="w", pady=(SPACE["md"], 0))
        tk.Label(
            security_frame,
            text="When `winget download` can't be used, falls back to trusting winget's own "
                 "manifest-reported hash instead of independently downloading and hashing a "
                 "file. That's a real, but materially weaker, guarantee. Leave this off unless "
                 "you've accepted that tradeoff explicitly.",
            font=("Segoe UI", 9), wraplength=340, justify="left",
            background=COLORS["bg"], foreground=COLORS["muted"],
        ).pack(anchor="w", pady=(SPACE["xs"], 0))

        notify_frame = ttk.LabelFrame(container, text="Notifications", padding=SPACE["md"])
        notify_frame.pack(fill="x", pady=(0, SPACE["md"]))

        notify_var = tk.BooleanVar(value=self.cfg.get("notify_new_cves", True))
        ttk.Checkbutton(notify_frame, text="Notify me when a new CVE is found for an installed app",
                         variable=notify_var).pack(anchor="w")
        tk.Label(
            notify_frame,
            text="Windows toast notification, informative only (no click-to-open -- "
                 "that needs a packaged app, which this isn't).",
            font=("Segoe UI", 9), wraplength=340, justify="left",
            background=COLORS["bg"], foreground=COLORS["muted"],
        ).pack(anchor="w", pady=(SPACE["xs"], 0))

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
            self.cfg["nvd_api_key"] = key_var.get().strip()
            self.cfg["require_valid_signature"] = require_sig_var.get()
            self.cfg["allow_manifest_only_verification"] = manifest_only_var.get()
            self.cfg["notify_new_cves"] = notify_var.get()
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

        ttk.Button(save_bar, text="Save", style="Accent.TButton", cursor="hand2",
                   command=save_and_close).pack()

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
                 foreground=COLORS["muted"], font=("Segoe UI", 9)).pack(side="right")

        refresh()

    # ---------- Rendering ----------

    @staticmethod
    def _verification_label(entry):
        """Returns (label, is_failed) for the Verification column."""
        if entry is None:
            return "Not checked yet", False
        if entry["verified"]:
            # manifest-only passes never downloaded or hashed a file
            # themselves (see patch_store._fallback_manifest_only) --
            # a materially weaker guarantee than a full verification, so
            # it must never be shown as a plain, indistinguishable
            # "Verified" here.
            if entry["verification_mode"] == "manifest-only":
                return "Verified (manifest only)", False
            return "Verified", False
        # ttk.Treeview tags apply per-row, not per-cell -- there's no way to
        # color just the Verification column red without also tinting every
        # other column (which then fuses with severity tinting on a
        # critical/high row that ALSO failed verification, reading as
        # "everything is red" with no distinguishable signal). So the
        # failure signal lives in the cell text itself via this glyph, and
        # the row-level "verify_failed" tag only lightens the text color
        # (see its tag_configure call in _build_table) rather than
        # overriding it to a bg-contrast-failing red.
        if not entry["hash_match"]:
            return "⚠ Failed — hash mismatch", True
        return "⚠ Failed — unsigned", True

    _STATUS_LABELS = {
        "idle": "-",
        "deploying": "In Progress",
        "deployed": "Complete",
        "failed": "Failed",
    }

    @classmethod
    def _status_label(cls, deploy_status):
        return cls._STATUS_LABELS.get(deploy_status, deploy_status)

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
            self.xscroll.grid_remove()
            if self._has_scanned:
                # A scan JUST ran and correctly found nothing pending --
                # telling the user to "run a scan" right after they did one
                # is actively confusing, so this is worded as a result
                # rather than an instruction.
                self.empty_state_title.configure(text="Everything is up to date")
                self.empty_state_subtitle.configure(text="No pending updates as of your last scan.")
            else:
                self.empty_state_title.configure(text="No pending updates")
                self.empty_state_subtitle.configure(
                    text="Run a scan to check installed software for updates and known CVEs.")
            self.empty_state.grid(row=0, column=0, columnspan=2, sticky="nsew")
        else:
            self.empty_state.grid_remove()
            self.tree.grid(row=0, column=0, sticky="nsew")
            self.yscroll.grid(row=0, column=1, sticky="ns")
            self.xscroll.grid(row=1, column=0, sticky="ew")

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
            if not cves:
                cve_text = "-"
            elif len(cves) > 3:
                # Full list is one click away via the row itself / dashboard
                # risk card -- this just needs to signal "there's more" so a
                # truncated list doesn't read as the complete picture.
                cve_text = ", ".join(c["id"] for c in cves[:3]) + f", +{len(cves) - 3} more"
            else:
                cve_text = ", ".join(c["id"] for c in cves)
            severities = [c["severity"] for c in cves]
            sev_tag = "clean"
            if "CRITICAL" in severities:
                sev_tag = "critical"
                critical_count += 1
            elif "HIGH" in severities:
                sev_tag = "high"
            elif "MEDIUM" in severities or "LOW" in severities:
                # Previously fell through to "clean" -- visually identical
                # to an app with zero known CVEs, i.e. "no color = no risk"
                # even when real (lower-severity) CVEs exist. See U5 in the
                # UI review / tag_configure("medium_low", ...) in _build_table.
                sev_tag = "medium_low"

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
                "status": self._status_label(app["deploy_status"]),
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
        # Same anchor preference as state.get_eligible_for_autodeploy():
        # release_date when winget reports one, otherwise local detection
        # time -- so this column always matches what actually gates
        # Deploy All Eligible instead of showing a different countdown.
        anchor = app["release_date"] or app["first_seen_available"]
        if not anchor:
            return "-"
        anchor_ts = state.parse_anchor_timestamp(anchor)
        if anchor_ts is None:
            return "-"
        elapsed_days = (time.time() - anchor_ts) / 86400
        remaining = self.cfg["delay_days"] - elapsed_days
        return "Eligible now" if remaining <= 0 else f"{remaining:.1f}"


def main():
    root = tk.Tk()
    LocalPatchApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
