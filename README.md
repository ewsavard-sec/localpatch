# LocalPatch

![CI](https://github.com/ewsavard-sec/localpatch/actions/workflows/ci.yml/badge.svg)

A simple local patch manager for Windows: scans installed software, checks
for new versions, cross-references known CVEs, and can auto-deploy updates
after a configurable "burn-in" delay.

## What this demonstrates

- **Local software inventory + vulnerability correlation** — scans installed
  software via `winget` and cross-references each app's installed version
  against the NVD (National Vulnerability Database) for known CVEs.
- **Download integrity verification** — every update is independently
  re-hashed (SHA256 against winget's own manifest) and Authenticode
  signature-checked before it's ever allowed near an install command; a
  failed check blocks deployment and is logged to an auditable table, not
  silently skipped.
- **Policy-driven automated deployment** — a configurable N-day "burn-in"
  delay before any update auto-deploys, plus a 6-month retention policy that
  purges cached installers to bound disk usage.
- **Scheduled, unattended operation** — runs as a Windows Scheduled Task via
  `schtasks`, so the whole scan → verify → deploy → purge pipeline can run
  daily with no user present.

## Screenshots

<!-- TODO: add real screenshots of the GUI here after running it -->

## Requirements

- Windows 10/11 with `winget` installed (comes preinstalled on current
  Windows; if missing, install "App Installer" from the Microsoft Store)
- Python 3.10+
- `pip install -r requirements.txt`

## Running it

```
python main.py
```

opens the GUI. Click **Scan Now** to inventory installed software, check
`winget` for available upgrades, and query NVD for known CVEs against each
installed version.

Only apps with a pending update show up in the table. Rows are shaded
orange/red if NVD returned HIGH/CRITICAL severity CVEs for that app.

### Headless usage (for scripting/testing)

```
python main.py --scan     # scan + update state, no GUI
python main.py --auto     # scan, then deploy anything past the delay window
python main.py --purge    # delete cached patches older than retention_days
```

### First run

If `config.json` doesn't exist yet, it's bootstrapped automatically from
`config.example.json` on first launch — `config.json` itself is gitignored
(it can hold an NVD API key) so it's never committed.

### Automatic daily runs

In **Settings**, set a delay (default 7 days) and check "Enable automatic
daily scan + deploy," then Save. This registers a Windows Scheduled Task
(`LocalPatchAutoDeploy`) that runs `python main.py --auto` once a day at
the time you chose. You can also do this from the command line:

```
python main.py --setup-schedule
python main.py --remove-schedule
```

## How the delay window works

The burn-in delay is anchored to when a patch **actually shipped**, not
when this machine happened to notice it. Each scan looks up the release
date winget's manifest reports for the available version (`winget show`)
and stores it as `release_date`; an app becomes eligible once
`now - release_date >= delay_days`. If winget doesn't report a release
date for a package, it falls back to `first_seen_available` — the
timestamp this machine first detected the update, the old behavior.
`release_date` has day-only granularity (no time-of-day), so the
countdown can be off by up to ~1 day depending what time you're looking
at it.

If a second new version is released before the delay elapses, the timer
resets to the new version's release date — you always get the full
burn-in period on whatever the current release actually is. Manual
"Deploy Selected" and the "Deploy All Shown" button both bypass the delay
for apps you pick (or everything currently shown) by hand; only "Deploy
All Eligible" respects it.

## How patch verification works

Nothing gets installed straight off the network. For every update, `deployer.py`'s
`winget upgrade` is only called after `patch_store.py` has:

1. Downloaded the installer via `winget download` into `patch_cache/<package>/<version>/`
2. Independently re-computed its SHA256 and checked it against the hash winget's
   own manifest declares for that package/version
3. Run `Get-AuthenticodeSignature` on the file and checked the result is `Valid`
   (and, if `trusted_publishers` is configured for that package, that the signer
   matches)

If any check fails, the deployment is **blocked and logged** — not skipped
silently. Every attempted download (pass or fail) is recorded in the
`patch_cache` table, and the GUI's Verification column and "View Verification
Log" dialog surface the full detail (expected vs. actual hash, signer, when it
was checked). Rows that failed verification are excluded from "Deploy All
Eligible" and require manual review.

By default `require_valid_signature` is `true`, which blocks unsigned
installers outright — set it to `false` in `config.json` to downgrade an
unsigned/untrusted result to a warning instead of a hard block (this reduces
the security guarantee; some legitimate installers do ship unsigned).

If `winget download` isn't usable on a given machine, verification falls back
to a weaker `manifest-only` mode that trusts the hash `winget show` reports
rather than independently re-downloading and re-hashing — this is always
labeled as such (never presented as a full independent verification).

Cached installers are purged automatically after `retention_days` (default
180) to bound disk usage — see `patch_store.purge_expired()`, the "Clean Up
Old Patches Now" Settings button, or `python main.py --purge`.

## Known limitations (read before relying on this)

- **Only covers apps `winget` knows about.** Software installed outside a
  winget-tracked source (some manually-installed tools, portable apps)
  won't show up. For broader coverage you'd extend `scanner.py` to also
  read the registry's Uninstall keys.
- **CVE matching is heuristic, not authoritative.** It resolves an app
  name to a CPE via NVD's keyword search and takes the closest match —
  this works well for well-known software (Chrome, Firefox, Java, Adobe
  Reader) and can miss or mismatch obscure/oddly-named packages. Treat
  flagged CVEs as a starting point to verify, not a guarantee, and treat
  the absence of a flagged CVE as "nothing found," not "confirmed safe."
- **NVD rate limits.** Without an API key you're limited to ~5 requests
  per 30 seconds, so a scan of many apps will be slow. Get a free key at
  nvd.nist.gov/developers/request-an-api-key and add it in Settings.
- **Silent installs aren't universal.** `winget upgrade --silent` works
  for most packages but a few installers still pop a UI regardless — you
  may see stalled auto-deploys for specific apps, in which case deploy
  those manually and check the app's installer.
- **Partially tested against real winget, not yet the full pipeline.**
  `patch_store.py`'s download/hash/signature verification and the retention
  purge have been run against a real `winget download` (confirmed the
  manifest format, the Authenticode output format, and that a corrupted
  file correctly fails verification) — but `scanner.py`'s live inventory
  scan, `deployer.py`'s actual `winget upgrade --silent` install, and
  `scheduler.py`'s `schtasks` registration haven't had a full end-to-end
  pass yet. Good first step: run `python main.py --scan` from a terminal
  and check the printed counts look right before touching auto-deploy or
  the scheduler.

## Project layout

```
main.py              CLI entry point / GUI launcher
gui.py               Tkinter interface
scanner.py           winget-based inventory + upgrade detection
cve_matcher.py       NVD CVE lookup
state.py             SQLite persistence + delay-window + patch_cache logic
patch_store.py       Download, hash/signature verification, retention purge
deployer.py          Runs winget upgrade for a given package
scheduler.py         Registers/removes the Windows Scheduled Task
tests/               pytest suite (delay window, verification, purge)
.github/workflows/   CI (runs pytest on windows-latest)
config.example.json  Settings template, tracked in git
config.json          Your local settings (gitignored, bootstrapped on first run)
```
