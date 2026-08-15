# LocalPatch

A simple local patch manager for Windows: scans installed software, checks
for new versions, cross-references known CVEs, and can auto-deploy updates
after a configurable "burn-in" delay.

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
```

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

Each app's row stores `first_seen_available` — the timestamp the *current*
available version was first detected. An app only becomes eligible for
auto-deploy once `now - first_seen_available >= delay_days`. If a second
new version is released before the delay elapses, the timer resets to the
new version's detection time — you always get the full burn-in period on
whatever the current release actually is. Manual "Deploy Selected" in the
GUI bypasses the delay for anything you pick by hand.

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
- **This hasn't been run on a live Windows machine yet** — it was built
  and unit-tested for its Windows-independent logic (the SQLite/delay-
  window code), but the `winget`/`schtasks` integration needs a real test
  pass on your machine. Good first step: run `python main.py --scan` from
  a terminal and check the printed counts look right before touching the
  GUI or the scheduler.

## Project layout

```
main.py          CLI entry point / GUI launcher
gui.py           Tkinter interface
scanner.py       winget-based inventory + upgrade detection
cve_matcher.py   NVD CVE lookup
state.py         SQLite persistence + delay-window logic
deployer.py      Runs winget upgrade for a given package
scheduler.py     Registers/removes the Windows Scheduled Task
config.json      Settings (delay days, auto-run, NVD key)
```
