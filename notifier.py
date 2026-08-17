"""
notifier.py — Windows toast notifications for newly discovered CVEs.

Uses the WinRT toast API (Windows.UI.Notifications) directly, invoked via
PowerShell -- the same "shell out to PowerShell for a Windows-native
capability" pattern patch_store.py already uses for Authenticode checks,
rather than adding a third-party notification package.

Real-world notes from testing on the target machine:
- The commonly-suggested "no dependencies" trick --
  System.Windows.Forms.NotifyIcon's balloon tip -- did NOT reliably
  display. Balloon tips need an active message loop that a short-lived
  script doesn't provide. The WinRT toast API works without one and was
  confirmed visible.
- Non-packaged scripts have no AppUserModelID of their own to register a
  toast under, so this borrows PowerShell's own well-known AppID --
  notifications appear as coming from "Windows PowerShell" in the Action
  Center, not "LocalPatch". There's no clean way around that short of
  packaging this as a signed MSIX app.
- Click-to-open was attempted via activationType="protocol" + a
  `localpatch:` URI handler registered under HKEY_CURRENT_USER. The
  registry handler itself worked fine for classic ShellExecute resolution
  (confirmed: `Start-Process "localpatch:open"` launched the app
  correctly) -- but Action Center's toast-click activation does NOT use
  that resolution path. It requires a properly packaged MSIX/AppX app
  with a declared URI scheme, which non-packaged scripts don't have.
  Clicking without one shows Windows' "Get an app to open this link"
  dialog -- worse than no click handling at all. Dropped rather than
  shipped broken; see the 2026-08-17 Iteration Log for the full story.

SECURITY (2026-08-17 finding, fixed here): title/body ultimately originate
from app display names, which come from scanner.scan_installed() ->
`winget list` -> the ARP/uninstall-registry DisplayName -- a value any
unprivileged local process can write with no admin rights. The original
version of this module built _TOAST_SCRIPT with `.format()`, interpolating
title/body directly into a PowerShell **double-quoted** here-string
(`@" ... "@`). Double-quoted here-strings expand `$(...)` subexpressions,
so an app "named" `$(some-command)` got that command EXECUTED by
powershell.exe -- a full local-to-elevated RCE chain once scheduler.py's
`/RL HIGHEST` daily task is in the picture. `_xml_escape()` below only
ever protected against malformed XML, never against this -- it escapes
`& < > " '`, none of which stop `$(...)` or backtick expansion.

The fix: title/body now cross the process boundary as environment
variables (LP_TOAST_TITLE / LP_TOAST_BODY), never as text spliced into the
script. Env var values are opaque strings to PowerShell -- $env:X is a
runtime lookup, not something PowerShell re-parses as code, so this closes
the entire "untrusted text becomes untrusted code" bug class rather than
trying to enumerate more characters to escape. The script then assigns
those values into the toast XML via the DOM (CreateTextNode/AppendChild)
instead of string concatenation, which also makes XML-escaping a non-issue
for this path -- CreateTextNode encodes the text as data, not markup.
"""

import os
import subprocess

_POWERSHELL_APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"

# NOTE: the template below is a *single*-quoted here-string (@' ... '@),
# not double-quoted (@" ... "@) -- single-quoted here-strings do NOT expand
# $(...) or variables at all, so even the literal, static <text></text>
# placeholders here can never be a vector. The only place untrusted data
# enters is via $env:LP_TOAST_TITLE / $env:LP_TOAST_BODY, read at runtime
# and inserted through the XML DOM (CreateTextNode), never through string
# interpolation of any kind. app_id below IS still substituted via Python's
# .format() -- that's safe because it's a fixed module-level constant, not
# attacker-controlled input.
_TOAST_SCRIPT = """
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

$template = @'
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text></text>
            <text></text>
        </binding>
    </visual>
</toast>
'@

$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)

$textNodes = $xml.GetElementsByTagName('text')
$textNodes.Item(0).AppendChild($xml.CreateTextNode($env:LP_TOAST_TITLE)) | Out-Null
$textNodes.Item(1).AppendChild($xml.CreateTextNode($env:LP_TOAST_BODY)) | Out-Null

$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{app_id}').Show($toast)
"""


def _xml_escape(text):
    """
    Retained for any caller that ends up building toast XML by string
    concatenation (e.g. a future template with more fields). notify()
    itself no longer needs this: title/body are inserted via
    CreateTextNode, which already treats them as opaque text data, not
    markup, so pre-escaping them here would just show literal "&amp;"
    etc. in the toast instead of "&". This function is NOT a substitute
    for the env-var boundary above -- see the module docstring.
    """
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace('"', "&quot;").replace("'", "&apos;"))


def notify(title, body):
    """
    Fires a Windows toast notification. Fire-and-forget: failures are
    swallowed -- a notification is a nice-to-have that should never block
    or crash a scan, same philosophy as cve_matcher's network-error
    handling.

    title/body are passed to PowerShell as environment variables rather
    than interpolated into the script text -- see the module docstring's
    2026-08-17 finding for why that distinction is load-bearing.
    """
    script = _TOAST_SCRIPT.format(app_id=_POWERSHELL_APP_ID)
    env = {**os.environ, "LP_TOAST_TITLE": title, "LP_TOAST_BODY": body}
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=15, env=env,
        )
    except Exception:
        pass


def diff_new_cves(prev_cves, new_cves):
    """
    Returns the entries in new_cves whose id wasn't present in prev_cves --
    genuinely new discoveries, not a CVE already known from a prior scan.
    Both are lists of {id, severity, url} dicts (the format state.py stores
    per app). Centralized here so "what counts as new" is defined once,
    rather than duplicated at each call site.
    """
    prev_ids = {c.get("id") for c in prev_cves}
    return [c for c in new_cves if c.get("id") not in prev_ids]


_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def _worst_severity(cves):
    present = {c.get("severity") for c in cves}
    for sev in _SEVERITY_ORDER:
        if sev in present:
            return sev
    return None


def notify_new_cves(app_name, new_cves):
    """new_cves: list of {id, severity, url} dicts not previously known for this app."""
    if not new_cves:
        return
    ids = [c.get("id", "?") for c in new_cves]
    id_text = ", ".join(ids[:5])
    if len(ids) > 5:
        id_text += f", +{len(ids) - 5} more"
    worst = _worst_severity(new_cves)
    title = (f"LocalPatch: new CVE for {app_name}" if len(new_cves) == 1
             else f"LocalPatch: {len(new_cves)} new CVEs for {app_name}")
    body = f"{id_text} ({worst})" if worst else id_text
    notify(title, body)
