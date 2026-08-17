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
"""

import subprocess

_POWERSHELL_APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"

_TOAST_SCRIPT = """
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

$template = @"
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text>{title}</text>
            <text>{body}</text>
        </binding>
    </visual>
</toast>
"@

$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{app_id}').Show($toast)
"""


def _xml_escape(text):
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace('"', "&quot;").replace("'", "&apos;"))


def notify(title, body):
    """
    Fires a Windows toast notification. Fire-and-forget: failures are
    swallowed -- a notification is a nice-to-have that should never block
    or crash a scan, same philosophy as cve_matcher's network-error
    handling.
    """
    script = _TOAST_SCRIPT.format(
        title=_xml_escape(title), body=_xml_escape(body), app_id=_POWERSHELL_APP_ID,
    )
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=15,
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
