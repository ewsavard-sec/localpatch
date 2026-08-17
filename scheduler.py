"""
scheduler.py — Registers/removes a Windows Scheduled Task that runs
LocalPatch's auto-deploy pass daily.

The task is created with /RL HIGHEST so the DAILY UNATTENDED run installs
updates without a UAC prompt: Task Scheduler only asks for interactive
consent at the point a task is *authorized* to run elevated, not every
time an already-authorized task fires. Once main.py --auto is launched by
Task Scheduler with an elevated token, every winget call it makes inherits
that token and elevates silently too -- no prompt.

Creating (or deleting) a HIGHEST-privilege task is itself a privileged
operation, though, and LocalPatch normally runs unelevated. So enable()/
disable() invoke schtasks via ShellExecuteEx's "runas" verb -- this
elevates ONLY that one schtasks.exe call (one UAC prompt, once, when you
turn the setting on or off in Settings), rather than requiring the whole
LocalPatch GUI to run as Administrator all the time. Manual "Deploy
Selected"/"Deploy All..." clicks in the GUI are unaffected by any of this
and will still prompt for UAC when winget needs elevation -- that's
correct: those are YOU interactively triggering an admin action, which is
exactly what UAC exists to gate. This module only makes the unattended
scheduled path silent.
"""

import ctypes
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

TASK_NAME = "LocalPatchAutoDeploy"

_SW_HIDE = 0
_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_INFINITE = 0xFFFFFFFF


class _SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", ctypes.c_ulong),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hKeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]


def _run_via_shell(exe, args, verb):
    """
    Runs `exe args` via ShellExecuteEx with the given verb and waits for
    it to finish, returning its exit code. verb="runas" triggers a UAC
    consent prompt for this specific call; verb="open" does not (used by
    tests to exercise this plumbing without needing a human to click
    through a real UAC dialog).

    Raises RuntimeError if ShellExecuteEx itself fails to launch the
    process at all -- e.g. the user clicked "No" on the UAC prompt.
    """
    sei = _SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(_SHELLEXECUTEINFOW)
    sei.fMask = _SEE_MASK_NOCLOSEPROCESS
    sei.lpVerb = verb
    sei.lpFile = exe
    sei.lpParameters = subprocess.list2cmdline(args)
    sei.nShow = _SW_HIDE

    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei)):
        error = ctypes.GetLastError()
        raise RuntimeError(
            "Elevation was declined or failed -- this setting requires "
            f"administrator approval to change. Windows error code: {error}"
        )

    ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, _INFINITE)
    exit_code = wintypes.DWORD()
    ctypes.windll.kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(exit_code))
    ctypes.windll.kernel32.CloseHandle(sei.hProcess)
    return exit_code.value


def enable(run_time="09:00"):
    main_py = str((Path(__file__).parent / "main.py").resolve())
    python_exe = sys.executable
    args = [
        "/Create", "/TN", TASK_NAME, "/SC", "DAILY",
        "/ST", run_time, "/TR", f'"{python_exe}" "{main_py}" --auto',
        "/RL", "HIGHEST",
        "/F",  # overwrite if it already exists
    ]
    exit_code = _run_via_shell("schtasks.exe", args, verb="runas")
    if exit_code != 0:
        raise RuntimeError(f"schtasks /Create failed (exit code {exit_code}).")


def disable():
    # Non-fatal by design (matches the previous check=False behavior):
    # a nonzero exit here is usually just "task doesn't exist", which is
    # fine -- disable() should be idempotent.
    try:
        _run_via_shell("schtasks.exe", ["/Delete", "/TN", TASK_NAME, "/F"], verb="runas")
    except RuntimeError:
        pass


def is_enabled():
    result = subprocess.run(
        ["schtasks", "/Query", "/TN", TASK_NAME],
        capture_output=True, text=True,
    )
    return result.returncode == 0
