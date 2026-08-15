"""
scheduler.py — Registers/removes a Windows Scheduled Task that runs
LocalPatch's auto-deploy pass daily. Uses `schtasks`, which works for a
per-user task without needing the admin-only Task Scheduler COM APIs.
"""

import subprocess
import sys
from pathlib import Path

TASK_NAME = "LocalPatchAutoDeploy"


def enable(run_time="09:00"):
    main_py = str((Path(__file__).parent / "main.py").resolve())
    python_exe = sys.executable
    subprocess.run(
        [
            "schtasks", "/Create", "/TN", TASK_NAME, "/SC", "DAILY",
            "/ST", run_time, "/TR", f'"{python_exe}" "{main_py}" --auto',
            "/F",  # overwrite if it already exists
        ],
        check=True,
    )


def disable():
    subprocess.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"], check=False)


def is_enabled():
    result = subprocess.run(
        ["schtasks", "/Query", "/TN", TASK_NAME],
        capture_output=True, text=True,
    )
    return result.returncode == 0
