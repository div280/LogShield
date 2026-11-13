"""
admin_cmd.py -- Interactive and single-command runner for LogShield live forensic demonstration.
Executes real Windows commands and bridges telemetry directly into LogShield live stream.
"""
import sys
import os
import subprocess
import json
import re
from datetime import datetime, timezone

STREAM_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_tail", "admin_stream.jsonl")
os.makedirs(os.path.dirname(STREAM_FILE), exist_ok=True)

_counter_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "live_tail", ".counter")


def get_next_record_id() -> int:
    """Retrieve monotonically increasing record ID."""
    rid = 700000
    if os.path.exists(_counter_file):
        try:
            with open(_counter_file, "r") as f:
                rid = int(f.read().strip())
        except Exception:
            pass
    rid += 1
    try:
        with open(_counter_file, "w") as f:
            f.write(str(rid))
    except Exception:
        pass
    return rid


def execute_and_log(cmd_str: str) -> None:
    """Execute a real Windows command and record forensic telemetry.

    Parameters:
        cmd_str (str): Command to execute.

    Returns:
        None
    """
    if not cmd_str.strip():
        return

    cmd_clean = cmd_str.strip()
    print(f"\n[LogShield-Admin] >>> Executing: {cmd_clean}")

    start_time = datetime.now(timezone.utc)
    returncode = 0
    try:
        proc = subprocess.run(cmd_clean, shell=True, text=True)
        returncode = proc.returncode
    except Exception as err:
        print(f"[Execution Error]: {err}")
        returncode = 1

    # Forensic telemetry parsing
    rid = get_next_record_id()
    eid = 4688
    task = "Process Creation"
    account = os.environ.get("USERNAME", "Administrator")
    proc_name = "cmd.exe"
    tampered = 0
    tamper_type = "none"

    first_word = cmd_clean.split()[0].lower()
    if first_word.endswith(".exe"):
        proc_name = first_word
    else:
        proc_name = f"{first_word}.exe"

    lower_cmd = cmd_clean.lower()

    if "net user" in lower_cmd:
        proc_name = "net.exe"
        if "/add" in lower_cmd:
            eid = 4720
            task = "User Account Created"
            parts = cmd_clean.split()
            try:
                idx = [p.lower() for p in parts].index("user")
                if idx + 1 < len(parts):
                    account = parts[idx + 1]
            except Exception:
                pass
        elif "/del" in lower_cmd:
            eid = 4726
            task = "User Account Deleted"
            parts = cmd_clean.split()
            try:
                idx = [p.lower() for p in parts].index("user")
                if idx + 1 < len(parts):
                    account = parts[idx + 1]
            except Exception:
                pass
        else:
            eid = 4738
            task = "User Account Query/Modification"

    elif "wevtutil" in lower_cmd and ("cl" in lower_cmd or "clear" in lower_cmd):
        eid = 1102
        task = "Audit Log Cleared"
        proc_name = "wevtutil.exe"
        tampered = 1
        tamper_type = "audit_cleared"

    elif "mimikatz" in lower_cmd:
        eid = 4688
        proc_name = "mimikatz.exe"
        task = "Process Creation"
        tampered = 1
        tamper_type = "injection"

    elif "whoami" in lower_cmd:
        proc_name = "whoami.exe"
        task = "Privilege Discovery"

    event = {
        'source_file': 'LIVE_ADMIN_CMD',
        'event_record_id': rid,
        'event_id': eid,
        'time_created': start_time.isoformat(),
        'computer': os.environ.get("COMPUTERNAME", "WORKSTATION-01"),
        'provider': 'Microsoft-Windows-Security-Auditing',
        'channel': 'Security',
        'level': 'Information' if tampered == 0 else 'Critical',
        'task': task,
        'account_name': account,
        'process_name': proc_name,
        'event_data': f"Admin executed: {cmd_clean} (Exit code: {returncode})",
        'raw_xml_length': 400,
        'is_tampered': tampered,
        'tamper_type': tamper_type
    }

    with open(STREAM_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

    print(f"[LogShield-Admin] Forensic Telemetry Emitted -> Record #{rid} | Event ID {eid} ({task}) | Target: {account} | Process: {proc_name}\n")


def interactive_console():
    """Start an interactive command console for live forensic demonstration."""
    print("=" * 70)
    print("   LogShield Interactive Administrator Console")
    print("   Any command typed here runs on Windows AND streams live to LogShield SIEM")
    print("=" * 70)
    print("Type any Windows command (e.g., 'net user Yashu3 yashu /add', 'whoami', 'exit')\n")

    while True:
        try:
            cmd = input("LogShield-Admin> ")
            if not cmd.strip():
                continue
            if cmd.strip().lower() in ("exit", "quit"):
                print("Exiting console.")
                break
            execute_and_log(cmd)
        except (KeyboardInterrupt, EOFError):
            print("\nExiting console.")
            break


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Single command execution: python admin_cmd.py net user Yashu2 yashu /add
        cmd_to_run = " ".join(sys.argv[1:])
        execute_and_log(cmd_to_run)
    else:
        # Interactive shell: python admin_cmd.py
        interactive_console()

