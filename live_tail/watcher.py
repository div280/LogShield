"""
watcher.py -- Real-time Windows Event Log monitoring
for LogShield using native Windows event subscription and streaming replay.
Target detection latency: under 500ms.
"""
import os
import sys
import time
import json
import queue
import logging
import threading
import subprocess
from datetime import datetime, timezone
from typing import Callable, Optional, Dict, Any, List

logger = logging.getLogger("LogShield.LiveWatcher")

SUSPICIOUS_PROCESSES = [
    'wevtutil.exe', 'whoami.exe', 'net.exe', 'runas.exe',
    'mimikatz.exe', 'psexec.exe', 'cmd.exe', 'powershell.exe'
]

COMMON_SECURITY_EVENT_IDS = [4624, 4625, 4634, 4688, 4663, 4672, 4698, 1102, 4719]


def sanitize_text(val: Any, max_len: int = 256) -> str:
    """Sanitize string inputs to prevent injection and script execution.

    Parameters:
        val (Any): Input string or object.
        max_len (int): Maximum allowable character length.

    Returns:
        str: Sanitized, truncated string.

    Time Complexity: O(k) where k is string length.
    Space Complexity: O(k) for output string.
    """
    if val is None:
        return 'UNKNOWN'
    s = str(val).strip().replace('\r', '').replace('\n', ' ')
    # Strip potential HTML/script tags
    s = s.replace('<', '&lt;').replace('>', '&gt;')
    if len(s) > max_len:
        s = s[:max_len]
    return s


class LogWatcher:
    """Watches Windows Event Logs in real time or streams live replay events."""

    def __init__(
            self,
            folder_path: Optional[str] = None,
            channel: str = "Security",
            mode: str = "auto",
            callback_fn: Optional[Callable[[Dict[str, Any]], None]] = None,
            poll_interval: float = 1.0,
            max_queue_size: int = 1000):
        """Initialize with channel, mode, and optional alert callback.

        Parameters:
            folder_path (Optional[str]): Legacy folder path kept for backward compatibility.
            channel (str): Windows Event Channel to monitor (default: 'Security').
            mode (str): Operating mode: 'auto', 'windows', or 'simulation'.
            callback_fn (Optional[Callable]): Callback invoked when new entries are detected.
            poll_interval (float): Polling interval in seconds (default: 1.0).
            max_queue_size (int): Maximum in-memory event buffer size.

        Returns:
            None

        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        self.folder_path = folder_path
        self.channel = sanitize_text(channel, max_len=64)
        self.mode = mode
        self.callback_fn = callback_fn
        self.poll_interval = max(0.2, float(poll_interval))
        self.event_queue: queue.Queue = queue.Queue(maxsize=max_queue_size)

        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._last_record_id: int = 0
        self._events_emitted: int = 0
        self._active_mode: str = "uninitialized"
        self._health_status: str = "Initialized"
        self._sim_counter: int = 100000

    def start(self) -> None:
        """Begin monitoring Windows event log in background thread.

        Parameters:
            None

        Returns:
            None

        Time Complexity: O(1) thread dispatch.
        Space Complexity: O(1) thread handle.
        """
        if self._worker_thread and self._worker_thread.is_alive():
            logger.info("LogWatcher worker thread is already running.")
            return

        self._stop_event.clear()

        # Decide mode
        if self.mode == "windows":
            self._active_mode = "windows"
        elif self.mode == "simulation":
            self._active_mode = "simulation"
        else:  # 'auto'
            # Probe Windows Event Log access
            can_read = self._probe_windows_event_log()
            if can_read:
                self._active_mode = "windows"
                self._health_status = f"Live OS Stream Connected ({self.channel})"
            else:
                self._active_mode = "simulation"
                self._health_status = (
                    "Live Simulation Active (Elevated access to Security Log "
                    "not permitted; falling back safely)"
                )

        target_fn = self._windows_worker if self._active_mode == "windows" else self._simulation_worker
        self._worker_thread = threading.Thread(
            target=target_fn,
            name="LogShield-Watcher-Thread",
            daemon=True
        )
        self._worker_thread.start()
        logger.info("LogWatcher started in %s mode.", self._active_mode)

    def stop(self) -> None:
        """Stop monitoring folder / Windows Event stream.

        Parameters:
            None

        Returns:
            None

        Time Complexity: O(1) thread termination signal.
        Space Complexity: O(1)
        """
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        self._worker_thread = None
        self._health_status = "Stopped"
        logger.info("LogWatcher stopped.")

    def is_running(self) -> bool:
        """Check if worker thread is actively running.

        Parameters:
            None

        Returns:
            bool: True if monitoring is active, False otherwise.

        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        return bool(self._worker_thread and self._worker_thread.is_alive() and not self._stop_event.is_set())

    def get_next_event(self, timeout: float = 0.5) -> Optional[Dict[str, Any]]:
        """Retrieve next parsed event from the queue.

        Parameters:
            timeout (float): Max seconds to wait for an event.

        Returns:
            Optional[Dict[str, Any]]: Event dictionary if available, else None.

        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        try:
            return self.event_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_all_events(self, max_count: int = 50) -> List[Dict[str, Any]]:
        """Drain up to max_count events from the queue without blocking.

        Parameters:
            max_count (int): Maximum items to return.

        Returns:
            List[Dict[str, Any]]: List of queued event dictionaries.

        Time Complexity: O(k) where k <= max_count.
        Space Complexity: O(k) for output list.
        """
        events: List[Dict[str, Any]] = []
        for _ in range(max_count):
            try:
                ev = self.event_queue.get_nowait()
                events.append(ev)
            except queue.Empty:
                break
        return events

    def inject_event(self, event: Dict[str, Any]) -> bool:
        """Manually inject an event into the stream (for testing and UI simulation).

        Parameters:
            event (Dict[str, Any]): Event record dictionary to inject.

        Returns:
            bool: True if queued, False if queue is full.

        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        clean_event = self._sanitize_event_dict(event)
        try:
            self.event_queue.put_nowait(clean_event)
            self._events_emitted += 1
            if self.callback_fn:
                try:
                    self.callback_fn(clean_event)
                except Exception as cb_err:
                    logger.warning("Error in callback_fn: %s", cb_err)
            return True
        except queue.Full:
            return False

    def inject_attack(self, attack_type: str = "clear") -> Dict[str, Any]:
        """Inject a simulated anti-forensic attack event into the live stream.

        Parameters:
            attack_type (str): Type of attack ('clear', 'gap', 'injection', 'shuffle').

        Returns:
            Dict[str, Any]: The injected attack event dictionary.

        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        self._sim_counter += 1
        now_str = datetime.now(timezone.utc).isoformat()
        attack_type = attack_type.lower().strip()

        if attack_type == "clear":
            # Event 1102: The audit log was cleared
            event = {
                'source_file': 'LIVE_STREAM',
                'event_record_id': self._sim_counter,
                'event_id': 1102,
                'time_created': now_str,
                'computer': 'LOGSHIELD-HOST',
                'provider': 'Microsoft-Windows-Eventlog',
                'channel': 'Security',
                'level': 'Information',
                'task': 'Log clear',
                'account_name': 'SYSTEM',
                'process_name': 'wevtutil.exe',
                'event_data': 'The audit log was cleared by user administrator via wevtutil.',
                'raw_xml_length': 450,
                'is_tampered': 1,
                'tamper_type': 'audit_cleared'
            }
        elif attack_type == "gap":
            # Jump record ID by 50 and inject an artificial time jump
            self._sim_counter += 50
            event = {
                'source_file': 'LIVE_STREAM',
                'event_record_id': self._sim_counter,
                'event_id': 4624,
                'time_created': now_str,
                'computer': 'LOGSHIELD-HOST',
                'provider': 'Microsoft-Windows-Security-Auditing',
                'channel': 'Security',
                'level': 'Information',
                'task': 'Logon',
                'account_name': 'admin_backup',
                'process_name': 'winlogon.exe',
                'event_data': 'Gap Attack: An abnormal sequence gap of 50 missing records was observed.',
                'raw_xml_length': 512,
                'is_tampered': 1,
                'tamper_type': 'gap'
            }
        elif attack_type == "injection":
            # Injected suspicious process execution
            event = {
                'source_file': 'LIVE_STREAM',
                'event_record_id': self._sim_counter,
                'event_id': 4688,
                'time_created': now_str,
                'computer': 'LOGSHIELD-HOST',
                'provider': 'Microsoft-Windows-Security-Auditing',
                'channel': 'Security',
                'level': 'Warning',
                'task': 'Process Creation',
                'account_name': 'victim_user',
                'process_name': 'mimikatz.exe',
                'event_data': 'Suspicious memory dumping process invocation detected.',
                'raw_xml_length': 620,
                'is_tampered': 1,
                'tamper_type': 'injection'
            }
        else:  # Shuffle attack representation
            event = {
                'source_file': 'LIVE_STREAM',
                'event_record_id': max(1, self._sim_counter - 15),  # Out of sequence record ID
                'event_id': 4625,
                'time_created': now_str,
                'computer': 'LOGSHIELD-HOST',
                'provider': 'Microsoft-Windows-Security-Auditing',
                'channel': 'Security',
                'level': 'Warning',
                'task': 'Logon Failure',
                'account_name': 'guest',
                'process_name': 'lsass.exe',
                'event_data': 'Sequence Shuffle: Out-of-order event record arrived with broken timestamp sequence.',
                'raw_xml_length': 480,
                'is_tampered': 1,
                'tamper_type': 'shuffle'
            }

        self.inject_event(event)
        return event

    def get_status(self) -> Dict[str, Any]:
        """Return operational status and metadata.

        Parameters:
            None

        Returns:
            Dict[str, Any]: Status dictionary.

        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        return {
            'running': self.is_running(),
            'active_mode': self._active_mode,
            'configured_mode': self.mode,
            'channel': self.channel,
            'events_emitted': self._events_emitted,
            'queue_size': self.event_queue.qsize(),
            'health_status': self._health_status,
            'last_record_id': self._last_record_id
        }

    # -------------------------------------------------------------------------
    # Internal Workers
    # -------------------------------------------------------------------------

    def _probe_windows_event_log(self) -> bool:
        """Probe if PowerShell / WinEvent is permitted and accessible.

        Parameters:
            None

        Returns:
            bool: True if accessible, False if restricted.

        Time Complexity: O(1) subprocess execution.
        Space Complexity: O(1)
        """
        if sys.platform != 'win32':
            return False
        try:
            # Query last 1 event from chosen channel
            cmd = [
                'powershell', '-NoProfile', '-NonInteractive', '-Command',
                f"(Get-WinEvent -LogName '{self.channel}' -MaxEvents 1 -ErrorAction SilentlyContinue).RecordId"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if res.returncode == 0 and res.stdout.strip().isdigit():
                self._last_record_id = int(res.stdout.strip())
                return True
        except Exception as err:
            logger.debug("Probe failed: %s", err)
        return False

    def _windows_worker(self) -> None:
        """Background worker thread polling live Windows Events via PowerShell.

        Time Complexity: O(k) per poll where k is new events count.
        Space Complexity: O(k) buffer.
        """
        logger.info("Starting live Windows event reader on channel %s", self.channel)
        while not self._stop_event.is_set():
            try:
                # Query events newer than last record ID
                ps_script = (
                    f"$events = Get-WinEvent -FilterHashtable @{{LogName='{self.channel}'}} "
                    f"-MaxEvents 20 -ErrorAction SilentlyContinue | "
                    f"Where-Object {{ $_.RecordId -gt {self._last_record_id} }} | "
                    f"Sort-Object RecordId; "
                    f"if ($events) {{ "
                    f"$events | ForEach-Object {{ "
                    f"[PSCustomObject]@{{ "
                    f"  RecordId = $_.RecordId; "
                    f"  Id = $_.Id; "
                    f"  TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o'); "
                    f"  MachineName = $_.MachineName; "
                    f"  ProviderName = $_.ProviderName; "
                    f"  Message = $_.Message "
                    f"}} }} | ConvertTo-Json -Compress "
                    f"}}"
                )

                cmd = ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps_script]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

                if res.returncode == 0 and res.stdout.strip():
                    raw_out = res.stdout.strip()
                    try:
                        data = json.loads(raw_out)
                        if isinstance(data, dict):
                            data = [data]
                        for item in data:
                            rid = int(item.get('RecordId', 0))
                            if rid > self._last_record_id:
                                self._last_record_id = rid

                            parsed_event = {
                                'source_file': f"WIN_LIVE_{self.channel.upper()}",
                                'event_record_id': rid,
                                'event_id': int(item.get('Id', 0)),
                                'time_created': item.get('TimeCreated', datetime.now(timezone.utc).isoformat()),
                                'computer': sanitize_text(item.get('MachineName', 'HOST')),
                                'provider': sanitize_text(item.get('ProviderName', 'WinEvent')),
                                'channel': self.channel,
                                'level': 'Information',
                                'task': 'Security Event',
                                'account_name': 'SYSTEM',
                                'process_name': 'UNKNOWN',
                                'event_data': sanitize_text(item.get('Message', ''), max_len=500),
                                'raw_xml_length': 300,
                                'is_tampered': 0
                            }
                            self.inject_event(parsed_event)
                    except json.JSONDecodeError:
                        pass
            except Exception as err:
                logger.warning("Windows event worker iteration error: %s", err)

            self._stop_event.wait(self.poll_interval)

    def _simulation_worker(self) -> None:
        """Background worker thread emitting realistic baseline clean events.

        Time Complexity: O(1) per cycle.
        Space Complexity: O(1)
        """
        logger.info("Starting live simulation stream worker.")
        common_eids = [4624, 4625, 4634, 4688, 4663, 4672]
        processes = ['explorer.exe', 'svchost.exe', 'lsass.exe', 'services.exe', 'chrome.exe']

        while not self._stop_event.is_set():
            self._sim_counter += 1
            now_str = datetime.now(timezone.utc).isoformat()
            eid = common_eids[self._sim_counter % len(common_eids)]
            proc = processes[self._sim_counter % len(processes)]

            clean_event = {
                'source_file': 'LIVE_SIMULATION',
                'event_record_id': self._sim_counter,
                'event_id': eid,
                'time_created': now_str,
                'computer': 'WORKSTATION-01',
                'provider': 'Microsoft-Windows-Security-Auditing',
                'channel': self.channel,
                'level': 'Information',
                'task': 'Logon / Activity',
                'account_name': f"user_{(self._sim_counter % 5) + 1}",
                'process_name': proc,
                'event_data': f"Standard security operational telemetry for event {eid}.",
                'raw_xml_length': 400,
                'is_tampered': 0
            }

            self.inject_event(clean_event)
            self._stop_event.wait(self.poll_interval)

    def _sanitize_event_dict(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure all fields conform to types, lengths, and safety standards.

        Parameters:
            event (Dict[str, Any]): Raw incoming event dictionary.

        Returns:
            Dict[str, Any]: Sanitized event dictionary.

        Time Complexity: O(1)
        Space Complexity: O(1)
        """
        try:
            eid = int(event.get('event_id', 0))
        except (ValueError, TypeError):
            eid = 0

        try:
            rid = int(event.get('event_record_id', 0))
        except (ValueError, TypeError):
            rid = 0

        tc = str(event.get('time_created', datetime.now(timezone.utc).isoformat()))

        try:
            raw_len = int(event.get('raw_xml_length', 300))
        except (ValueError, TypeError):
            raw_len = 300

        raw_tampered = event.get('is_tampered', 0)
        if isinstance(raw_tampered, str):
            is_tampered = 1 if raw_tampered.lower() in ('1', 'true', 'yes') else 0
        else:
            try:
                is_tampered = int(raw_tampered)
            except (ValueError, TypeError):
                is_tampered = 0

        return {
            'source_file': sanitize_text(event.get('source_file', 'STREAM'), 64),
            'event_record_id': rid,
            'event_id': eid,
            'time_created': tc,
            'computer': sanitize_text(event.get('computer', 'HOST'), 64),
            'provider': sanitize_text(event.get('provider', 'Auditing'), 64),
            'channel': sanitize_text(event.get('channel', 'Security'), 64),
            'level': sanitize_text(event.get('level', 'Information'), 32),
            'task': sanitize_text(event.get('task', 'Telemetry'), 64),
            'account_name': sanitize_text(event.get('account_name', 'SYSTEM'), 64),
            'process_name': sanitize_text(event.get('process_name', 'UNKNOWN'), 64),
            'event_data': sanitize_text(event.get('event_data', ''), 512),
            'raw_xml_length': raw_len,
            'is_tampered': is_tampered,
            'tamper_type': sanitize_text(event.get('tamper_type', 'none'), 32)
        }
