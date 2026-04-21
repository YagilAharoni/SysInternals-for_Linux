#!/usr/bin/env python3
"""LPBA monitor: collect syscall-driven behavior and score suspicious activity."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

SENSITIVE_PATH_PREFIXES = [
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/",
]

SYSCALL_FILTER = "open,openat,read,write,connect,execve"


@dataclass
class Event:
    timestamp: str
    pid: int
    ppid: int
    uid: int
    process_name: str
    event_type: str
    action: str
    target: str
    outcome: str
    bytes: int
    rule_hits: List[str]
    risk_delta: int
    cumulative_risk: int


class HeuristicEngine:
    """Simple additive risk scoring engine for behavior-based triage."""

    def __init__(self) -> None:
        self.risk_by_pid: Dict[int, int] = defaultdict(int)
        self.tmp_write_windows: Dict[int, Deque[float]] = defaultdict(deque)
        self.beacon_windows: Dict[Tuple[int, str], Deque[float]] = defaultdict(deque)

    def score_event(self, event: Dict[str, Any]) -> Tuple[List[str], int, int]:
        pid = int(event["pid"])
        now = time.time()
        delta = 0
        hits: List[str] = []

        if event["event_type"] == "file" and event["action"] in {"open", "openat"}:
            target = str(event.get("target", ""))
            if int(event.get("uid", -1)) != 0 and any(
                target == p or target.startswith(p) for p in SENSITIVE_PATH_PREFIXES
            ):
                hits.append("non_root_sensitive_file_read")
                delta += 40

        if event["event_type"] == "file" and event["action"] == "write":
            target = str(event.get("target", ""))
            if target.startswith("/tmp/"):
                window = self.tmp_write_windows[pid]
                window.append(now)
                while window and now - window[0] > 10:
                    window.popleft()
                if len(window) >= 35:
                    hits.append("tmp_high_rate_writes")
                    delta += 25

        if event["event_type"] == "network" and event["action"] == "connect":
            target = str(event.get("target", "unknown"))
            key = (pid, target)
            window = self.beacon_windows[key]
            window.append(now)
            while window and now - window[0] > 15:
                window.popleft()
            if len(window) >= 7:
                hits.append("possible_beacon_pattern")
                delta += 20

        if event.get("outcome") in {"EACCES", "EPERM"}:
            hits.append("privileged_access_denied")
            delta += 10

        self.risk_by_pid[pid] += delta
        return hits, delta, self.risk_by_pid[pid]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Linux Process Behavioral Analyzer")
    parser.add_argument("--pid", type=int, default=None, help="Attach to an existing PID")
    parser.add_argument(
        "--cmd",
        nargs=argparse.REMAINDER,
        help="Run and monitor a command, e.g. --cmd ./dummy_malware",
    )
    parser.add_argument("--duration", type=int, default=25, help="Capture duration in seconds for PID mode")
    parser.add_argument("--out", type=str, default="artifacts", help="Output directory")
    return parser.parse_args()


def read_proc_identity(pid: int) -> Tuple[str, int, int]:
    name = f"pid_{pid}"
    ppid = -1
    uid = -1
    status_path = Path(f"/proc/{pid}/status")
    if not status_path.exists():
        return name, ppid, uid

    text = status_path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        if line.startswith("Name:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("PPid:"):
            ppid = int(line.split(":", 1)[1].strip())
        elif line.startswith("Uid:"):
            uid = int(line.split(":", 1)[1].strip().split()[0])
    return name, ppid, uid


def run_strace_command(trace_prefix: Path, cmd: List[str]) -> None:
    strace_cmd = [
        "strace",
        "-ff",
        "-tt",
        "-s",
        "256",
        "-e",
        f"trace={SYSCALL_FILTER}",
        "-o",
        str(trace_prefix),
    ] + cmd
    subprocess.run(strace_cmd, check=False)


def run_strace_attach(trace_prefix: Path, pid: int, duration: int) -> None:
    strace_cmd = [
        "strace",
        "-ff",
        "-tt",
        "-s",
        "256",
        "-e",
        f"trace={SYSCALL_FILTER}",
        "-o",
        str(trace_prefix),
        "-p",
        str(pid),
    ]
    proc = subprocess.Popen(strace_cmd)
    try:
        time.sleep(duration)
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=5)


def parse_trace_file(path: Path) -> Iterable[Dict[str, Any]]:
    # Child traces are stored as prefix.PID when strace uses -ff.
    pid = int(path.suffix.lstrip(".")) if path.suffix.lstrip(".").isdigit() else -1
    fd_to_path: Dict[int, str] = {}

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "unfinished ..." in line or "resumed>" in line:
            continue

        syscall_match = re.search(r"\s([a-zA-Z_][a-zA-Z0-9_]*)\((.*)\)\s+=\s+(.+)$", line)
        if not syscall_match:
            continue

        syscall = syscall_match.group(1)
        args = syscall_match.group(2)
        ret = syscall_match.group(3)

        event_type = "syscall"
        target = ""
        nbytes = 0
        outcome = "OK"

        if "EACCES" in ret:
            outcome = "EACCES"
        elif "EPERM" in ret:
            outcome = "EPERM"

        if syscall in {"open", "openat"}:
            event_type = "file"
            path_match = re.search(r'"([^\"]+)"', args)
            if path_match:
                target = path_match.group(1)
            fd_match = re.match(r"(\d+)", ret.strip())
            if fd_match and target:
                fd_to_path[int(fd_match.group(1))] = target

        elif syscall == "write":
            event_type = "file"
            first_arg = args.split(",", 1)[0].strip()
            if first_arg.isdigit() and int(first_arg) in fd_to_path:
                target = fd_to_path[int(first_arg)]
            else:
                target = "/tmp/unknown"
            bytes_match = re.search(r",\s*(\d+)\s*$", args)
            if bytes_match:
                nbytes = int(bytes_match.group(1))

        elif syscall == "connect":
            event_type = "network"
            ip_match = re.search(r'inet_addr\("([0-9\.]+)"\)', args)
            port_match = re.search(r"htons\((\d+)\)", args)
            if ip_match and port_match:
                target = f"{ip_match.group(1)}:{port_match.group(1)}"
            else:
                target = "unknown"

        elif syscall == "execve":
            event_type = "process"
            binary_match = re.search(r'"([^\"]+)"', args)
            if binary_match:
                target = binary_match.group(1)

        if pid > 0:
            proc_name, ppid, uid = read_proc_identity(pid)
        else:
            proc_name, ppid, uid = "unknown", -1, -1

        yield {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "process_name": proc_name,
            "event_type": event_type,
            "action": syscall,
            "target": target,
            "outcome": outcome,
            "bytes": nbytes,
        }


def write_jsonl(path: Path, events: Iterable[Dict[str, Any]]) -> int:
    count = 0
    with path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=True) + "\n")
            count += 1
    return count


def build_report_summary(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not events:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_events": 0,
            "max_risk": 0,
            "risk_band": "LOW",
            "top_processes": [],
        }

    max_risk = max(int(e["cumulative_risk"]) for e in events)
    if max_risk >= 80:
        band = "CRITICAL"
    elif max_risk >= 50:
        band = "HIGH"
    elif max_risk >= 20:
        band = "MEDIUM"
    else:
        band = "LOW"

    scores: Dict[int, Dict[str, Any]] = {}
    for e in events:
        pid = int(e["pid"])
        if pid not in scores or int(e["cumulative_risk"]) > int(scores[pid]["cumulative_risk"]):
            scores[pid] = {
                "pid": pid,
                "process_name": e["process_name"],
                "cumulative_risk": int(e["cumulative_risk"]),
            }

    top = sorted(scores.values(), key=lambda x: x["cumulative_risk"], reverse=True)[:10]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_events": len(events),
        "max_risk": max_risk,
        "risk_band": band,
        "top_processes": top,
    }


def main() -> int:
    args = parse_args()

    if (args.pid is None and not args.cmd) or (args.pid is not None and args.cmd):
        raise SystemExit("Provide exactly one mode: either --pid or --cmd")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    trace_prefix = out_dir / "trace.lpba"

    if args.cmd:
        cmd = args.cmd
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        if not cmd:
            raise SystemExit("--cmd was provided but no executable was supplied")
        run_strace_command(trace_prefix, cmd)
    else:
        run_strace_attach(trace_prefix, args.pid, args.duration)

    trace_files = sorted(out_dir.glob("trace.lpba*"))
    if not trace_files:
        raise SystemExit("No trace files were produced. Check strace permissions and inputs.")

    raw_events: List[Dict[str, Any]] = []
    for tfile in trace_files:
        raw_events.extend(list(parse_trace_file(tfile)))

    engine = HeuristicEngine()
    scored_events: List[Dict[str, Any]] = []
    for evt in raw_events:
        hits, delta, total = engine.score_event(evt)
        modeled = Event(
            timestamp=evt["timestamp"],
            pid=int(evt["pid"]),
            ppid=int(evt["ppid"]),
            uid=int(evt["uid"]),
            process_name=str(evt["process_name"]),
            event_type=str(evt["event_type"]),
            action=str(evt["action"]),
            target=str(evt["target"]),
            outcome=str(evt["outcome"]),
            bytes=int(evt["bytes"]),
            rule_hits=hits,
            risk_delta=delta,
            cumulative_risk=total,
        )
        scored_events.append(asdict(modeled))

    events_path = out_dir / "events.jsonl"
    count = write_jsonl(events_path, scored_events)

    summary = build_report_summary(scored_events)
    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=True), encoding="utf-8")

    print(f"LPBA captured {count} events")
    print(f"Events: {events_path}")
    print(f"Summary: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
