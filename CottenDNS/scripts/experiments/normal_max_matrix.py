#!/usr/bin/env python3
"""Sequential, verified production Normal/Max comparisons over shaped UDP DNS.

No production service or external resolver is used. Each case retains its actual
generated TOML and client/server logs next to the raw result.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import random
import statistics
import subprocess
import sys
import time


PROFILES = {
    "bulk-wide-download": dict(direction="download", flows=1, bytes=2097152, rtt=80, loss=0, qname=253, answer=1232),
    "bulk-wide-upload": dict(direction="upload", flows=1, bytes=262144, rtt=80, loss=0, qname=253, answer=1232),
    "bulk-narrow-download": dict(direction="download", flows=1, bytes=2097152, rtt=80, loss=0, qname=101, answer=512),
    "bulk-narrow-upload": dict(direction="upload", flows=1, bytes=262144, rtt=80, loss=0, qname=101, answer=512),
    "healthy-wide-download": dict(direction="download", flows=1, bytes=524288, rtt=80, loss=0, qname=253, answer=1232),
    "healthy-wide-upload": dict(direction="upload", flows=1, bytes=65536, rtt=80, loss=0, qname=253, answer=1232),
    "healthy-wide-four-download": dict(direction="download", flows=4, bytes=262144, rtt=80, loss=0, qname=253, answer=1232),
    "healthy-wide-four-upload": dict(direction="upload", flows=4, bytes=32768, rtt=80, loss=0, qname=253, answer=1232),
    "lossy-wide-download": dict(direction="download", flows=1, bytes=262144, rtt=120, loss=.03, qname=253, answer=1232),
    "lossy-wide-upload": dict(direction="upload", flows=1, bytes=32768, rtt=120, loss=.03, qname=253, answer=1232),
    "healthy-narrow-download": dict(direction="download", flows=1, bytes=524288, rtt=80, loss=0, qname=101, answer=512),
    "healthy-narrow-upload": dict(direction="upload", flows=1, bytes=65536, rtt=80, loss=0, qname=101, answer=512),
}


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def aggregate(rows):
    groups = {}
    for row in rows:
        groups.setdefault((row["profile"], row["mode"]), []).append(row)
    result = []
    for (profile, mode), values in sorted(groups.items()):
        good = [v["result"] for v in values if v.get("returncode") == 0 and not v["result"].get("error")]
        entry = {"profile": profile, "mode": mode, "successes": len(good), "failures": len(values)-len(good)}
        for key in ("goodput_mbps", "query_starts_per_second", "transfer_seconds", "cold_start_seconds", "stream_open_seconds", "target_connection_starts_per_second"):
            measurements = [v[key] for v in good]
            if measurements:
                entry[key] = {"median": statistics.median(measurements), "min": min(measurements), "max": max(measurements)}
        if entry["failures"]:
            entry["errors"] = [v["result"].get("error", v.get("stderr", "unknown")) for v in values if v.get("returncode") != 0 or v["result"].get("error")]
        result.append(entry)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", default=".bench/normalmax/normalmaxbench.exe")
    p.add_argument("--client", default=".bench/normalmax/client.exe")
    p.add_argument("--server", default=".bench/normalmax/server.exe")
    p.add_argument("--output", required=True)
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--timeout", type=int, default=240)
    p.add_argument("--modes", nargs="+", default=["normal-android", "normal-desktop", "max-full", "max-low"])
    p.add_argument("--profiles", nargs="+", choices=sorted(PROFILES), default=["healthy-wide-download", "healthy-wide-upload"])
    p.add_argument("--desktop-template")
    p.add_argument("--android-template")
    p.add_argument("--debug", action="store_true", help="mark overlapping/short smoke runs as non-comparative debug data")
    a = p.parse_args()
    if a.runs < 1:
        p.error("runs must be positive")
    out = pathlib.Path(a.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    binary, client, server = (str(pathlib.Path(v).resolve()) for v in (a.binary, a.client, a.server))
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    diff = subprocess.check_output(["git", "diff", "--binary"], stderr=subprocess.DEVNULL)
    metadata = {"started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "platform": platform.platform(), "processor": platform.processor(), "logical_cpus": os.cpu_count(), "godebug": os.environ.get("GODEBUG", ""), "sequential": True, "debug_only": a.debug, "runs": a.runs, "source_commit": revision, "tracked_source_diff_sha256": hashlib.sha256(diff).hexdigest(), "source_is_dirty": bool(diff), "options": vars(a), "binaries_sha256": {"harness": sha(binary), "client": sha(client), "server": sha(server)}}
    metadata["normal_template_sha256"] = {key: sha(value) for key, value in {"android": a.android_template, "desktop": a.desktop_template}.items() if value}
    metadata["source_context_note"] = "source_commit and tracked_source_diff_sha256 describe the worktree at measurement time, not provenance of a prebuilt executable; executable identity is the recorded SHA-256. The prior Full comparison deliberately uses an older client executable."
    (out/"metadata.json").write_text(json.dumps(metadata, indent=2)+"\n", encoding="utf-8")
    rows = []
    jobs = [(profile, mode) for profile in a.profiles for mode in a.modes]
    total = len(jobs)*a.runs
    with (out/"runs.jsonl").open("w", encoding="utf-8", newline="\n") as raw:
        for rep in range(a.runs):
            ordered = jobs[:]
            random.Random(9143+rep).shuffle(ordered)
            for profile, mode in ordered:
                case = out/f"r{rep+1}-{profile}-{mode}"
                command = [binary, "-mode", mode, "-client", client, "-server", server, "-seed", str(3400+rep), "-timeout", str(a.timeout), "-runtime-dir", str(case)]
                for key, value in PROFILES[profile].items():
                    command += ["-"+key, str(value)]
                template = a.desktop_template if mode=="normal-desktop" else a.android_template if mode=="normal-android" else None
                if template:
                    command += ["-normal-template", str(pathlib.Path(template).resolve())]
                at = time.monotonic()
                try:
                    completed = subprocess.run(command, text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=a.timeout+20)
                    value = json.loads(completed.stdout.strip().splitlines()[-1])
                    code, stderr = completed.returncode, completed.stderr
                except (subprocess.TimeoutExpired, ValueError, IndexError) as err:
                    value, code, stderr = {"error": str(err)}, -1, ""
                row = {"repetition": rep+1, "profile": profile, "mode": mode, "command": command, "wall_seconds": time.monotonic()-at, "returncode": code, "result": value, "stderr": stderr}
                rows.append(row)
                raw.write(json.dumps(row)+"\n")
                raw.flush()
                status = "FAIL "+value.get("error", "") if code else f"{value['goodput_mbps']:.4f} Mbps; {value['query_starts_per_second']:.1f} DNS q/s"
                print(f"{len(rows)}/{total} r{rep+1} {profile} {mode}: {status}", flush=True)
                (out/"summary.json").write_text(json.dumps(aggregate(rows), indent=2)+"\n", encoding="utf-8")
    sys.exit(1 if any(row["returncode"] for row in rows) else 0)


if __name__ == "__main__":
    main()
