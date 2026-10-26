"""Measure full/low DNS load sequentially; verify bytes and keep every run."""
from pathlib import Path
import argparse
import collections
import datetime
import hashlib
import json
import os
import platform
import random
import statistics
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
parser.add_argument('--prior-binary', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--runs', type=int, default=3)
args = parser.parse_args()
out = Path(args.output)
out.mkdir(parents=True, exist_ok=True)
binary = str(Path(args.binary).resolve())
prior_binary = str(Path(args.prior_binary).resolve())

def command_output(command):
    return subprocess.check_output(command, text=True).strip()

metadata = {
    'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'platform': platform.platform(), 'machine': platform.machine(),
    'processor': platform.processor(), 'logical_cpus': os.cpu_count(),
    'runs': args.runs, 'sequential': True, 'godebug': os.environ.get('GODEBUG', ''),
    'current_source_commit': command_output(['git', 'rev-parse', 'HEAD']),
    'build_command': 'go build -tags maxexperiment -trimpath -o .cache/maxexperiment-traffic.exe ./cmd/maxexperiment',
    'embedded_vcs_note': 'Go reports the enclosing repository revision for this nested Git worktree. The embedded vcs.revision is not the source identity; use current_source_commit, the recorded build command, and binary SHA256.',
    'prior_binary_identity_note': 'Retained binary from prior experiments; no source-commit identity claim. File SHA256 and Go build metadata retained.',
    'limitations': ['Shaped loopback UDP DNS, not a VPS or physical ISP.',
                    'Power, temperature, background OS work not controlled.',
                    'DNS-byte counters exclude IP/UDP headers.',
                    'Payload QPS excludes warmup and stream-open work, retained separately in raw result.'],
    'binaries': {},
}
for label, path in [('current', binary), ('prior', prior_binary)]:
    metadata['binaries'][label] = {
        'path': path, 'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest(),
        'go_version_m': command_output(['go', 'version', '-m', path]),
    }
try:
    metadata['cpu'] = command_output(['powershell', '-NoProfile', '-Command', '(Get-CimInstance Win32_Processor).Name'])
except (OSError, subprocess.CalledProcessError):
    pass
(out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')

common = {'domains': 2, 'strategy': 'parallel', 'flows': 4,
          'inflight': 128, 'qname': 101, 'answer': 512,
          'cipher': 'chacha20-poly1305-8'}
profiles = [
    ('80ms-download-four-flows', {'rtt': 80, 'bytes': 32 << 10}),
    ('80ms-upload-four-flows', {'rtt': 80, 'bytes': 8 << 10, 'direction': 'upload'}),
    ('120ms-loss3-download-four-flows', {'rtt': 120, 'loss': 0.03, 'bytes': 32 << 10}),
]
cases = []
for name, flags in profiles:
    for mode in ['full', 'low']:
        cases.append(('profiles', name, mode, binary,
                      dict(common, **flags, **{'traffic-profile': mode})))
for variant, path, flags in [('prior-binary', prior_binary, {}),
                              ('current-full', binary, {'traffic-profile': 'full'})]:
    cases.append(('default-regression', 'loopback-download-one-flow', variant, path,
                  dict(flags, domains=1, strategy='failover', flows=1,
                       inflight=128, qname=101, answer=512, bytes=8 << 20,
                       cipher='chacha20-poly1305-8')))

records = []
with (out / 'runs.jsonl').open('w', encoding='utf-8') as raw:
    for rep in range(args.runs):
        order = cases.copy()
        random.Random(19824 + rep).shuffle(order)
        for category, profile, variant, path, flags in order:
            command = [path, '-seed', str(3400 + rep)]
            for key, value in flags.items():
                command += ['-' + key, str(value)]
            try:
                run = subprocess.run(command, capture_output=True, text=True, timeout=135)
                try:
                    result = json.loads(run.stdout.strip().splitlines()[-1])
                except (json.JSONDecodeError, IndexError):
                    result = {'error': 'missing JSON result', 'stdout': run.stdout}
                result.update(returncode=run.returncode, stderr=run.stderr)
                if run.returncode and not result.get('error'):
                    result['error'] = 'nonzero benchmark exit'
            except subprocess.TimeoutExpired as exc:
                result = {'error': 'subprocess timeout', 'returncode': None,
                          'stdout': str(exc.stdout), 'stderr': str(exc.stderr)}
            result.update(category=category, profile=profile, variant=variant,
                          repetition=rep + 1, command=command)
            if not result.get('error'):
                result['payload_queries_per_second'] = result['traffic']['queries'] / result['transfer_seconds']
            records.append(result)
            raw.write(json.dumps(result) + '\n')
            raw.flush()
            print(f"{len(records)}/{len(cases) * args.runs} {category}/{profile}/{variant}: "
                  f"{result.get('goodput_mbps', 0):.3f} Mbps; "
                  f"{result.get('payload_queries_per_second', 0):.1f} queries/s "
                  f"{result.get('error', '')}", flush=True)

groups = collections.defaultdict(list)
for record in records:
    groups[record['category'], record['profile'], record['variant']].append(record)
summary = []
for (category, profile, variant), runs in sorted(groups.items()):
    good = [r for r in runs if not r.get('error')]
    row = dict(category=category, profile=profile, variant=variant,
               successes=len(good), failures=len(runs) - len(good), repeats=len(runs))
    if good:
        for field, source in [('mbps', 'goodput_mbps'), ('seconds', 'transfer_seconds'),
                              ('qps', 'payload_queries_per_second'),
                              ('warmup_ms', 'all_domain_warmup_ms'),
                              ('open_ms', 'stream_open_ms'),
                              ('cold_auth_probe_ms', 'cold_auth_probe_ms')]:
            if all(source in r for r in good):
                values = [r[source] for r in good]
                row.update({f'median_{field}': statistics.median(values),
                            f'min_{field}': min(values), f'max_{field}': max(values)})
        row.update(median_queries=statistics.median(r['traffic']['queries'] for r in good),
                   median_up_dns_bytes=statistics.median(r['traffic']['up_wire_bytes'] for r in good),
                   median_down_dns_bytes=statistics.median(r['traffic']['down_wire_bytes'] for r in good),
                   max_sampled_inflight=max(r['sampled_peak_inflight'] for r in good),
                   verified_bytes=good[0]['verified_bytes'],
                   domains_with_payload_queries=[r['traffic']['queries_by_domain'] for r in good])
    summary.append(row)
for row in summary:
    variant = 'full' if row['category'] == 'profiles' else 'prior-binary'
    baseline = next((r for r in summary if r['category'] == row['category'] and
                     r['profile'] == row['profile'] and r['variant'] == variant), None)
    if baseline and baseline.get('median_mbps') and row.get('median_mbps'):
        row['percent_mbps_vs_baseline'] = 100 * (row['median_mbps'] / baseline['median_mbps'] - 1)
        row['percent_qps_vs_baseline'] = 100 * (row['median_qps'] / baseline['median_qps'] - 1)
(out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
failures = sum(bool(r.get('error')) for r in records)
print(f'Completed {len(records)} cases; failures={failures}; output={out}', flush=True)
sys.exit(bool(failures))
