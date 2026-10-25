"""Run one tunnel experiment at a time; retain every verified result/failure."""
from pathlib import Path
import argparse
import collections
import datetime
import json
import os
import platform
import random
import statistics
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--runs', type=int, default=3)
parser.add_argument('--suite', choices=['crypto', 'domains', 'all'], default='all')
args = parser.parse_args()
out = Path(args.output)
out.mkdir(parents=True, exist_ok=True)
binary = str(Path(args.binary).resolve())

suites = ['chacha20-poly1305-8', 'chacha20-poly1305-8-stacktag', 'aes-128-gcm-12',
          'aes-256-gcm-12', 'aes-128-gcm-16', 'chacha20-poly1305-16']
crypto_profiles = [
    ('loopback-download', {'bytes': 8 << 20}),
    ('loopback-upload', {'bytes': 512 << 10, 'direction': 'upload'}),
    ('80ms-download', {'bytes': 512 << 10, 'rtt': 80}),
    ('80ms-upload', {'bytes': 64 << 10, 'rtt': 80, 'direction': 'upload'}),
    ('lossy-download', {'bytes': 256 << 10, 'rtt': 120, 'loss': 0.03}),
    ('lossy-upload', {'bytes': 32 << 10, 'rtt': 120, 'loss': 0.03, 'direction': 'upload'}),
    ('wide-name-upload', {'bytes': 128 << 10, 'rtt': 80, 'qname': 253,
                          'answer': 1232, 'direction': 'upload'}),
]
domain_profiles = [
    ('one-flow', {'bytes': 512 << 10, 'rtt': 80}),
    ('four-flows', {'bytes': 256 << 10, 'rtt': 80, 'flows': 4}),
    ('shared-cap', {'bytes': 64 << 10, 'rtt': 80, 'flows': 4, 'qps': 120}),
    ('independent-caps', {'bytes': 64 << 10, 'rtt': 80, 'flows': 4,
                           'qps': 120, 'cap-scope': 'domain'}),
    ('blocked-standby', {'bytes': 256 << 10, 'rtt': 80, 'flows': 4,
                        'blocked-domain': 1}),
]
variants = [('one-domain', {'domains': 1}),
            ('two-failover', {'domains': 2, 'strategy': 'failover'}),
            ('two-parallel', {'domains': 2, 'strategy': 'parallel'})]

cases = []
if args.suite in ('crypto', 'all'):
    for name, flags in crypto_profiles:
        for suite in suites:
            cases.append(('crypto', name, suite, dict(flags, cipher=suite)))
if args.suite in ('domains', 'all'):
    for name, flags in domain_profiles:
        for variant, extra in variants:
            cases.append(('domains', name, variant, dict(flags, **extra)))

metadata = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'platform': platform.platform(), 'machine': platform.machine(),
            'processor': platform.processor(), 'logical_cpus': os.cpu_count(),
            'runs': args.runs, 'sequential': True,
            'godebug': os.environ.get('GODEBUG', ''), 'binary': binary}
try:
    if sys.platform == 'win32':
        metadata['cpu'] = subprocess.check_output(
            ['powershell', '-NoProfile', '-Command', '(Get-CimInstance Win32_Processor).Name'],
            text=True).strip()
    else:
        metadata['lscpu'] = subprocess.check_output(['lscpu'], text=True)
except (OSError, subprocess.CalledProcessError):
    pass
(out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')

records = []
total = len(cases) * args.runs
# Randomize within each repetition, retain seeds and actual order for auditing.
with (out / 'runs.jsonl').open('w', encoding='utf-8') as raw:
    for rep in range(args.runs):
        order = cases.copy()
        random.Random(8341 + rep).shuffle(order)
        for category, profile, variant, flags in order:
            command = [binary, '-seed', str(3400 + rep)]
            for key, value in flags.items():
                command += ['-' + key, str(value)]
            run = subprocess.run(command, capture_output=True, text=True, timeout=135)
            try:
                result = json.loads(run.stdout.strip().splitlines()[-1])
            except (json.JSONDecodeError, IndexError):
                result = {'error': 'missing JSON result', 'stdout': run.stdout}
            result.update(category=category, profile=profile, variant=variant,
                          repetition=rep + 1, returncode=run.returncode,
                          stderr=run.stderr, command=command)
            if run.returncode and not result.get('error'):
                result['error'] = 'nonzero benchmark exit'
            records.append(result)
            raw.write(json.dumps(result) + '\n')
            raw.flush()
            print(f"{len(records)}/{total} {category}/{profile}/{variant}: "
                  f"{result.get('goodput_mbps', 0):.3f} Mbps "
                  f"{result.get('error', '')}", flush=True)

groups = collections.defaultdict(list)
for record in records:
    groups[(record['category'], record['profile'], record['variant'])].append(record)
summary = []
for (category, profile, variant), runs in sorted(groups.items()):
    good = [r for r in runs if not r.get('error')]
    row = dict(category=category, profile=profile, variant=variant,
               successes=len(good), failures=len(runs) - len(good), repeats=len(runs))
    if good:
        speeds = [r['goodput_mbps'] for r in good]
        row.update(median_mbps=statistics.median(speeds), min_mbps=min(speeds),
                   max_mbps=max(speeds), median_seconds=statistics.median(r['transfer_seconds'] for r in good),
                   median_warmup_ms=statistics.median(r['all_domain_warmup_ms'] for r in good),
                   median_open_ms=statistics.median(r['stream_open_ms'] for r in good),
                   median_queries_per_MiB=statistics.median(r['traffic']['queries'] / r['verified_bytes'] * (1 << 20) for r in good),
                   median_wire_bytes_per_byte=statistics.median((r['traffic']['up_wire_bytes'] + r['traffic']['down_wire_bytes']) / r['verified_bytes'] for r in good),
                   max_sampled_inflight=max(r['sampled_peak_inflight'] for r in good))
    summary.append(row)
for row in summary:
    baseline = next((r for r in summary if r['category'] == row['category'] and
                     r['profile'] == row['profile'] and r['variant'] ==
                     ('chacha20-poly1305-8' if row['category'] == 'crypto' else 'one-domain')), None)
    if baseline and baseline.get('median_mbps') and row.get('median_mbps'):
        row['percent_vs_baseline'] = 100 * (row['median_mbps'] / baseline['median_mbps'] - 1)
(out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
failures = sum(bool(r.get('error')) for r in records)
print(f"Completed {len(records)} cases; failures={failures}; output={out}", flush=True)
sys.exit(bool(failures))
