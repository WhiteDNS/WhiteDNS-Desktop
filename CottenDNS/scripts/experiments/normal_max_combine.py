#!/usr/bin/env python3
"""Combine disjoint ordered-relay measurements without rerunning matched cases."""
import argparse
import csv
import datetime
import hashlib
import json
from pathlib import Path

from normal_max_matrix import aggregate


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inputs', nargs='+', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--validated-core-pin', default='')
    p.add_argument('--build-manifest')
    a = p.parse_args()
    out = Path(a.output)
    out.mkdir(parents=True, exist_ok=True)
    rows, sources, seen, identities = [], [], set(), set()
    for source in map(Path, a.inputs):
        meta = json.loads((source / 'metadata.json').read_text(encoding='utf-8-sig'))
        identities.add(tuple(sorted(meta['binaries_sha256'].items())))
        sources.append({'path': str(source), 'metadata_sha256': digest(source/'metadata.json'),
                        'runs_sha256': digest(source/'runs.jsonl')})
        for line in (source/'runs.jsonl').read_text(encoding='utf-8-sig').splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            key = row['profile'], row['mode'], row['repetition']
            if key in seen:
                raise ValueError(f'duplicate case {key}')
            seen.add(key)
            result = row['result']
            if row['returncode'] != 0 or result.get('error'):
                raise ValueError(f'failed case {key}: {result.get("error")}')
            options = result['options']
            if options.get('relay_order') != 'ordered':
                raise ValueError(f'non-ordered case {key}')
            if result['verified_bytes'] != options['bytes_per_flow'] * options['flows']:
                raise ValueError(f'unverified case {key}')
            row['source_bundle'] = str(source)
            rows.append(row)
    if len(identities) != 1:
        raise ValueError('mixed harness/client/server binaries require a separate comparison')
    summary = aggregate(rows)
    csv_rows = []
    for item in summary:
        profile, mode = item['profile'], item['mode']
        full = next(r for r in summary if r['profile'] == profile and r['mode'] == 'max-full')
        speed = item['goodput_mbps']['median']
        base = full['goodput_mbps']['median']
        item['speed_loss_vs_full_percent'] = 100 * (1 - speed/base)
        flat = {'profile': profile, 'mode': mode, 'samples': item['successes'],
                'median_mbps': speed, 'min_mbps': item['goodput_mbps']['min'],
                'max_mbps': item['goodput_mbps']['max'],
                'median_queries_per_second': item['query_starts_per_second']['median'],
                'speed_loss_vs_full_percent': item['speed_loss_vs_full_percent']}
        for normal_mode in ['normal-android', 'normal-desktop']:
            normal = next((r for r in summary if r['profile'] == profile and r['mode'] == normal_mode), None)
            if normal:
                ratio = speed/normal['goodput_mbps']['median']
                item['speed_ratio_vs_'+normal_mode] = ratio
                flat['speed_ratio_vs_'+normal_mode] = ratio
        csv_rows.append(flat)
    (out/'runs.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows), encoding='utf-8')
    (out/'summary.json').write_text(json.dumps(summary, indent=2)+'\n', encoding='utf-8')
    fields = list(dict.fromkeys(key for row in csv_rows for key in row))
    with (out/'summary.csv').open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(csv_rows)
    binaries = dict(next(iter(identities)))
    build_identity = None
    if a.build_manifest:
        build_identity = json.loads(Path(a.build_manifest).read_text(encoding='utf-8-sig'))
        if build_identity['binary_sha256'] != binaries:
            raise ValueError('build manifest does not identify the measured executables')
        if a.validated_core_pin and build_identity['core_source_pin'] != a.validated_core_pin:
            raise ValueError('validated source pin differs from the fresh build manifest')
        (out/'build-identity.json').write_text(json.dumps(build_identity, indent=2)+'\n', encoding='utf-8')
    metadata = {'combined_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'verified_cases': len(rows), 'binaries_sha256': binaries, 'sources': sources,
                'validated_core_pin': a.validated_core_pin,
                'measurement_scope': 'Production default UDP socket factory, original unchanged server, ordered per-direction DNS relay.',
                'source_provenance_note': 'Executable identity is the captured SHA256. The final client and harness were rebuilt from the production-clean validated core pin with -buildvcs=false; build-identity.json records the commands, verified source directory and binary hashes. The server executable was retained unchanged from before percentage pacing.'}
    (out/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n', encoding='utf-8')
    print(f'Combined {len(rows)} verified cases into {out}')
    for item in summary:
        if item['mode'].startswith('max-'):
            print(f"{item['profile']} {item['mode']}: {item['goodput_mbps']['median']:.4f} Mbps; "
                  f"{item['speed_loss_vs_full_percent']:.1f}% loss versus Full")


if __name__ == '__main__':
    main()
