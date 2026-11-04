"""Plot measured application speed and DNS query rate; errors show observed ranges."""
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

parser = argparse.ArgumentParser()
parser.add_argument('--input', default='experiment-results/traffic-profiles-windows-amd64/summary.json')
parser.add_argument('--output', default='docs/benchmarks/cottenmax-low-100-comparison')
args = parser.parse_args()
rows = json.loads(Path(args.input).read_text(encoding='utf-8-sig'))
profiles = [('80ms-download-four-flows', 'Download · 80 ms'),
            ('80ms-upload-four-flows', 'Upload · 80 ms'),
            ('120ms-loss3-download-four-flows', 'Download · 120 ms, 3% loss each way')]
colors = ['#2563eb', '#ea580c']
plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 11,
                     'axes.spines.top': False, 'axes.spines.right': False,
                     'axes.titleweight': 'medium', 'figure.facecolor': 'white',
                     'savefig.facecolor': 'white', 'svg.hashsalt': 'cottenmax-traffic-profiles'})
fig, axes = plt.subplots(2, 3, figsize=(14, 8.5), layout='constrained')
for column, (profile, title) in enumerate(profiles):
    group = [next(r for r in rows if r['category'] == 'profiles' and
                  r['profile'] == profile and r['variant'] == v) for v in ['full', 'low']]
    for row, metric, unit in [(0, 'mbps', 'Application goodput (Mbps)'),
                              (1, 'qps', 'DNS queries / second')]:
        ax = axes[row, column]
        values = [r['median_' + metric] for r in group]
        lows = [r['min_' + metric] for r in group]
        highs = [r['max_' + metric] for r in group]
        ax.bar([0, 1], values, color=colors, width=0.58,
               yerr=[[v-l for v,l in zip(values,lows)], [h-v for h,v in zip(highs,values)]],
               capsize=5, error_kw={'ecolor':'#404040','elinewidth':1.2})
        ax.set_xticks([0, 1], ['Full', 'Low · 100 QPS'])
        ax.set_ylabel(unit)
        ax.set_ylim(0, max(highs) * 1.30)
        ax.set_axisbelow(True)
        ax.grid(axis='y', color='#dddddd', linewidth=0.7)
        for x, (value, high) in enumerate(zip(values, highs)):
            label = f'{value:.3f}' if metric == 'mbps' else f'{value:,.1f}'
            ax.text(x, high + max(highs)*0.035, label, ha='center', va='bottom')
        reduction = 100 * (1 - values[1] / values[0])
        ax.set_title(title if row == 0 else f'{reduction:.1f}% lower query rate', pad=14)
        if row == 0:
            ax.text(0.98, 0.95, f'{reduction:.1f}% slower', transform=ax.transAxes,
                    ha='right', va='top', color='#7c2d12', weight='medium')
fig.suptitle('Original Low profile (100 QPS): speed versus load', fontsize=18, weight='medium')
fig.supxlabel('Windows x64 · four flows / two domains · fixed QNAME 101, answer 512 B · medians of 3 runs; error bars = min–max\n'
              'Verified UDP DNS transfers through a shaped loopback relay; source 7934e3c2. Not a VPS or ISP measurement.', fontsize=10)
out = Path(args.output)
out.parent.mkdir(parents=True, exist_ok=True)
for suffix in ['.png', '.svg']:
    path = out.with_suffix(suffix)
    fig.savefig(path, dpi=160, metadata={'Date': None} if suffix == '.svg' else None)
    if suffix == '.svg':
        path.write_text('\n'.join(line.rstrip() for line in path.read_text(encoding='utf-8').splitlines())+'\n', encoding='utf-8')
plt.close(fig)
print(out.with_suffix('.png'))
print(out.with_suffix('.svg'))
