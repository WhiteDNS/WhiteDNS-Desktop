"""Render percentage-control and Normal/Max speed graphs from measured CSV rows."""
import argparse
import csv
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

p = argparse.ArgumentParser()
p.add_argument('--csv', required=True)
p.add_argument('--output', default='docs/benchmarks/cottenmax-adjustable-low')
p.add_argument('--profile-prefix', default='bulk')
p.add_argument('--caption', default='80 ms RTT, one flow, no injected loss; medians of 3 verified UDP DNS transfers. Error bars show observed ranges.')
a = p.parse_args()
with Path(a.csv).open(encoding='utf-8-sig', newline='') as f:
    rows = list(csv.DictReader(f))
lookup = {(r['profile'], r['mode']): r for r in rows if int(r['successes']) > 0}
modes = [('max-full', 'Full'), ('max-low-10', 'Low 10%'),
         ('max-low-35', 'Low 35%'), ('max-low-90', 'Low 90%'),
         ('normal-android', 'Normal\nAndroid'), ('normal-desktop', 'Normal\nDesktop')]
colors = ['#2563eb', '#fdba74', '#ea580c', '#9a3412', '#94a3b8', '#475569']
plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 11,
                     'axes.spines.top': False, 'axes.spines.right': False,
                     'figure.facecolor': 'white', 'savefig.facecolor': 'white',
                     'svg.hashsalt': 'cottenmax-traffic-profiles'})

def save_plot(fig, path):
    fig.savefig(path, dpi=160, metadata={'Date': None} if path.suffix == '.svg' else None)
    if path.suffix == '.svg':
        path.write_text('\n'.join(line.rstrip() for line in path.read_text(encoding='utf-8').splitlines())+'\n', encoding='utf-8')

out = Path(a.output)
out.parent.mkdir(parents=True, exist_ok=True)
fig, axes = plt.subplots(2, 2, figsize=(13, 9), layout='constrained')
for ri, direction in enumerate(['download', 'upload']):
    for ci, capacity in enumerate(['wide', 'narrow']):
        ax = axes[ri, ci]
        profile = f'{a.profile_prefix}-{capacity}-{direction}'
        selected = [(i, label, lookup[(profile, mode)]) for i, (mode, label) in enumerate(modes) if (profile, mode) in lookup]
        if not selected:
            ax.set_visible(False)
            continue
        values = [float(r['mbps_median']) for _, _, r in selected]
        low = [float(r['mbps_min']) for _, _, r in selected]
        high = [float(r['mbps_max']) for _, _, r in selected]
        xs = list(range(len(selected)))
        ax.bar(xs, values, color=[colors[i] for i, _, _ in selected], width=.66,
               yerr=[[v-l for v,l in zip(values,low)], [h-v for h,v in zip(high,values)]],
               capsize=4, error_kw={'ecolor':'#333333', 'elinewidth':1.1})
        ax.set_xticks(xs, [label for _, label, _ in selected])
        ax.set_ylim(0, max(high)*1.26)
        ax.set_ylabel('Application goodput (Mbps)')
        ax.set_title(f'{direction.capitalize()} · '+('QNAME 253 / answer 1232 B' if capacity=='wide' else 'QNAME 101 / answer 512 B'))
        ax.set_axisbelow(True)
        ax.grid(axis='y', color='#dddddd', linewidth=.7)
        for x, value, hi in zip(xs, values, high):
            ax.text(x, hi+max(high)*.025, f'{value:.3f}', ha='center', va='bottom')
fig.suptitle('CottenMax: adjustable Low versus Full and Normal', fontsize=17)
fig.supxlabel(a.caption+'\nNormal uses the actual app configurations on the same server; no missing/failed case is plotted as zero.', fontsize=10)
for ext in ['.png', '.svg']:
    save_plot(fig, out.with_suffix(ext))
plt.close(fig)

fig, axes = plt.subplots(1, 2, figsize=(12, 5.2), layout='constrained')
for ax, direction in zip(axes, ['download', 'upload']):
    ax.plot([0,100], [0,100], '--', color='#777777', linewidth=1, label='Selected target')
    for capacity, color, marker in [('wide','#2563eb','o'), ('narrow','#ea580c','s')]:
        profile = f'{a.profile_prefix}-{capacity}-{direction}'
        points = [(pct, lookup.get((profile, f'max-low-{pct}'))) for pct in [10,35,90]]
        points = [(pct,r) for pct,r in points if r and r['percent_speed_loss_vs_full']]
        if not points:
            continue
        xs = [pct for pct,_ in points]
        ys = [float(r['percent_speed_loss_vs_full']) for _,r in points]
        ax.plot(xs, ys, color=color, marker=marker, linewidth=2,
                label='253 / 1232 B' if capacity=='wide' else '101 / 512 B')
        other_capacity = 'narrow' if capacity == 'wide' else 'wide'
        for x,y in zip(xs,ys):
            other = lookup.get((f'{a.profile_prefix}-{other_capacity}-{direction}', f'max-low-{x}'))
            other_y = float(other['percent_speed_loss_vs_full']) if other else None
            offset = -17 if other_y is not None and abs(y-other_y) < 8 and y < other_y else 8
            ax.annotate(f'{y:.1f}%', (x,y), xytext=(0,offset),
                        textcoords='offset points', ha='center')
    ax.set(xlim=(0,100), ylim=(0,105), xticks=[10,35,90],
           xlabel='Selected reduction target (%)', ylabel='Measured speed loss versus Full (%)',
           title=direction.capitalize())
    ax.grid(color='#e5e5e5', linewidth=.7)
    ax.legend(loc='upper left', frameon=False)
fig.suptitle('How closely the percentage tracks measured speed loss', fontsize=16)
fig.supxlabel(a.caption.replace(' Error bars show observed ranges.', '')+'\nTargets are approximate; CPU, startup and resolver behavior affect realized loss.', fontsize=10)
for ext in ['.png', '.svg']:
    save_plot(fig, out.with_name(out.name+'-targets').with_suffix(ext))
plt.close(fig)
print(out.with_suffix('.png'))
print(out.with_name(out.name+'-targets').with_suffix('.png'))
