# Normal / Max comparison bundles

The current percentage-control results are **only** `normal-max-final/`.
It combines the disjoint `normal-max-final-wide/` (36 cases) and
`normal-max-final-narrow/` (24 cases) using the same fresh client/harness binaries
and the unchanged server binary. `build-identity.json` identifies the validated
source and executable hashes. All 60 cases succeeded and verified every payload
byte. See [the report](../docs/COTTENMAX_TRAFFIC_PROFILES.md) for methodology,
limits, client pins, and graphs.

The other bundles preserve the investigation and must not be pooled into the
current figures:

| Bundle | Purpose |
| --- | --- |
| `normal-max-percentage-wide/`, `normal-max-percentage-narrow/` | Earlier percentage controller and timer-per-packet relay; smaller transfers |
| `normal-max-comparison.csv` | Export of those earlier wide/narrow summaries, **not** the final graph input |
| `normal-max-full-prior-binary/` | Historical Full comparison using a retained older client executable |
| `normal-max-percentage-smoke/`, `normal-max-percentage-v2-smoke/` | Development smoke checks; not the final repeated matrix |
| `normal-max-percentage-v2-jitter-smoke/` | Development scheduler-jitter experiment |
| `normal-max-percentage-v2-buffers-check/` | Development receive-buffer check; does not establish a cause for speed variance |
| `normal-max-percentage-v2-ordered-check/` | Preliminary ordered-relay comparison before the final clean-build pin |

The final ordered relay preserves packet arrival order within each direction.
The earlier per-packet timer relay allowed callback scheduling to introduce
reordering, which made Full downloads noisy. Changes to harness behavior,
controller version, payload sizes, binary identity, and startup accounting make
these separate experiments, rather than extra repetitions of the final matrix.

Committed files contain result rows, summaries, metadata, and public benchmark
configuration fixtures. Generated runtime directories, executables, logs and
local build caches remain outside the tracked result bundles. The fixture's
unused desktop credential field was removed after the validated source pin;
the harness overrides it with the same public dummy credential in every mode,
so this text cleanup does not change the measurements.
Scoped Git attributes preserve the captured result/fixture bytes across
platforms, including line endings, so manifest hashes survive checkout.

To regenerate the current graph, use
`normal-max-final/comparison.csv` with
[`plot_low_percentages.py`](../scripts/experiments/plot_low_percentages.py).
See [reproduction instructions](../scripts/experiments/normal_max_README.md).
