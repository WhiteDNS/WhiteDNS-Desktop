export const LATENCY_WINDOW_MS = 80_000;
export const LATENCY_INTERVAL_MS = 5_000;
export type TunnelSample = { at: number; latency: number | null; error?: string };

export function retainSamples(samples: TunnelSample[], now: number): TunnelSample[] {
  return samples.filter(sample => sample.at >= now - LATENCY_WINDOW_MS && sample.at <= now);
}

export function summarizeLatency(samples: TunnelSample[]) {
  const values = samples.flatMap(s => s.latency !== null && Number.isFinite(s.latency) && s.latency >= 0 ? [s.latency] : []);
  return {
    min: values.length ? Math.min(...values) : null,
    avg: values.length ? Math.round(values.reduce((total, value) => total + value, 0) / values.length) : null,
    max: values.length ? Math.max(...values) : null,
    loss: samples.length ? Math.round((samples.length - values.length) / samples.length * 100) : null,
  };
}

export function latencyGeometry(samples: TunnelSample[], now: number) {
  const visible = retainSamples(samples, now);
  const values = visible.flatMap(s => s.latency !== null && Number.isFinite(s.latency) && s.latency >= 0 ? [s.latency] : []);
  const min = values.length ? Math.min(...values) : 0;
  const max = values.length ? Math.max(...values) : 100;
  const span = Math.max(max - min, 10);
  const low = Math.max(0, min - span * 0.8);
  const high = max + span * 1.8;
  const points = visible.map(sample => ({
    ...sample,
    x: Math.max(0, Math.min(1000, 1000 * (1 - (now - sample.at) / LATENCY_WINDOW_MS))),
    y: sample.latency === null || !Number.isFinite(sample.latency) || sample.latency < 0 ? null : 184 - 170 * (sample.latency - low) / (high - low),
  }));
  const segments: typeof points[] = [];
  let segment: typeof points = [];
  for (const point of points) {
    if (segment.length && point.at - segment[segment.length - 1].at > LATENCY_INTERVAL_MS * 2) { segments.push(segment); segment = []; }
    if (point.y === null) { if (segment.length) segments.push(segment); segment = []; }
    else segment.push(point);
  }
  if (segment.length) segments.push(segment);
  const strokes: string[] = [], areas: string[] = [];
  for (const group of segments) {
    if (group.length < 2) continue;
    let path = `M ${group[0].x} ${group[0].y}`;
    // Midpoint quadratics stay within the measured points' range; no fabricated
    // interpolation across a failed probe or an unmeasured part of the window.
    for (let i = 1; i < group.length - 1; i++) {
      path += ` Q ${group[i].x} ${group[i].y} ${(group[i].x + group[i + 1].x) / 2} ${(group[i].y! + group[i + 1].y!) / 2}`;
    }
    const last = group[group.length - 1];
    path += ` L ${last.x} ${last.y}`;
    strokes.push(path);
    areas.push(`${path} L ${last.x} 200 L ${group[0].x} 200 Z`);
  }
  return { points, strokes, areas };
}
