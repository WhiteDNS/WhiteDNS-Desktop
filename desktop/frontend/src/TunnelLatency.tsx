import { useEffect, useId, useState } from "react";
import { Card } from "@/components/ui/card";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Info } from "lucide-react";
import { LATENCY_INTERVAL_MS, latencyGeometry, retainSamples, summarizeLatency, type TunnelSample } from "./latency";
import { backend } from "./wails";

export function TunnelLatency({ connected, sessionKey }: { connected: boolean; sessionKey: string }) {
  const [samples, setSamples] = useState<TunnelSample[]>([]);
  const [now, setNow] = useState(Date.now);
  const [probing, setProbing] = useState(false);
  const [message, setMessage] = useState("");
  const gradient = "latency-" + useId().replace(/:/g, "");

  useEffect(() => {
    let cancelled = false, inFlight = false;
    setSamples([]);
    setMessage("");
    setProbing(false);
    setNow(Date.now());
    if (!connected) return;
    async function probe() {
      if (cancelled || inFlight || document.visibilityState === "hidden") return;
      inFlight = true;
      setProbing(true);
      const at = Date.now();
      let latency: number | null = null;
      let failure = "";
      try {
        const result = await backend.probeTunnelLatency();
        if (result.ok && Number.isFinite(result.latencyMs) && result.latencyMs >= 0) latency = result.latencyMs;
        else failure = result.message || "Tunnel probe did not receive a response.";
      } catch (err) { failure = err instanceof Error ? err.message : String(err); }
      if (!cancelled) {
        const completedAt = Date.now();
        setSamples(current => retainSamples([...current, { at, latency, error: failure || undefined }], completedAt));
        setNow(completedAt);
        setMessage(failure);
        setProbing(false);
      }
      inFlight = false;
    }
    void probe();
    const timer = window.setInterval(() => void probe(), LATENCY_INTERVAL_MS);
    const onVisible = () => { if (document.visibilityState === "visible") void probe(); };
    document.addEventListener("visibilitychange", onVisible);
    // Avoid overlap when a slow probe takes longer than five seconds. Ignore
    // results from an old connection after disconnect, reconnect or unmount.
    return () => { cancelled = true; window.clearInterval(timer); document.removeEventListener("visibilitychange", onVisible); };
  }, [connected, sessionKey]);

  useEffect(() => {
    if (!connected) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") setNow(Date.now());
    }, reduced.matches ? 1000 : 100);
    return () => window.clearInterval(timer);
  }, [connected]);

  const visible = retainSamples(samples, now);
  const stats = summarizeLatency(visible);
  const geometry = latencyGeometry(visible, now);
  const hasData = geometry.points.some(point => point.y !== null);

  return <Card className="tunnel-latency gap-0 py-0" aria-label="Tunnel latency">
    <div className="latency-heading">
      <div>
        <h2 className="text-sm font-semibold">Round-trip through the tunnel</h2>
        <p className="mt-1 text-xs text-muted-foreground">{connected ? "Measured every 5 s through the tunnel. Last 80 seconds." : "Connect to start measuring latency through the tunnel."}</p>
      </div>
      <div className="latency-summary">
        {message && connected ? <Tooltip>
          <TooltipTrigger asChild><button type="button" className="latency-state latency-retrying" aria-label="Tunnel probe details"><span aria-hidden="true" />Retrying<Info className="size-3" /></button></TooltipTrigger>
          <TooltipContent side="bottom" align="end" className="latency-tooltip max-w-80 flex-col items-start gap-1 border bg-popover text-popover-foreground text-xs leading-relaxed shadow-md">
            <p>{message}</p><p className="mt-1">Red marks indicate missed checks. LOSS shows their share of the last 80 seconds.</p>
          </TooltipContent>
        </Tooltip> : <span className="latency-state" data-live={connected}><span aria-hidden="true" />{connected ? "Live" : "Idle"}</span>}
        <dl>
          {([['MIN', stats.min], ['AVG', stats.avg], ['MAX', stats.max], ['LOSS', stats.loss]] as const).map(([label, value]) => <div key={label}
            title={label === "LOSS" ? "Percentage of tunnel probes that failed to receive a response" : "Milliseconds"}>
            <dt>{label}</dt><dd data-loss={label === "LOSS"} data-failed={label === "LOSS" && value !== null && value > 0}>{value === null ? "—" : label === "LOSS" ? `${value}%` : value}</dd>
          </div>)}
        </dl>
      </div>
    </div>
    <div className="latency-plot">
      <svg viewBox="0 0 1000 200" preserveAspectRatio="none" role="img" aria-label={hasData ? "Measured tunnel round-trip latency in milliseconds over the last 80 seconds" : "No tunnel latency samples yet"}>
        <defs><linearGradient id={gradient} x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="var(--dashboard-green)" stopOpacity=".24" /><stop offset="100%" stopColor="var(--dashboard-green)" stopOpacity="0" /></linearGradient></defs>
        {[20, 80, 140, 199].map(y => <line key={y} x1="0" x2="1000" y1={y} y2={y} className="latency-grid" vectorEffect="non-scaling-stroke" />)}
        {geometry.areas.map((path, index) => <path key={index} d={path} fill={`url(#${gradient})`} />)}
        {geometry.strokes.map((path, index) => <path key={index} d={path} className="latency-line" vectorEffect="non-scaling-stroke" />)}
        {geometry.points.map(point => point.y === null ? <rect key={point.at} x={point.x - 1} y="178" width="2" height="14" rx="1" className="latency-failure"><title>{point.error || "Probe did not receive a response"}</title></rect>
          : <circle key={point.at} cx={point.x} cy={point.y} r="2.5" className="latency-point"><title>{point.latency} ms</title></circle>)}
      </svg>
      {!hasData && <div className="latency-empty">{connected ? probing ? "Measuring tunnel latency…" : "Waiting for a successful tunnel response" : "Your tunnel latency will appear here"}</div>}
    </div>
    <div className="latency-timeline" aria-hidden="true"><span>-80s</span><span>-60s</span><span>-40s</span><span>-20s</span><span>now</span></div>
    <span className="sr-only" role="status">{message && connected ? "Tunnel probe is retrying. Focus Tunnel probe details to see the reason." : ""}</span>
  </Card>;
}
