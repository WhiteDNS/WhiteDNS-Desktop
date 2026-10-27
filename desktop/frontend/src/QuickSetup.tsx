import { useEffect, useState } from "react";
import { Check, ChevronDown, FileText, Globe2, LoaderCircle, Maximize2, Minimize2, Monitor, Network, Save, Shield, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import type { AppState, ResolverProfile, SettingsProfile } from "./types";
import { backend } from "./wails";

const modes = [
  { id: "proxy", title: "Proxy mode", icon: Monitor, detail: "Set the proxy inside your app." },
  { id: "vpn", title: "VPN mode", icon: Globe2, detail: "Set the system proxy automatically. Apps must support the system proxy." },
  { id: "tun", title: "TUN mode", icon: Shield, detail: "Route device traffic. Windows will ask for administrator approval when you connect." },
] as const;

export function QuickSetup({ state, settings, resolver, locked, onRun }: {
  state: AppState; settings?: SettingsProfile; resolver?: ResolverProfile; locked: boolean;
  onRun: (action: () => Promise<AppState>) => Promise<void>;
}) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState(false);
  const [source, setSource] = useState<"paste" | "file">("paste");
  const [importedId, setImportedId] = useState("");
  const [preview, setPreview] = useState<string[]>([]);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [tunSupported, setTunSupported] = useState(false);
  const mode = state.tunnelMode || (settings?.singBoxSetSystemProxy ? "vpn" : "proxy");
  const shared = Boolean(state.globalResolverProfileId);
  const disabled = locked || busy;
  const file = state.resolverProfiles.find(p => p.id === importedId && p.resolverSource === "file") || (resolver?.resolverSource === "file" ? resolver : undefined);
  const fileApplied = Boolean(file && state.globalResolverProfileId === file.id);

  useEffect(() => { void backend.getTunModeSupported().then(setTunSupported).catch(() => setTunSupported(false)); }, []);
  useEffect(() => {
    if (resolver?.resolverSource === "file") { setImportedId(resolver.id); setSource("file"); }
    else setSource("paste");
    setText(resolver?.resolverSource === "file" ? "" : resolver?.resolverText || "");
    setError("");
  }, [resolver?.id, resolver?.resolverText, resolver?.resolverFile]);
  useEffect(() => {
    if (!file) { setPreview([]); return; }
    let cancelled = false;
    setPreview(file.resolverPreview || []);
    setPreviewLoading(true);
    backend.getResolverProfilePreview(file.id, 0, expanded ? 100 : 4)
      .then(page => { if (!cancelled) setPreview(page.resolvers || []); })
      .catch(() => { if (!cancelled) setError("The file preview is unavailable. Replace the file to try again."); })
      .finally(() => { if (!cancelled) setPreviewLoading(false); });
    return () => { cancelled = true; };
  }, [file?.id, file?.resolverFile, file?.resolverCount, expanded]);

  async function run(action: () => Promise<AppState>) {
    if (disabled) return;
    setBusy(true);
    setError("");
    try {
      await onRun(async () => {
        try { return await action(); }
        catch (err) { setError(err instanceof Error ? err.message : String(err)); throw err; }
      });
    } finally { setBusy(false); }
  }

  async function importFile() {
    await run(async () => {
      const result = await backend.importGlobalResolverFile();
      if (result.profile?.id) {
        setImportedId(result.profile.id);
        setPreview(result.profile.resolverPreview || []);
        setSource("file");
        setExpanded(false);
      }
      return result.state;
    });
  }

  async function save() {
    await run(async () => {
      const next = source === "file" && file ? await backend.setGlobalResolverProfile(file.id) : await backend.saveGlobalResolvers(text);
      setSaved(true);
      return next;
    });
  }

  return <Card className="quick-setup gap-0 overflow-hidden py-0" aria-busy={busy}>
    <div className="quick-setup-heading flex flex-wrap items-center justify-between gap-2 border-b">
      <h2 className="flex items-center gap-2 text-sm font-semibold"><Network className="size-4 text-muted-foreground" />Quick setup</h2>
      <p className="text-xs text-muted-foreground">{locked ? "Disconnect to change these settings" : "Applies to your next connection"}</p>
    </div>
    <CardContent className="quick-setup-content">
      <fieldset disabled={disabled} className="min-w-0">
        <legend className="mb-3 text-sm font-medium">Tunnel mode</legend>
        <div className="grid grid-cols-3 gap-2" role="radiogroup" aria-label="Tunnel mode">
          {modes.map(({ id, title, icon: Icon }) => <button key={id} type="button" role="radio" aria-checked={mode === id}
            disabled={disabled || (id === "tun" && !tunSupported)}
            title={id === "tun" && !tunSupported ? "Automatic TUN mode is currently available on Windows" : undefined}
            className={cn("tunnel-mode", mode === id && "tunnel-mode-selected")}
            onClick={() => { if (mode !== id || !state.tunnelMode) void run(() => backend.setTunnelMode(id)); }}
            onKeyDown={event => {
              const offset = event.key === "ArrowRight" || event.key === "ArrowDown" ? 1 : event.key === "ArrowLeft" || event.key === "ArrowUp" ? -1 : 0;
              if (offset || event.key === "Home" || event.key === "End") {
                event.preventDefault();
                const available = modes.filter(item => item.id !== "tun" || tunSupported);
                const next = available[event.key === "Home" ? 0 : event.key === "End" ? available.length - 1 : (available.findIndex(item => item.id === mode) + offset + available.length) % available.length];
                (event.currentTarget.parentElement?.children[modes.indexOf(next)] as HTMLButtonElement)?.focus();
                void run(() => backend.setTunnelMode(next.id));
              }
            }} tabIndex={mode === id ? 0 : -1}><Icon className="size-5" />{title}</button>)}
        </div>
        <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{modes.find(item => item.id === mode)?.detail}{!tunSupported && " TUN is available on Windows."}</p>
      </fieldset>
      <div className="quick-resolver-pane">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <Label htmlFor="shared-resolvers" className="text-sm font-medium">Shared resolvers</Label>
          <div className="flex items-center gap-2">
            <Label htmlFor="use-shared-resolvers" className="text-xs text-muted-foreground">Use for all connections</Label>
            <Switch id="use-shared-resolvers" checked={shared} disabled={disabled || !resolver}
              onCheckedChange={checked => { setSaved(false); void run(() => backend.setGlobalResolverProfile(checked ? (source === "file" && file ? file.id : resolver?.id || "") : "")); }} />
          </div>
        </div>
        <div className="resolver-input-toolbar">
          <div className="resolver-source-controls" aria-label="Resolver input method">
            <button type="button" aria-pressed={source === "paste"} disabled={disabled} onClick={() => setSource("paste")}><FileText />Paste addresses</button>
            <button type="button" aria-pressed={source === "file"} disabled={disabled} onClick={() => void importFile()}><Upload />Import file</button>
          </div>
          <button type="button" className="resolver-expand" disabled={busy} aria-label={expanded ? "Collapse resolver input" : "Expand resolver input"}
            aria-expanded={expanded} aria-controls="resolver-input-panel" onClick={() => setExpanded(value => !value)}>{expanded ? <Minimize2 /> : <Maximize2 />}</button>
        </div>
        <div id="resolver-input-panel" className="resolver-input-panel" data-expanded={expanded}>
          <Textarea id="shared-resolvers" value={source === "file" ? preview.slice(0, expanded ? 100 : 2).join("\n") : text}
            disabled={disabled && source === "paste"} readOnly={source === "file"} rows={expanded ? 6 : 2}
            className="resolver-textarea" placeholder={source === "file" && previewLoading ? "Loading preview…" : "1.1.1.1\n8.8.8.8:53"}
            aria-describedby="shared-resolver-help" aria-invalid={Boolean(error)}
            onKeyDown={event => { if (source === "paste" && (event.ctrlKey || event.metaKey) && event.key === "Enter" && text.trim()) { event.preventDefault(); void save(); } }}
            onChange={event => { setText(event.target.value); setSaved(false); setError(""); if (event.target.value.split("\n").length > 2) setExpanded(true); }} />
          <Button className="resolver-save" disabled={disabled || (source === "file" ? !file || fileApplied : !text.trim())} onClick={() => void save()}>
            {busy ? <LoaderCircle className="animate-spin" /> : source === "file" && fileApplied ? <Check /> : <Save />}
            {busy ? "Saving…" : source === "file" && fileApplied ? "Applied" : "Save & use for all"}
          </Button>
        </div>
        <p id="shared-resolver-help" className="mt-2 text-xs leading-relaxed text-muted-foreground">Paste IP addresses or import a resolver list.</p>
        {file && <div className={cn("resolver-file", fileApplied && "resolver-file-active")}>
          <FileText className="size-4 shrink-0" />
          <span className="min-w-0 flex-1 truncate" title={file.sourceFileName || file.name}>{file.sourceFileName || file.name}</span>
          <span className="shrink-0 text-muted-foreground">{(file.resolverCount || 0).toLocaleString()} resolvers</span>
          <button type="button" disabled={busy} className="resolver-preview-toggle" aria-label="Toggle file preview" aria-expanded={expanded}
            onClick={() => { setSource("file"); setExpanded(value => !value); }}><ChevronDown className={cn("size-3.5", expanded && "rotate-180")} /></button>
          <button type="button" disabled={disabled} className="resolver-replace" onClick={() => void importFile()}>Replace</button>
        </div>}
        {!!file?.resolverInvalidCount && <p className="mt-2 text-xs text-amber-600">{file.resolverInvalidCount.toLocaleString()} invalid entries skipped.</p>}
        {(!fileApplied || error) && <p className={cn("resolver-feedback", error && "text-destructive")} role={error ? "alert" : "status"}>
          {error || (saved ? "Shared resolvers saved and enabled." : shared ? `Using ${resolver?.name || "shared resolvers"} for every connection` : "Off · each connection uses its own resolver profile")}
        </p>}
      </div>
    </CardContent>
  </Card>;
}
