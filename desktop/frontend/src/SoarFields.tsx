import type { SoarSettings } from "./types";
import { Input } from "./components/ui/input";
import { Switch } from "./components/ui/switch";
import { Button } from "./components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./components/ui/select";
import { Tooltip, TooltipContent, TooltipTrigger } from "./components/ui/tooltip";

export const defaultSoarSettings: SoarSettings = {
 transport:"auto",discovery:true,country:"IR",discoveryWant:2,discoveryConcurrency:2,discoveryPaceMs:1000,
 safeQName:101,maxQName:253,maxAnswer:1232,holdMs:500,maxInflight:128,maxPathWindow:32,maxStreams:128,
 streamWindowKiB:256,sendBufferKiB:64,sessionIdleSeconds:90,dialTimeoutSeconds:90,
};
const fields: Array<[keyof SoarSettings,string,number,number,string]> = [
 ["safeQName","Initial safe query length",101,253,"DNS name length used at startup. 101 suits restrictive paths; it must not exceed the maximum query length."],
 ["maxQName","Maximum query length",101,253,"Upload capacity ceiling. The engine starts safely and tests larger names up to this value. Larger names can carry more data, but some paths drop them."],
 ["maxAnswer","Maximum DNS answer (bytes)",512,1232,"Download packet ceiling. 512 is conservative; larger answers may improve throughput where the path supports them."],
 ["holdMs","Idle query hold (ms)",100,1500,"How long an idle server query may wait for data. Ready data returns sooner. Low values increase DNS traffic."],
 ["maxInflight","Outstanding requests, all paths",8,1024,"Maximum unanswered DNS requests. Excessive concurrency can cause packet loss and resolver throttling."],
 ["maxPathWindow","Outstanding requests per path",2,128,"Caps concurrent DNS requests on each resolver path. Increase only on paths that tolerate extra load."],
 ["discoveryWant","Desired healthy paths",1,32,"Target number of verified paths. More paths are not necessarily faster. Discovery resumes when paths fail."],
 ["discoveryConcurrency","Concurrent discovery checks",1,16,"Number of unknown resolvers tested at once. Higher values increase discovery load; engine scanning has its own cap."],
 ["discoveryPaceMs","Discovery pacing (ms)",100,5000,"Minimum spacing between adding paths for testing, not a delay applied to each data packet."],
 ["maxStreams","Concurrent TCP streams",8,256,"Stream limit in this client. The server account may impose a lower limit. This does not limit device count."],
 ["streamWindowKiB","Receive window per stream (KiB)",64,1024,"Unacknowledged receive capacity per stream. A larger window uses more memory and can help high-latency paths."],
 ["sendBufferKiB","Send buffer per stream (KiB)",32,1024,"Send queue capacity. Increasing it uses more memory; it does not increase DNS path capacity by itself."],
 ["sessionIdleSeconds","Idle session retirement (seconds)",15,110,"Retire an idle session before the server's two-minute expiry so it is not reused after expiration."],
 ["dialTimeoutSeconds","Connection timeout (seconds)",5,120,"Maximum tunnel connection/startup time. Extra time accommodates slow paths without making them faster."],
];
function Help({label,text}:{label:string;text:string}) {
 return <Tooltip><TooltipTrigger asChild><button type="button" aria-label={`Help: ${label}`} className="inline-flex size-5 items-center justify-center rounded-full border text-xs text-muted-foreground">?</button></TooltipTrigger><TooltipContent className="max-w-80 leading-relaxed">{text}</TooltipContent></Tooltip>;
}
export function SoarFields({value,onChange}:{value:SoarSettings;onChange:(value:SoarSettings)=>void}) {
 const options={...defaultSoarSettings,...value};
 return <section className="mt-6 space-y-4 border-t pt-5" aria-label="Soar advanced settings">
  <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="text-sm font-semibold">Soar advanced settings</h3>
   <div className="flex gap-2"><Button type="button" variant="outline" size="sm" onClick={()=>onChange({...defaultSoarSettings,country:options.country})}>Automatic</Button>
    <Button type="button" variant="outline" size="sm" onClick={()=>onChange({...defaultSoarSettings,country:options.country,maxQName:101,maxAnswer:512,maxInflight:32,maxPathWindow:8,discoveryWant:1,discoveryConcurrency:1,discoveryPaceMs:1500})}>Limited path</Button></div>
  </div>
  <p className="text-xs leading-relaxed text-muted-foreground">Encryption is fixed: ChaCha20-Poly1305, X25519 and Ed25519. MasterDNS encryption and MTU controls do not apply. Subscription refresh replaces provider-owned Soar settings.</p>
  <div className="grid gap-4 sm:grid-cols-2">
   <div className="space-y-2"><div className="flex items-center justify-between text-sm"><span>Resolver transport</span><Help label="Resolver transport" text="Automatic starts with UDP and adds TCP/53 when needed. This controls DNS transport, not the local proxy type." /></div>
    <Select value={options.transport} onValueChange={transport=>onChange({...options,transport})}><SelectTrigger aria-label="Resolver transport" className="w-full"><SelectValue/></SelectTrigger><SelectContent>
      {[['auto','Automatic — UDP with TCP fallback'],['on','UDP and TCP from startup'],['only','TCP only'],['off','UDP only']].map(([key,label])=><SelectItem key={key} value={key}>{label}</SelectItem>)}
    </SelectContent></Select>
   </div>
   <div className="space-y-2"><div className="flex items-center justify-between text-sm"><span>Discovery scope</span><Help label="Discovery scope" text="Iran prioritizes Iranian resolver candidates before the global list. This is a search preference, not the exit IP country or a guarantee of connectivity." /></div>
    <Select value={options.country || 'global'} onValueChange={country=>onChange({...options,country:country==='global'?'':country})}><SelectTrigger aria-label="Discovery scope" className="w-full"><SelectValue/></SelectTrigger><SelectContent><SelectItem value="IR">Iran first</SelectItem><SelectItem value="global">Global</SelectItem>{options.country && options.country!=='IR' && <SelectItem value={options.country}>{options.country}</SelectItem>}</SelectContent></Select>
   </div>
   <div className="flex items-center justify-between gap-2 rounded-md border p-3 sm:col-span-2"><span className="text-sm">Automatic path discovery</span><div className="flex items-center gap-3"><Help label="Automatic path discovery" text="Find alternative authenticated DNS paths beyond the selected resolver list. Disabling discovery restricts this profile to manual resolvers."/><Switch aria-label="Automatic path discovery" checked={options.discovery} onCheckedChange={discovery=>onChange({...options,discovery})}/></div></div>
   {fields.map(([key,label,min,max,description])=><div key={key} className="space-y-2"><div className="flex items-start justify-between gap-2"><label htmlFor={`soar-${key}`} className="text-sm">{label}</label><Help label={label} text={description}/></div>
    <Input id={`soar-${key}`} type="number" min={min} max={max} step={1} value={Number(options[key])} onChange={e=>onChange({...options,[key]:Number(e.target.value)})}/>
    <p className="text-xs text-muted-foreground">{min}–{max}</p>
   </div>)}
  </div>
 </section>;
}
