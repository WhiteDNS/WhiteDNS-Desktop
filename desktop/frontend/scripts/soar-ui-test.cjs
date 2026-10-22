// Visual/interaction checks with a synthetic Wails bridge. Go tests cover the
// real APIs, parsing, persistence and runtime; this fixture contains no secrets.
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.DESKTOP_PLAYWRIGHT||'playwright');
const fixture=JSON.parse(fs.readFileSync(process.env.DESKTOP_UI_FIXTURE,'utf8'));
const root=path.resolve(__dirname,'../dist'),out=process.env.DESKTOP_SCREENSHOTS||path.resolve(__dirname,'../../../.cache/ui');fs.mkdirSync(out,{recursive:true});
const server=http.createServer((req,res)=>{const relative=decodeURIComponent(new URL(req.url,'http://localhost').pathname);let file=path.resolve(root,'.'+relative);if(!file.startsWith(root+path.sep)&&file!==root){res.writeHead(404);res.end();return;}if(file===root||!path.extname(file))file=path.join(root,'index.html');try{const mime={'.html':'text/html','.js':'text/javascript','.css':'text/css','.woff2':'font/woff2','.png':'image/png','.svg':'image/svg+xml'};res.setHeader('Content-Type',mime[path.extname(file)]||'application/octet-stream');res.end(fs.readFileSync(file));}catch{res.writeHead(404);res.end();}});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
 const browser=await chromium.launch({headless:true,...(process.env.DESKTOP_CHROME?{executablePath:process.env.DESKTOP_CHROME}:{})});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.on('pageerror',e=>{errors.push(e.message);console.error('BROWSER ERROR:',e.stack)});
  await page.addInitScript(state=>{
   let current=structuredClone(state);window.testCalls=[];
   const clone=()=>structuredClone(current);
   const methods={
    GetAppState:async()=>clone(),
    ValidateResolverText:async raw=>({isValid:true,normalizedResolvers:raw.split(/\r?\n/).filter(Boolean),normalizedText:raw,invalidEntries:[]}),
    GetSystemLANIP:async()=>"127.0.0.1",
    GetValidatorState:async()=>({status:'idle',results:[],ports:[],ranges:[],retained:0}),
    GetScannerState:async()=>({status:'idle',results:[],validResolvers:[],total:0,completed:0}),
    GetParallelTestState:async()=>({status:'idle',candidates:[],resolverResults:[],selectedPresetIds:[]}),
    GetParallelTestPresetOptions:async()=>[],GetCottenDNSOptionSchema:async()=>current._cottenSchema||[],
    SaveSettingsProfile:async profile=>{window.testCalls.push(["save-settings",profile]);current.settingsProfiles=current.settingsProfiles.map(p=>p.id===profile.id?profile:p);return clone();},
    GetDefaultSettingsProfile:async()=>current.settingsProfiles[0],
    CheckFirewallStatus:async()=>({supported:false,enabled:false,message:'Synthetic test'}),
    RefreshSubscriptions:async due=>{window.testCalls.push(['refresh',due]);return clone();},
    ImportSubscription:async(address,allow)=>{window.testCalls.push(['import',address,allow]);return clone();},
    SelectConnectionProfile:async id=>{current.selectedConnectionProfileId=id;return clone();},
    SelectSettingsProfile:async id=>{current.selectedSettingsProfileId=id;return clone();},
    SaveConnectionProfile:async profile=>{window.testCalls.push(['save',profile]);current.connectionProfiles=current.connectionProfiles.map(p=>p.id===profile.id?profile:p);return clone();},
   };
   window.go={main:{App:new Proxy(methods,{get:(object,key)=>object[key]||async function(){return [];}})}};
   window.runtime={EventsOn:()=>()=>{},InitializeNotifications:async()=>{},CleanupNotifications:async()=>{}};
  },fixture);
  await page.goto(origin);await page.getByRole('button',{name:'Connections',exact:true}).click();
  await page.getByRole('heading',{name:'Connection Profiles',exact:true}).waitFor();
  await page.getByRole('button',{name:'Refresh subscriptions',exact:true}).click();
  assert.ok(await page.evaluate(()=>window.testCalls.some(c=>c[0]==='refresh'&&c[1]===false)));
  await page.getByRole('button',{name:'Import',exact:true}).click();
  const dialog=page.getByRole('dialog');await dialog.getByRole('textbox',{name:'Profiles',exact:true}).fill('https://panel.example.org/sub/test');
  await dialog.getByRole('button',{name:'Import',exact:true}).click();await dialog.waitFor({state:'hidden'});
  assert.ok(await page.evaluate(()=>window.testCalls.some(c=>c[0]==='import'&&c[2]===false)));
  await page.getByRole('button',{name:'Import',exact:true}).click();await dialog.getByRole('textbox',{name:'Profiles',exact:true}).fill('http://panel.example.org/sub/test');
  assert.ok(await dialog.getByRole('button',{name:'Import',exact:true}).isDisabled());
  await dialog.getByRole('checkbox').check();await dialog.getByRole('button',{name:'Import',exact:true}).click();await dialog.waitFor({state:'hidden'});
  assert.ok(await page.evaluate(()=>window.testCalls.some(c=>c[0]==='import'&&c[2]===true)));
  await page.screenshot({path:path.join(out,'subscriptions-desktop-1440.png'),fullPage:true});
  await page.locator('tr[role=button]').filter({hasText:'Soar Test'}).click();await dialog.waitFor();
  await page.getByRole('region',{name:'Soar advanced settings'}).waitFor();
  assert.equal(await dialog.getByRole('combobox',{name:'Resolver transport'}).count(),1);
  const first=page.locator('#soar-safeQName');await first.scrollIntoViewIfNeeded();await first.hover();
  assert.equal(await page.getByRole('tooltip').count(),0,'field hover must not open help');
  await page.getByRole('button',{name:'Help: Initial safe query length',exact:true}).hover();
  await page.getByRole('tooltip').waitFor();assert.match(await page.getByRole('tooltip').innerText(),/101/);
  await page.keyboard.press('Escape');await dialog.getByRole('button',{name:'Limited path',exact:true}).click();
  assert.equal(await page.locator('#soar-maxQName').inputValue(),'101');
  await dialog.getByRole('button',{name:'Automatic',exact:true}).click();assert.equal(await page.locator('#soar-maxQName').inputValue(),'253');
  for(const width of [1440,900,600]){await page.setViewportSize({width,height:1000});await page.screenshot({path:path.join(out,`soar-settings-${width}.png`),fullPage:true});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'page overflow');}
  await dialog.getByRole('button',{name:'Save',exact:true}).click();await dialog.waitFor({state:'hidden'});
  assert.ok(await page.evaluate(()=>window.testCalls.some(c=>c[0]==='save'&&c[1].soarSettings.maxQName===253&&c[1].subscription)));
  await page.setViewportSize({width:1440,height:1000});
  await page.locator('tr[role=button]').filter({hasText:'Cotten Test'}).click();await dialog.waitFor();
  assert.equal(await dialog.getByRole('combobox',{name:'Normal-mode encryption',exact:true}).count(),1);
  assert.equal(await dialog.getByRole('region',{name:'Soar advanced settings'}).count(),0);
  await dialog.getByRole('button',{name:'Save',exact:true}).click();await dialog.waitFor({state:'hidden'});
  assert.ok(await page.evaluate(()=>window.testCalls.some(c=>c[0]==='save'&&c[1].id==='cotten-ui'&&c[1].encryptionKey==='shared-test-key')));
  await page.getByRole('button',{name:'Settings',exact:true}).click();
  await page.locator('tr[role=button]').filter({hasText:'CottenMax Settings'}).click();await dialog.waitFor();
  await dialog.getByRole('tab',{name:'CottenDNS',exact:true}).click();
  const mode=dialog.getByRole('combobox',{name:'CottenDNS mode',exact:true});await mode.waitFor();
  assert.match(await mode.innerText(),/CottenMax/);
  await mode.click();await page.getByRole('option',{name:'Normal CottenDNS',exact:true}).click();
  await mode.click();await page.getByRole('option',{name:'CottenMax (beta)',exact:true}).click();
  await page.screenshot({path:path.join(out,'cottenmax-settings-1440.png'),fullPage:true});
  await dialog.getByRole('button',{name:'Save',exact:true}).click();await dialog.waitFor({state:'hidden'});
  assert.ok(await page.evaluate(()=>window.testCalls.some(c=>c[0]==='save-settings'&&c[1].cottenDnsOptions.TUNNEL_MODE==='cottenmax'&&c[1].cottenDnsOptions.RESOLVER_TRANSPORT==='auto')));
  assert.deepEqual(errors,[]);console.log('PASS: desktop subscription import/HTTP consent/refresh, Soar tuning, question-only help, presets, save and responsive views; CottenMax mode switching and profile boundaries.');
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(e=>{console.error(e);process.exitCode=1;server.close();});
