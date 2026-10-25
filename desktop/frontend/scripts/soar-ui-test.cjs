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
  const installBridge=state=>{
   let current=structuredClone(state);window.testCalls=[];
   const locationCase=new URLSearchParams(location.search).get('location-test');let countryCalls=0;
   if(locationCase){
    current.selectedConnectionProfileId='cotten-ui';current.selectedSettingsProfileId='cotten-ui-settings';
    const connection=current.connectionProfiles.find(p=>p.id==='cotten-ui');connection.name='Iran profile';connection.domain='cot.user.iran.example.org';connection.domains=[connection.domain];
    current.runtime={...current.runtime,status:'connected',activeConnectionId:'cotten-ui',listenIp:'127.0.0.1',localProxyIp:'127.0.0.1',listenPort:10886,proxyProtocol:'socks'};
   }
   let scan={status:'idle',mode:'manual',paused:false,phase:'',message:'',inputFileName:'',scanParallel:200,total:0,completed:0,valid:0,rejected:0,invalid:0,duplicates:0,validResolvers:[],testingPaths:[],workingPaths:[]};
   const clone=()=>structuredClone(current);
   const methods={
    GetAppState:async()=>clone(),
    LookupProxyCountry:async()=>{
     window.testCalls.push(['country',++countryCalls]);
     if(countryCalls===1&&locationCase==='retry')throw new Error('Country lookup timed out');
     if(countryCalls===1&&locationCase==='invalid')return {ok:false,ip:'',countryCode:'IR',proxy:'127.0.0.1:10886',message:'Country lookup unavailable'};
     return {ok:true,ip:'203.0.113.10',countryCode:locationCase==='iran'?'IR':'DE',proxy:'127.0.0.1:10886',message:'Proxy egress IP 203.0.113.10'};
    },
    ValidateResolverText:async raw=>({isValid:true,normalizedResolvers:raw.split(/\r?\n/).filter(Boolean),normalizedText:raw,invalidEntries:[]}),
    GetSystemLANIP:async()=>"127.0.0.1",
    GetValidatorState:async()=>({status:'idle',results:[],ports:[],ranges:[],retained:0}),
    GetScannerState:async()=>structuredClone(scan),
    SelectScannerInputFile:async()=>{scan={...scan,inputFileName:'scan.resolvers',total:2};return structuredClone(scan);},
    StartScannerScan:async request=>{window.testCalls.push(['scan',request]);scan={...scan,status:'running',phase:'probing',scanParallel:request.scanParallel,selectedConnectionProfileId:request.connectionProfileId,startedAt:Date.now()};return structuredClone(scan);},
    CancelScannerScan:async()=>{window.testCalls.push(['cancel-scan']);scan={...scan,status:'cancelled',finishedAt:Date.now()};return structuredClone(scan);},
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
  };
  await page.addInitScript(installBridge,fixture);
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
  await page.getByRole('button',{name:'DNS Scanner',exact:true}).click();
  await page.getByRole('heading',{name:'DNS Scanner',exact:true}).waitFor();
  const scannerProfile=page.getByRole('combobox');
  await scannerProfile.click();await page.getByRole('option',{name:'Soar Test',exact:true}).click();
  const workers=page.getByRole('spinbutton');
  assert.equal(await workers.getAttribute('max'),'8');assert.equal(await workers.inputValue(),'8');
  await page.getByText(/Verifies each resolver with the Soar server public key/).waitFor();
  await page.getByRole('button',{name:'File',exact:true}).click();
  await page.getByRole('button',{name:'Scan',exact:true}).click();
  assert.ok(await page.evaluate(()=>window.testCalls.some(c=>c[0]==='scan'&&c[1].connectionProfileId==='soar-ui'&&c[1].scanParallel===8)));
  assert.ok(await page.getByRole('button',{name:'Pause',exact:true}).isDisabled());
  assert.ok(await page.getByRole('button',{name:'Cancel',exact:true}).isEnabled());
  await page.screenshot({path:path.join(out,'soar-scanner-running.png'),fullPage:true});
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  assert.ok(await page.evaluate(()=>window.testCalls.some(c=>c[0]==='cancel-scan')));
  await scannerProfile.click();await page.getByRole('option',{name:'Cotten Test',exact:true}).click();
  assert.equal(await workers.getAttribute('max'),'1000');
  for(const scenario of ['retry','invalid','iran']){
   const locationPage=await browser.newPage({viewport:{width:1440,height:1000}});
   locationPage.on('pageerror',e=>errors.push(e.message));
   await locationPage.addInitScript(installBridge,fixture);
   await locationPage.goto(origin+'/?location-test='+scenario);
   if(scenario==='iran'){
    await locationPage.getByText('Iran',{exact:true}).waitFor();
   }else{
    await locationPage.getByText('Unknown',{exact:true}).waitFor({timeout:5000});
    assert.equal(await locationPage.getByText('Iran',{exact:true}).count(),0,'failed lookup must not infer Iran from the domain or profile');
    const retry=locationPage.getByRole('button',{name:'Retry location lookup',exact:true});
    await locationPage.screenshot({path:path.join(out,'location-'+scenario+'-unknown.png'),fullPage:true});
    await retry.click();
    await locationPage.getByText('Germany',{exact:true}).waitFor();
    assert.equal(await retry.count(),0,'verified location must not offer a failed-lookup retry');
    assert.equal(await locationPage.locator('[title="Proxy egress IP 203.0.113.10"]').count(),1);
    assert.equal(await locationPage.evaluate(()=>window.testCalls.filter(c=>c[0]==='country').length),2);
    await locationPage.screenshot({path:path.join(out,'location-'+scenario+'.png'),fullPage:true});
   }
   await locationPage.close();
  }
  assert.deepEqual(errors,[]);console.log('PASS: desktop subscription import/HTTP consent/refresh, Soar tuning, question-only help, presets, save and responsive views; CottenMax mode switching and profile boundaries; Soar scanner selection, bounded workers, supported controls and cancellation; verified proxy location, honest failed lookups and retry recovery.');
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(e=>{console.error(e);process.exitCode=1;server.close();});
