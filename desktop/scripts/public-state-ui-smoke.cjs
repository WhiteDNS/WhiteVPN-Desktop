const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {spawn} = require('node:child_process');
const assert = require('node:assert/strict');
// Run from the repository root after generating the Go API fixture and building
// the frontend. Only localhost pages and disposable credentials are loaded.
const root = path.resolve(__dirname, '../..');
const fixture = JSON.parse(fs.readFileSync(path.join(root, '.cache/public-ui-fixture.json'), 'utf8'));
const artifacts = path.join(root, '.cache/public-state-ui');
fs.mkdirSync(artifacts, {recursive:true});
const profileDir = fs.mkdtempSync(path.join(artifacts, 'chrome-'));
const dist = path.join(root, 'desktop/frontend/dist');
const mock = `
window.__fixture = ${JSON.stringify(fixture)};
window.__calls = [];
window.__uiErrors = [];
window.addEventListener('error', e => window.__uiErrors.push(e.error?.stack || e.message));
window.addEventListener('unhandledrejection', e => window.__uiErrors.push(String(e.reason)));
window.runtime = {EventsOn: () => () => {}, IsNotificationAvailable: async () => false};
window.go = {main: {App: new Proxy({}, {get: (_, name) => async (...args) => {
  window.__calls.push({name, args});
  const f = window.__fixture;
  switch(name) {
    case 'GetAppState': return structuredClone(f.state);
    case 'GetAppVersion': return 'smoke-test';
    case 'GetLocalProxyEndpoint': return '';
    case 'GetPrivacyPolicyVersion': return 1;
    case 'GetLegacyImportOffer': return {available:false};
    case 'GetValidatorState': return {status:'idle',results:[],logs:[],ranges:[]};
    case 'CheckForUpdate': return {available:false,currentVersion:'smoke-test'};
    case 'CheckFirewallStatus': return {supported:false};
    case 'GetSystemLANIP': return '127.0.0.1';
    case 'TunnelSupported': return true;
    case 'ListWhiteVPNNodes':
    case 'ListSubscriptionNodes': return structuredClone(f.nodes);
    case 'GetV2RaySubscriptionForEdit': return structuredClone(f.subscription);
    case 'GetWhiteVPNSettingsForEdit': return structuredClone(f.settings);
    case 'ManualNodeProfile': return structuredClone(f.profile);
    case 'ExportNodeLinks': {
      const links=args[1].map(name => ({name,link:'vless://'+f.profile.uuid+'@localhost:443#Demo'}));
      if (window.__deferShare) return new Promise(resolve=>window.__releaseShare=()=>resolve(links));
      return links;
    }
    case 'SaveV2RaySubscription': f.subscription=structuredClone(args[0]); return structuredClone(f.state);
    case 'SaveWhiteVPNSettings': f.settings=structuredClone(args[0]); return structuredClone(f.state);
    case 'SaveManualNode': f.profile=structuredClone(args[0]); return structuredClone(f.nodes);
    default: throw new Error('Unmocked backend method: '+String(name));
  }
}})}};
`;
const server = http.createServer((req,res) => {
  const relative = decodeURIComponent(new URL(req.url,'http://localhost').pathname).replace(/^\/+/, '') || 'index.html';
  const file = path.resolve(dist, relative);
  if (!file.startsWith(dist+path.sep)) {res.writeHead(403).end(); return;}
  try {
    let bytes = fs.readFileSync(file);
    res.setHeader('Content-Type', file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.html')?'text/html':'application/octet-stream');
    res.end(bytes);
  } catch {res.writeHead(404).end();}
});
let chrome, ws;
const pause = ms => new Promise(r=>setTimeout(r,ms));
const checks=[];
(async()=>{
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const log=fs.openSync(path.join(profileDir,'chrome.log'),'a');
  chrome = spawn('C:/Program Files/Google/Chrome/Application/chrome.exe', ['--headless=new','--disable-gpu','--in-process-gpu','--no-sandbox','--no-first-run','--no-default-browser-check','--remote-debugging-port=0','--user-data-dir='+profileDir,'about:blank'], {windowsHide:true,stdio:['ignore',log,log]});
  chrome.on('exit',(code,signal)=>console.log('Chrome exit',code,signal));
  chrome.on('error',e=>console.error(e.message));
  let port;
  for(let i=0;i<100;i++) {try{port=fs.readFileSync(path.join(profileDir,'DevToolsActivePort'),'utf8').split('\n')[0];break;}catch{await pause(100);}}
  assert.ok(port,'Chrome did not expose the isolated DevTools port');
  console.log('Chrome started');
  const targets = await (await fetch('http://127.0.0.1:'+port+'/json/list')).json();
  ws = new WebSocket(targets.find(t=>t.type==='page').webSocketDebuggerUrl);
  await new Promise((r,j)=>{ws.addEventListener('open',r,{once:true});ws.addEventListener('error',j,{once:true});});
  console.log('DevTools connected');
  let seq=0; const pending=new Map(); const errors=[];
  ws.addEventListener('message', e=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);if(p){pending.delete(m.id);m.error?p.reject(Error(m.error.message)):p.resolve(m.result);}} else if(m.method==='Runtime.exceptionThrown') errors.push(m.params.exceptionDetails.text);});
  const cdp=(method,params={})=>new Promise((resolve,reject)=>{const id=++seq;const timer=setTimeout(()=>{pending.delete(id);reject(Error('DevTools timeout: '+method));},15000);pending.set(id,{resolve:r=>{clearTimeout(timer);resolve(r);},reject:e=>{clearTimeout(timer);reject(e);}});ws.send(JSON.stringify({id,method,params}));});
  const evaluate=async(expression)=>{const r=await cdp('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw Error(r.exceptionDetails.exception?.description||r.exceptionDetails.text);return r.result.value;};
  const wait=async(expression,label)=>{for(let i=0;i<100;i++){if(await evaluate('Boolean('+expression+')')){console.log('Passed:',label);return;}await pause(100);}throw Error('Timed out: '+label+'\n'+JSON.stringify(await evaluate('({url:location.href,text:document.body.innerText,errors:window.__uiErrors,calls:window.__calls})')));};
  const clickText=async(text,scope='document')=>evaluate(`(()=>{const b=Array.from(${scope}.querySelectorAll('button')).find(e=>e.textContent.trim()===${JSON.stringify(text)});if(!b)throw Error('Missing button: '+${JSON.stringify(text)});b.click();})()`);
  const dialog="document.querySelector('[role=dialog]')";
  await cdp('Runtime.enable'); await cdp('Page.enable');
  await cdp('Page.addScriptToEvaluateOnNewDocument',{source:mock});
  await cdp('Emulation.setDeviceMetricsOverride',{width:1360,height:1000,deviceScaleFactor:1,mobile:false});
  await cdp('Page.navigate',{url:'http://127.0.0.1:'+server.address().port+'/'});
  await wait("Array.from(document.querySelectorAll('button')).some(e=>e.textContent.trim()==='Servers')",'initial app render');
  assert.equal(await evaluate("window.__calls.some(c=>['GetWhiteVPNSettingsForEdit','GetV2RaySubscriptionForEdit','ManualNodeProfile','ExportNodeLinks'].includes(c.name))"),false,'private API called on initial dashboard');
  checks.push('initial dashboard uses only public state');
  await clickText('Servers');
  await wait("document.querySelector('button[aria-label=Share]:not(:disabled)')",'node rows from public metadata');
  assert.equal(await evaluate("document.body.innerText.includes('11111111-1111')"),false);
  await evaluate("document.querySelector('button[aria-label=Share]').click()");
  await wait("document.querySelector('[role=dialog]')?.innerText.includes('vless://') || Array.from(document.querySelectorAll('[role=dialog] textarea')).some(e=>e.value.includes('vless://'))",'explicit share link');
  assert.equal(await evaluate("window.__calls.filter(c=>c.name==='ExportNodeLinks').length"),1);
  await clickText('Close',dialog).catch(()=>evaluate("document.querySelector('[role=dialog] button[data-slot=dialog-close]')?.click()"));
  await evaluate("document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))");
  await wait("!document.querySelector('[role=dialog]')",'share closes');
  checks.push('Share requests selected node link only when opened');
  await evaluate("document.querySelector('button[aria-label=Edit]').click()");
  await wait("Array.from(document.querySelectorAll('[role=dialog] input')).some(e=>e.value==='11111111-1111-1111-1111-111111111111')",'manual editor private credential');
  await clickText('Save',dialog);
  await wait("window.__calls.some(c=>c.name==='SaveManualNode')",'manual editor save');
  assert.equal(await evaluate("window.__calls.find(c=>c.name==='SaveManualNode').args[0].uuid"),fixture.profile.uuid);
  assert.equal(await evaluate("window.__calls.find(c=>c.name==='SaveManualNode').args[0].password"),fixture.profile.password);
  await wait("!document.querySelector('[role=dialog]')",'manual editor closes');
  checks.push('manual editor preserves credentials fetched explicitly');
  await evaluate("Array.from(document.querySelectorAll('button')).find(e=>e.textContent.trim().startsWith('Export all')).click()");
  await wait("Array.from(document.querySelectorAll('[role=dialog] textarea')).some(e=>e.value.includes('vless://'))",'bulk export fetches links explicitly');
  assert.equal(await evaluate("window.__calls.filter(c=>c.name==='ExportNodeLinks').length"),2);
  await clickText('Close',dialog);
  await wait("!document.querySelector('[role=dialog]')",'bulk export closes');
  checks.push('bulk export remains available with public node metadata');
  await evaluate("window.__deferShare=true;document.querySelector('button[aria-label=Share]').click()");
  await wait("typeof window.__releaseShare==='function'",'delayed share request');
  await clickText('Subscriptions');
  await wait("document.body.innerText.includes('Demo provider')",'public subscription row');
  await evaluate("window.__releaseShare();window.__deferShare=false");
  await pause(100);
  assert.equal(await evaluate("Boolean(document.querySelector('[role=dialog]'))"),false);
  checks.push('navigation discards a late private Share response');
  assert.equal(await evaluate("document.body.innerText.includes('subscription-secret-marker')"),false);
  await evaluate("Array.from(document.querySelectorAll('tr')).find(e=>e.innerText.includes('Demo provider')).click()");
  await wait("Array.from(document.querySelectorAll('[role=dialog] input')).some(e=>e.value.includes('subscription-secret-marker'))",'subscription editor private URL');
  await clickText('Save',dialog);
  await wait("window.__calls.some(c=>c.name==='SaveV2RaySubscription')",'subscription save');
  assert.equal(await evaluate("window.__calls.find(c=>c.name==='SaveV2RaySubscription').args[0].url"),fixture.subscription.url);
  checks.push('subscription editor fetches and preserves full URL');
  await wait("!document.querySelector('[role=dialog]')",'editor closes');
  await clickText('Settings');
  await wait("Array.from(document.querySelectorAll('input')).some(e=>e.value.includes('dns-secret-marker'))",'settings editor private DNS');
  // React's native input setter simulates a user edit through the real change handler.
  await evaluate(`(()=>{const e=Array.from(document.querySelectorAll('input')).find(e=>e.value.includes('dns-secret-marker'));Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,e.value+'-edited');e.dispatchEvent(new Event('input',{bubbles:true}));})()`);
  await wait("Array.from(document.querySelectorAll('button')).some(e=>e.textContent.trim()==='Save changes'&&!e.disabled)",'settings dirty');
  await clickText('Save changes');
  await wait("window.__calls.some(c=>c.name==='SaveWhiteVPNSettings')",'settings save');
  assert.equal(await evaluate("window.__calls.find(c=>c.name==='SaveWhiteVPNSettings').args[0].dnsPrivacy.dohUrl"),fixture.settings.dnsPrivacy.dohUrl+'-edited');
  await wait("window.__calls.filter(c=>c.name==='GetWhiteVPNSettingsForEdit').length>=2",'settings editor reload after secret-only save');
  assert.equal(await evaluate("Array.from(document.querySelectorAll('button')).find(e=>e.textContent.trim()==='Save changes')?.disabled"),true);
  checks.push('secret-only settings edit saves full details and reloads editor');
  assert.deepEqual(await evaluate('window.__uiErrors'),[]);
  assert.deepEqual(errors,[]);
  const screenshot=await cdp('Page.captureScreenshot',{format:'png'});
  fs.writeFileSync(path.join(artifacts,'settings.png'),Buffer.from(screenshot.data,'base64'));
  const report={passed:true,browser:'Chrome headless',bridge:'disposable Wails mock populated by Go public API fixture',checks,errors};
  fs.writeFileSync(path.join(artifacts,'checks.json'),JSON.stringify(report,null,2));
  console.log(JSON.stringify(report));
})().catch(e=>{console.error(e.stack);process.exitCode=1;}).finally(()=>{if(ws)ws.close();if(chrome)chrome.kill();server.close();setTimeout(()=>process.exit(process.exitCode||0),1000);});
