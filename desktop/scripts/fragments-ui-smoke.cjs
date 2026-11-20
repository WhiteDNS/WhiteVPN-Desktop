const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {spawn} = require('node:child_process');
const assert = require('node:assert/strict');
// Run after TestFragmentUIFixture and the frontend build.
// The browser bridge uses disposable backend-derived settings on localhost.
const root = path.resolve(__dirname, '../..');
const fixture = JSON.parse(fs.readFileSync(path.join(root, '.cache/fragment-ui-fixture.json'), 'utf8'));
const artifacts = path.join(root, '.cache/fragments-ui');
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
    case 'GetWhiteVPNSettingsForEdit': return structuredClone(f.settings);
    case 'GetFragmentPresets': return structuredClone(f.presets);
    case 'GetDefaultFragmentSettings': return structuredClone(f.fragmentDefaults);
    case 'ValidateFragmentSettings': {
      if (window.__validationError) throw new Error('Invalid fragment JSON');
      const s=structuredClone(args[0]); s.rawJson=JSON.stringify(JSON.parse(s.rawJson),null,2); return s;
    }
    case 'SaveWhiteVPNSettings':
      f.settings=structuredClone(args[0]);
      f.state.whiteVpn.fragments=structuredClone(args[0].fragments);
      f.state.whiteVpn.language=args[0].language;
      return structuredClone(f.state);
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
  chrome = spawn(process.env.CHROME_BIN || 'C:/Program Files/Google/Chrome/Application/chrome.exe', ['--headless=new','--disable-gpu','--in-process-gpu','--no-sandbox','--no-first-run','--no-default-browser-check','--remote-debugging-port=0','--user-data-dir='+profileDir,'about:blank'], {windowsHide:true,stdio:['ignore',log,log]});
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

  await cdp('Runtime.enable'); await cdp('Page.enable');
  await cdp('Page.addScriptToEvaluateOnNewDocument',{source:mock});
  await cdp('Emulation.setDeviceMetricsOverride',{width:1280,height:900,deviceScaleFactor:1,mobile:false});
  await cdp('Page.navigate',{url:'http://127.0.0.1:'+server.address().port+'/'});
  await wait("Array.from(document.querySelectorAll('button')).some(e=>e.textContent.includes('Fragments'))",'dashboard fragment shortcut');
  await evaluate("Array.from(document.querySelectorAll('button')).find(e=>e.textContent.includes('Fragments')).click()");
  await wait("document.getElementById('fragments-enabled')",'shortcut opens fragment settings');
  await evaluate("document.getElementById('fragments-enabled').click()");
  await wait("document.getElementById('fragment-json') && window.__fixture.settings.fragments.enabled",'enabling persists immediately');
  await wait("document.getElementById('fragment-preset') && !document.getElementById('fragment-preset').disabled",'preset controls ready');
  await evaluate("document.getElementById('fragment-preset').click()");
  await wait("document.querySelectorAll('[role=option]').length===6",'six Android presets');
  await evaluate("Array.from(document.querySelectorAll('[role=option]')).find(e=>e.textContent.includes('Suggestion 5')).click()");
  await wait("document.getElementById('fragment-json').value.includes('8-14')",'preset populates JSON');
  await clickText('Validate, format & apply');
  await wait("window.__fixture.settings.fragments.rawJson.includes('8-14')",'preset saved');
  await wait("document.getElementById('fragment-preset') && !document.getElementById('fragment-preset').disabled",'preset save complete');
  await clickText('VPN');
  await wait("Array.from(document.querySelectorAll('button')).some(e=>e.textContent.includes('Fragments'))",'back to dashboard');
  await evaluate("Array.from(document.querySelectorAll('button')).find(e=>e.textContent.includes('Fragments')).click()");
  await wait("document.getElementById('fragment-preset')?.textContent.includes('Suggestion 5')",'selected preset survives navigation');
  checks.push('dashboard shortcut, immediate toggle save, six presets, preset persistence');
  const setValue=async(id,value)=>evaluate(`(()=>{const e=document.getElementById(${JSON.stringify(id)});const proto=e.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;Object.getOwnPropertyDescriptor(proto,'value').set.call(e,${JSON.stringify(value)});e.dispatchEvent(new Event('input',{bubbles:true}));})()`);
  await setValue('fragment-json','{"tcp":[]}');
  await wait("document.getElementById('fragment-preset').textContent.includes('Customised')",'custom JSON label');
  const before=await evaluate("window.__calls.filter(c=>c.name==='SaveWhiteVPNSettings').length");
  await evaluate('window.__validationError=true');
  await clickText('Validate, format & apply');
  await wait("document.querySelector('#fragment-settings [role=alert]')?.textContent.includes('Invalid fragment JSON')",'validation error stays visible');
  assert.equal(await evaluate("window.__calls.filter(c=>c.name==='SaveWhiteVPNSettings').length"),before);
  await evaluate('window.__validationError=false');
  await clickText('Restore defaults');
  await wait("document.getElementById('fragment-json').value.includes('13-23')",'restore defaults');
  await setValue('fragment-alpn',''); await setValue('fragment-ciphers','');
  await clickText('Validate, format & apply');
  await wait("window.__fixture.settings.fragments.alpn==='' && window.__fixture.settings.fragments.cipherSuites===''",'blank TLS overrides retained');
  checks.push('custom indicator, validation rejection without save, defaults, blank server TLS overrides');
  await wait("document.getElementById('fragment-preset') && !document.getElementById('fragment-preset').disabled",'editor ready');
  await evaluate("document.getElementById('fragment-settings').scrollIntoView({block:'start'})");
  await pause(200);
  let shot=await cdp('Page.captureScreenshot',{format:'png'});
  fs.writeFileSync(path.join(artifacts,'fragments-en.png'),Buffer.from(shot.data,'base64'));
  await evaluate("Array.from(document.querySelectorAll('[role=combobox]')).find(e=>e.textContent.includes('English')).click()");
  await wait("Array.from(document.querySelectorAll('[role=option]')).some(e=>e.textContent.includes('فارسی'))",'Persian language option');
  await evaluate("Array.from(document.querySelectorAll('[role=option]')).find(e=>e.textContent.includes('فارسی')).click()");
  await clickText('Save changes');
  await wait("document.documentElement.dir==='rtl' && document.getElementById('fragments-enabled')",'Persian RTL settings');
  await evaluate("document.getElementById('fragment-settings').scrollIntoView({block:'start'})");
  await pause(200);
  shot=await cdp('Page.captureScreenshot',{format:'png'});
  fs.writeFileSync(path.join(artifacts,'fragments-fa.png'),Buffer.from(shot.data,'base64'));
  assert.equal(await evaluate("document.getElementById('fragment-json').dir"),'ltr');
  assert.equal(await evaluate("document.getElementById('fragment-alpn').dir"),'ltr');
  assert.equal(await evaluate(`(()=>{const track=document.getElementById('fragments-enabled').getBoundingClientRect();const thumb=document.querySelector('#fragments-enabled [data-slot=switch-thumb]').getBoundingClientRect();return thumb.left>=track.left && thumb.right<=track.right;})()`),true,'RTL switch thumb stays inside its track');
  checks.push('English and Persian RTL layouts with LTR JSON/TLS fields');
  await evaluate("document.getElementById('fragments-enabled').click()");
  await wait("!window.__fixture.settings.fragments.enabled && !document.getElementById('fragment-json')",'disabling persists and collapses advanced fields');
  assert.deepEqual(await evaluate('window.__uiErrors'),[]);
  assert.deepEqual(errors,[]);
  const report={passed:true,browser:'Chrome headless',bridge:'disposable Wails mock using Go-generated defaults and presets',checks,errors};
  fs.writeFileSync(path.join(artifacts,'checks.json'),JSON.stringify(report,null,2));
  console.log(JSON.stringify(report));
})().catch(e=>{console.error(e.stack);process.exitCode=1;}).finally(()=>{if(ws)ws.close();if(chrome)chrome.kill();server.close();setTimeout(()=>process.exit(process.exitCode||0),1000);});
