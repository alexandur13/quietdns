// Browser interaction tests use an explicitly labelled, in-memory API fixture.
// Real DNS, authentication and persistence are covered by the Go suite.
import {createServer} from 'node:http';
import {readFile,mkdir} from 'node:fs/promises';
import {resolve,extname,join} from 'node:path';
import {createRequire} from 'node:module';
import assert from 'node:assert/strict';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=resolve(import.meta.dirname,'../web');
let setupRequired=true,authenticated=false;
const settings={name:'Home network',upstreams:['1.1.1.1:53','9.9.9.9:53'],rules:[],logging:true};
const now=Date.now();
const sources=[{id:'hagezi-light',name:'HaGeZi Light',description:'A gentle starting point. Blocks common ads and trackers with fewer interruptions.',url:'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt',enabled:true,count:35206,updated:new Date(now-3600000),error:''},{id:'hagezi-normal',name:'HaGeZi Normal',description:'Broader coverage of advertising, tracking and malicious domains.',url:'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt',enabled:false,count:0,updated:'0001-01-01T00:00:00Z',error:''}];
let queries=Array.from({length:24},(_,i)=>({time:new Date(now-i*12300),domain:['api.github.com','ads.example.test','cdn.example.org','telemetry.example.test','fonts.example.org','news.example.org'][i%6],type:'A',client:i%2?'192.168.1.24':'192.168.1.18',status:i%3===1?'blocked':'allowed',reason:'Browser test fixture',latency:8.2+i/10}));
const buckets=Array.from({length:144},(_,i)=>({time:new Date(now-(143-i)*600000),total:Math.round(220+130*Math.sin(i/4)+90*Math.sin(i/7)),blocked:Math.round(32+23*Math.sin(i/4)),errors:0,latency:2000}));
let pausedUntil='0001-01-01T00:00:00Z';
const failures=[];
const server=createServer(async(req,res)=>{
 try{
  if(req.url.startsWith('/api/')){
   let body='';for await(const chunk of req)body+=chunk;const input=body?JSON.parse(body):{};let result={ok:true};
   switch(req.url){
    case '/api/status':result={setupRequired,authenticated};break;
    case '/api/setup':if(input.password.length<12)throw Error('password too short');setupRequired=false;authenticated=true;settings.name=input.name;break;
    case '/api/login':authenticated=true;break;
    case '/api/logout':authenticated=false;break;
    case '/api/overview':result={demo:true,name:settings.name,total:32741,blocked:5193,errors:0,latency:12.4,clients:8,domains:35207,buckets,queries,topDomains:[{domain:'ads.example.test',count:241},{domain:'telemetry.example.test',count:186},{domain:'metrics.example.test',count:95},{domain:'tracking.example.test',count:68},{domain:'pixel.example.test',count:32}],sources,pausedUntil,logging:settings.logging,updating:false,persistenceError:'',version:'0.2.0-preview'};break;
    case '/api/settings':if(req.method==='PUT')Object.assign(settings,input);result=settings;break;
    case '/api/rules':settings.rules=settings.rules.filter(r=>r.domain!==input.domain);if(req.method==='POST')settings.rules.push(input);break;
    case '/api/pause':pausedUntil=input.minutes?new Date(Date.now()+input.minutes*60000):'0001-01-01T00:00:00Z';break;
    case '/api/sources':sources.find(s=>s.id===input.id).enabled=input.enabled;break;
    case '/api/check':result=[{name:'UDP upstream',ok:true},{name:'TCP upstream',ok:true},{name:'Blocking rules',ok:true}];break;
    case '/api/history':queries=[];break;
   }
   res.setHeader('Content-Type','application/json');res.end(JSON.stringify(result));return;
  }
  const path=join(root,req.url==='/'?'index.html':req.url.split('?')[0]);
  if(!path.startsWith(root)){res.writeHead(403);res.end();return}
  const data=await readFile(path);res.setHeader('Content-Type',({'.html':'text/html','.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.svg':'image/svg+xml'})[extname(path)]||'text/plain');res.end(data);
 }catch(err){res.writeHead(500,{'Content-Type':'application/json'});res.end(JSON.stringify({error:err.message}))}
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
if(process.env.PREVIEW_ONLY){setupRequired=process.env.PREVIEW_SETUP==='1';authenticated=!setupRequired;console.log(`Preview: http://127.0.0.1:${server.address().port}`);await new Promise(()=>{})}
const browser=await chromium.launch({headless:true,...(process.env.BROWSER_EXECUTABLE?{executablePath:process.env.BROWSER_EXECUTABLE}:{})});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1080}});page.on('pageerror',e=>failures.push(e.message));
 await page.goto(`http://127.0.0.1:${server.address().port}`);
 await page.getByLabel('Network name').fill('Home network');await page.getByLabel('Installation key').fill('test-only-installation-key');await page.getByLabel('Administrator password').fill('a-long-test-password');
 await page.getByRole('button',{name:'Choose your protection'}).click();
 const screenshots=process.env.SCREENSHOT_DIR;if(screenshots){await mkdir(screenshots,{recursive:true});await page.screenshot({path:join(screenshots,'setup.png'),fullPage:true})}
 await page.getByRole('button',{name:'Create my network'}).click();await page.getByRole('button',{name:'Open my dashboard'}).click();await page.getByRole('heading',{name:'Overview',exact:true}).waitFor();
 if(screenshots)await page.screenshot({path:join(screenshots,'dashboard.png'),fullPage:true});
 await page.getByRole('button',{name:'Pause for 5 min'}).click();await page.getByRole('button',{name:'Resume protection'}).waitFor();await page.getByRole('button',{name:'Resume protection'}).click();
 await page.getByRole('link',{name:'Query log',exact:true}).click();await page.getByLabel('Search domains or clients').fill('ads.example.test');assert.equal(await page.locator('tbody tr').count(),4);
 await page.getByLabel('Filter query status').selectOption('blocked');assert.equal(await page.locator('tbody tr').count(),4);
 await page.getByRole('button',{name:'Allow',exact:true}).first().click();await page.getByRole('button',{name:'Save rule'}).click();
 await page.getByRole('link',{name:'Domain rules',exact:true}).click();await page.getByRole('cell',{name:'ads.example.test',exact:true}).waitFor();
 await page.getByRole('button',{name:'Add domain rule'}).click();await page.getByLabel('Domain',{exact:true}).fill('extra.example.test');await page.getByRole('button',{name:'Save rule'}).click();await page.getByRole('cell',{name:'extra.example.test',exact:true}).waitFor();
 await page.getByRole('button',{name:'Remove rule for extra.example.test'}).click();await page.getByRole('cell',{name:'extra.example.test',exact:true}).waitFor({state:'detached'});
 await page.getByRole('link',{name:'Blocklists',exact:true}).click();await page.getByRole('switch',{name:'Enable HaGeZi Normal'}).click();await page.locator('[aria-label="Enable HaGeZi Normal"][aria-checked="true"]').waitFor();
 await page.getByRole('link',{name:'Settings',exact:true}).click();await page.getByLabel('Network name').fill('Office network');await page.getByRole('button',{name:'Save preferences'}).click();await page.getByText('Office network',{exact:true}).waitFor();await page.getByRole('button',{name:'Run checks'}).click();await page.getByText('UDP upstream',{exact:true}).waitFor();
 await page.getByRole('link',{name:'Overview',exact:true}).click();await page.setViewportSize({width:390,height:844});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false,'mobile page overflows horizontally');
 if(screenshots)await page.screenshot({path:join(screenshots,'mobile.png'),fullPage:true});
 await page.getByRole('button',{name:'Toggle navigation'}).click();await page.getByRole('link',{name:'Query log',exact:true}).click();await page.getByRole('heading',{name:'Query log',exact:true}).waitFor();
 await page.getByRole('button',{name:'Sign out',exact:true}).click();await page.getByRole('heading',{name:'Welcome back.'}).waitFor();
 assert.deepEqual(failures,[],'browser console errors');console.log('PASS: setup, dashboard, pause/resume, query search, allow/block rules, source toggle, settings, checks, mobile navigation, logout; no page errors.');
}finally{await browser.close();server.close()}
