#!/usr/bin/env node
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import process from 'node:process';
import { chromium, firefox, webkit } from 'playwright';

const artifactPath = path.resolve(process.argv[2] || 'index.html');
const browserName = (process.argv[3] || process.env.FENC_BROWSER || 'chromium').toLowerCase();
const engines = { chromium, firefox, webkit };
if (!engines[browserName]) throw new Error(`Unsupported browser engine: ${browserName}`);
if (!fs.existsSync(artifactPath)) throw new Error(`Missing artifact: ${artifactPath}`);
const html = fs.readFileSync(artifactPath);

const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Length': html.length,
    });
    res.end(html);
    return;
  }
  res.writeHead(404); res.end('not found');
});
await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', resolve);
});
const port = server.address().port;
const url = `http://127.0.0.1:${port}/index.html`;

const browserType = engines[browserName];
const browser = await browserType.launch({ headless: true });
const page = await browser.newPage();
const pageErrors = [];
page.on('pageerror', e => pageErrors.push(String(e)));
await page.goto(url, { waitUntil: 'load', timeout: 60_000 });

const result = await page.evaluate(async () => {
  const FENC = window.FENC;
  const TEST_PWD = 'Browser-Matrix-Pwd-9f3K!';
  const CHUNK = 4096;
  const ARGON = { kdf:'argon2id', argonMem:19456, argonTime:2, argonPar:1 };
  const out = [];
  const add = async (name, fn) => {
    const t0 = performance.now();
    try {
      const ok = await fn();
      out.push({ name, ok: ok === true, ms: performance.now()-t0, detail: ok === true ? '' : String(ok) });
    } catch (e) {
      out.push({ name, ok:false, ms:performance.now()-t0, detail:String(e?.stack || e) });
    }
  };
  const randBytes = n => crypto.getRandomValues(new Uint8Array(n));
  const mkFile = (bytes, name='browser-test.bin') => new File([bytes], name, {type:'application/octet-stream'});
  const eq = (a,b) => a.length===b.length && a.every((v,i)=>v===b[i]);
  const memWriter = () => {
    const parts=[];
    const collect=()=>{ let n=0; for(const p of parts)n+=p.length; const r=new Uint8Array(n); let o=0; for(const p of parts){r.set(p,o);o+=p.length;} return r; };
    return { kind:'mem', write:c=>parts.push(c instanceof Uint8Array?c:new Uint8Array(c)), finish:async()=>({bytes:collect()}), _collect:collect };
  };
  const encryptToBytes = async (file, opts) => { const w=memWriter(); const ret=await FENC.encryptFile(file,opts,null,w); return {bytes:w._collect(),ret}; };
  const decryptToBytes = async (bytes, opts) => { const w=memWriter(); await FENC.decryptFile(new Blob([bytes]),opts,null,w); return w._collect(); };
  const expectReject = async fn => { try { await fn(); return false; } catch { return true; } };

  await add('secure context and FENC initialized', async()=> isSecureContext && !!crypto.subtle && !!FENC && typeof FENC.encryptFile==='function');

  await add('AES-GCM password round trip', async()=>{
    const data=randBytes(9000); const {bytes}=await encryptToBytes(mkFile(data),{keyMode:'password',password:TEST_PWD,cipher:'gcm',chunkSize:CHUNK,...ARGON});
    return eq(await decryptToBytes(bytes,{keyMode:'password',password:TEST_PWD}),data);
  });
  await add('XChaCha20-Poly1305 password round trip', async()=>{
    const data=randBytes(9000); const {bytes}=await encryptToBytes(mkFile(data),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
    return eq(await decryptToBytes(bytes,{keyMode:'password',password:TEST_PWD}),data);
  });
  await add('RSA-OAEP round trip', async()=>{
    const kp=await FENC.generateRSAKeyPair(2048), data=randBytes(1200);
    const {bytes}=await encryptToBytes(mkFile(data),{keyMode:'rsa',publicKeyPEM:kp.publicKeyPEM,cipher:'xchacha',chunkSize:CHUNK});
    return eq(await decryptToBytes(bytes,{privateKeyPEM:kp.privateKeyPEM}),data);
  });
  await add('X25519 ECDH round trip', async()=>{
    const kp=FENC.generateECCKeyPair('x25519'), data=randBytes(1200);
    const {bytes}=await encryptToBytes(mkFile(data),{keyMode:'ecc',eccPublicKey:kp.publicKeyPEM,cipher:'xchacha',chunkSize:CHUNK});
    return eq(await decryptToBytes(bytes,{eccSecretKey:kp.privateKeyPEM}),data);
  });
  await add('multi-recipient recovery via RSA', async()=>{
    const rsa=await FENC.generateRSAKeyPair(2048), ecc=FENC.generateECCKeyPair('x25519'), data=randBytes(1200);
    const {bytes}=await encryptToBytes(mkFile(data),{keyMode:'multi',recipients:[{type:'rsa',publicKeyPEM:rsa.publicKeyPEM},{type:'ecc',publicKeyPEM:ecc.publicKeyPEM}],cipher:'xchacha',chunkSize:CHUNK});
    return eq(await decryptToBytes(bytes,{privateKeyPEM:rsa.privateKeyPEM}),data);
  });
  await add('wrong password rejected', async()=>{
    const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
    return expectReject(()=>decryptToBytes(bytes,{keyMode:'password',password:'wrong'}));
  });
  await add('Algorithm-ID substitution rejected', async()=>{
    const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
    const t=bytes.slice(); t[6]=0; return expectReject(()=>decryptToBytes(t,{keyMode:'password',password:TEST_PWD}));
  });
  await add('Chunk-size substitution rejected', async()=>{
    const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:4096,...ARGON});
    const t=bytes.slice(); t.set([0,0,32,0],8); return expectReject(()=>decryptToBytes(t,{keyMode:'password',password:TEST_PWD}));
  });
  await add('reserved-header substitution rejected', async()=>{
    const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'gcm',chunkSize:CHUNK,...ARGON});
    const t=bytes.slice(); t[7]=1; return expectReject(()=>decryptToBytes(t,{keyMode:'password',password:TEST_PWD}));
  });
  await add('zero-byte XChaCha round trip', async()=>{
    const {bytes}=await encryptToBytes(mkFile(new Uint8Array(0),'empty.bin'),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
    const pt=await decryptToBytes(bytes,{keyMode:'password',password:TEST_PWD}); return pt.length===0;
  });
  await add('minimum chunk size accepted', async()=>{
    const data=randBytes(8); const {bytes}=await encryptToBytes(mkFile(data),{keyMode:'password',password:TEST_PWD,cipher:'gcm',chunkSize:1024,...ARGON});
    return eq(await decryptToBytes(bytes,{keyMode:'password',password:TEST_PWD}),data);
  });
  await add('below-minimum chunk size rejected by writer', async()=> expectReject(()=>encryptToBytes(mkFile(randBytes(8)),{keyMode:'password',password:TEST_PWD,cipher:'gcm',chunkSize:1023,...ARGON})));
  await add('above-maximum chunk size rejected by writer', async()=> expectReject(()=>encryptToBytes(mkFile(randBytes(8)),{keyMode:'password',password:TEST_PWD,cipher:'gcm',chunkSize:134217729,...ARGON})));

  return { userAgent:navigator.userAgent, secureContext:isSecureContext, results:out };
});

const version = browser.version();
const passed = result.results.filter(x=>x.ok).length;
const failed = result.results.length - passed;
const lines = [
  'FENC Browser Matrix Validation',
  `Engine: ${browserName}`,
  `Browser version: ${version}`,
  `User-Agent: ${result.userAgent}`,
  `Secure context: ${result.secureContext}`,
  `Artifact: ${path.basename(artifactPath)}`,
  `Result: ${passed}/${result.results.length} passed`,
  '',
  ...result.results.map((x,i)=>`${String(i+1).padStart(2,'0')}. ${x.ok?'PASS':'FAIL'} | ${x.name} | ${x.ms.toFixed(1)} ms${x.detail?` | ${x.detail}`:''}`),
];
if (pageErrors.length) lines.push('', 'Page errors:', ...pageErrors.map(x=>`- ${x}`));
const report = lines.join('\n')+'\n';
const reportPath = `FENC_Browser_${browserName}_Report.txt`;
fs.writeFileSync(reportPath, report);
console.log(report);
await browser.close();
await new Promise(resolve=>server.close(resolve));
if (failed || pageErrors.length) process.exitCode = 1;
