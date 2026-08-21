#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const cryptoNode = require('crypto');

const htmlPath = process.argv[2] || path.join(__dirname, 'FENC_Experimental_Prototype_Final.html');
const iterations = Number(process.argv[3] || 10000);
if (!fs.existsSync(htmlPath)) throw new Error(`Missing artifact: ${htmlPath}`);
if (!Number.isInteger(iterations) || iterations < 1) throw new Error('iterations must be a positive integer');

const htmlBytes = fs.readFileSync(htmlPath);
const html = htmlBytes.toString('utf8');
const sha256 = cryptoNode.createHash('sha256').update(htmlBytes).digest('hex');
function scriptBodies(s) { const out=[]; const re=/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi; let m; while((m=re.exec(s))) out.push(m[1]); return out; }
const scripts = scriptBodies(html);
if (scripts.length < 3) throw new Error(`Expected >=3 inline scripts, found ${scripts.length}`);
vm.runInThisContext(scripts[2], { filename:'embedded-noblex.js' });
vm.runInThisContext(scripts[0], { filename:'embedded-fenc-core.js' });
if (!globalThis.FENC) throw new Error('FENC core did not initialize');
const FENC = globalThis.FENC;

function randBytes(n){ return new Uint8Array(crypto.getRandomValues(new Uint8Array(n))); }
function mkFile(bytes,name='fuzz.bin'){ return new File([bytes],name,{type:'application/octet-stream'}); }
function memWriter(){
  const parts=[]; return {kind:'mem', write:c=>parts.push(c instanceof Uint8Array?c:new Uint8Array(c)), finish:async()=>({bytes:collect()}), _collect:collect};
  function collect(){ let n=0; for(const p of parts)n+=p.length; const o=new Uint8Array(n); let off=0; for(const p of parts){o.set(p,off);off+=p.length;} return o; }
}
async function encryptShamir(data,cipher='xchacha',chunkSize=1024){ const w=memWriter(); const ret=await FENC.encryptFile(mkFile(data),{keyMode:'shamir',shamirN:5,shamirK:3,cipher,chunkSize},null,w); const shares=ret.shares.slice(0,3).map(p=>{const s=FENC.shareFromPEM(p); return {x:s.x,y:s.y};}); return {bytes:w._collect(),shares}; }
async function decrypt(bytes,shares){ const w=memWriter(); await FENC.decryptFile(new Blob([bytes]),{shares},null,w); return w._collect(); }
async function rejects(fn){ try { await fn(); return false; } catch { return true; } }
function rng32(){ return cryptoNode.randomBytes(4).readUInt32BE(0); }
function mutate(base){
  const t=base.slice();
  const changes = 1 + (rng32()%4);
  for(let j=0;j<changes;j++){
    const pos = rng32()%t.length;
    const delta = 1 + (rng32()%255);
    t[pos] ^= delta;
  }
  return t;
}

(async()=>{
  const input=randBytes(4097); // multiple chunks + partial final chunk
  const {bytes,shares}=await encryptShamir(input,'xchacha',1024);
  const baseOk = !await rejects(()=>decrypt(bytes,shares));
  if(!baseOk) throw new Error('Baseline container failed to decrypt');

  let rejected=0, accepted=0, exceptions=0;
  const start=performance.now();
  for(let i=0;i<iterations;i++){
    const t=mutate(bytes);
    try {
      const wasRejected=await rejects(()=>decrypt(t,shares));
      if(wasRejected) rejected++; else accepted++;
    } catch(e) { exceptions++; }
  }

  // Structured malformed cases that stress length/truncation/trailing parsing.
  const structured=[];
  for (const cut of [1,2,8,16,32,64]) structured.push(bytes.slice(0,Math.max(0,bytes.length-cut)));
  for (const extra of [1,8,64,1024]) { const t=new Uint8Array(bytes.length+extra); t.set(bytes); crypto.getRandomValues(t.subarray(bytes.length)); structured.push(t); }
  // Header mutations, including parser-valid IDs and extreme chunk-size encodings.
  for (const [pos,val] of [[4,2],[5,0],[6,0],[7,255]]) { const t=bytes.slice(); t[pos]=val; structured.push(t); }
  for (const v of [[0,0,0,0],[0,0,8,0],[255,255,255,255]]) { const t=bytes.slice(); t.set(v,8); structured.push(t); }
  let structuredRejected=0;
  for (const t of structured) if(await rejects(()=>decrypt(t,shares))) structuredRejected++;

  const ms=(performance.now()-start).toFixed(1);
  console.log(`Node: ${process.version}`);
  console.log(`Artifact: ${path.basename(htmlPath)}`);
  console.log(`SHA-256: ${sha256}`);
  console.log(`Baseline bytes: ${bytes.length}`);
  console.log(`Random mutation iterations: ${iterations}`);
  console.log(`Rejected mutated containers: ${rejected}/${iterations}`);
  console.log(`Unexpectedly accepted mutated containers: ${accepted}/${iterations}`);
  console.log(`Harness exceptions: ${exceptions}`);
  console.log(`Structured malformed cases rejected: ${structuredRejected}/${structured.length}`);
  console.log(`Elapsed: ${ms} ms`);
  const ok=accepted===0 && exceptions===0 && structuredRejected===structured.length;
  console.log(`Overall: ${ok?'PASS':'FAIL'}`);
  process.exitCode=ok?0:1;
})().catch(e=>{console.error(e);process.exitCode=1;});
