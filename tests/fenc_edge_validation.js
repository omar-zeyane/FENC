#!/usr/bin/env node
'use strict';
const fs=require('fs'), path=require('path'), vm=require('vm'), cryptoNode=require('crypto');
const htmlPath=process.argv[2]||path.join(__dirname,'FENC_Experimental_Prototype_Final.html');
const htmlBytes=fs.readFileSync(htmlPath), html=htmlBytes.toString('utf8');
const sha256=cryptoNode.createHash('sha256').update(htmlBytes).digest('hex');
function scripts(s){const a=[];const re=/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi;let m;while((m=re.exec(s)))a.push(m[1]);return a;}
const ss=scripts(html); vm.runInThisContext(ss[2],{filename:'embedded-noblex.js'}); vm.runInThisContext(ss[0],{filename:'embedded-fenc-core.js'}); const FENC=globalThis.FENC;
function rb(n){return new Uint8Array(crypto.getRandomValues(new Uint8Array(n)));}
function file(b,n='edge.bin'){return new File([b],n,{type:'application/octet-stream'});}
function writer(){const p=[];return{kind:'mem',write:c=>p.push(c instanceof Uint8Array?c:new Uint8Array(c)),finish:async()=>({bytes:collect()}),_collect:collect};function collect(){let n=0;for(const x of p)n+=x.length;const o=new Uint8Array(n);let q=0;for(const x of p){o.set(x,q);q+=x.length;}return o;}}
function eq(a,b){if(a.length!==b.length)return false;for(let i=0;i<a.length;i++)if(a[i]!==b[i])return false;return true;}
async function encShamir(data,cipher='gcm',chunkSize=1024){const w=writer();const ret=await FENC.encryptFile(file(data),{keyMode:'shamir',shamirN:5,shamirK:3,cipher,chunkSize},null,w);const shares=ret.shares.slice(0,3).map(p=>{const s=FENC.shareFromPEM(p);return{x:s.x,y:s.y};});return{bytes:w._collect(),shares};}
async function dec(bytes,shares){const w=writer();await FENC.decryptFile(new Blob([bytes]),{shares},null,w);return w._collect();}
async function reject(fn){try{await fn();return false}catch{return true}}
function u32(a,o){return((a[o]<<24)>>>0)+(a[o+1]<<16)+(a[o+2]<<8)+a[o+3];}
function shamirLayout(bytes,cipher){const metaOff=14;const mLen=u32(bytes,metaOff+12);const chunk0=metaOff+16+mLen;const prefix=cipher==='xchacha'?28:cipher==='cascade'?40:16;function rec(off){const clen=u32(bytes,off+prefix-4);return{off,len:prefix+clen};}return{metaOff,mLen,chunk0,prefix,rec};}
const tests=[]; function t(name,fn){tests.push({name,fn});}
for(const cipher of ['gcm','chacha','xchacha','cascade']) t(`zero-byte ${cipher} round trip`,async()=>{const {bytes,shares}=await encShamir(new Uint8Array(0),cipher,1024);return eq(await dec(bytes,shares),new Uint8Array(0));});
t('minimum chunk size 1 KiB accepted',async()=>{const d=rb(2049),{bytes,shares}=await encShamir(d,'gcm',1024);return eq(await dec(bytes,shares),d);});
t('maximum chunk size 128 MiB accepted',async()=>{const d=rb(2049),{bytes,shares}=await encShamir(d,'gcm',134217728);return eq(await dec(bytes,shares),d);});
t('writer rejects chunk size below 1 KiB',async()=>reject(()=>FENC.encryptFile(file(rb(1)),{keyMode:'shamir',shamirN:3,shamirK:2,cipher:'gcm',chunkSize:1023},null,writer())));
t('writer rejects chunk size above 128 MiB',async()=>reject(()=>FENC.encryptFile(file(rb(1)),{keyMode:'shamir',shamirN:3,shamirK:2,cipher:'gcm',chunkSize:134217729},null,writer())));
t('writer rejects non-integer chunk size',async()=>reject(()=>FENC.encryptFile(file(rb(1)),{keyMode:'shamir',shamirN:3,shamirK:2,cipher:'gcm',chunkSize:4096.5},null,writer())));
for(const cipher of ['gcm','chacha']) t(`${cipher} repeated per-file nonce across chunks is rejected`,async()=>{const {bytes,shares}=await encShamir(rb(2500),cipher,1024);const L=shamirLayout(bytes,cipher),a=L.rec(L.chunk0),b=L.rec(L.chunk0+a.len),m=bytes.slice();m.set(m.slice(a.off,a.off+12),b.off);return reject(()=>dec(m,shares));});
t('XChaCha nonce mutation is rejected',async()=>{const {bytes,shares}=await encShamir(rb(2500),'xchacha',1024);const L=shamirLayout(bytes,'xchacha'),m=bytes.slice();m[L.chunk0]^=1;return reject(()=>dec(m,shares));});
t('reserved-byte substitution is rejected by bound authentication',async()=>{const {bytes,shares}=await encShamir(rb(700),'xchacha',1024);const m=bytes.slice();m[7]=1;return reject(()=>dec(m,shares));});
(async()=>{console.log(`Node: ${process.version}`);console.log(`Artifact: ${path.basename(htmlPath)}`);console.log(`SHA-256: ${sha256}`);let pass=0;for(let i=0;i<tests.length;i++){let ok=false,err='';const st=performance.now();try{ok=await tests[i].fn()}catch(e){err=String(e)}const ms=(performance.now()-st).toFixed(1);if(ok){pass++;console.log(`PASS ${String(i+1).padStart(2,'0')}/${tests.length}  ${tests[i].name} (${ms} ms)`)}else console.log(`FAIL ${String(i+1).padStart(2,'0')}/${tests.length}  ${tests[i].name} (${ms} ms) ${err}`)}console.log(`Overall: ${pass}/${tests.length} passed`);process.exitCode=pass===tests.length?0:1;})().catch(e=>{console.error(e);process.exitCode=1});
