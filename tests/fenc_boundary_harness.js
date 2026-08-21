#!/usr/bin/env node
'use strict';

/**
 * FENC boundary/edge-case validation harness.
 * Complements tests/fenc_regression_harness.js without changing the frozen
 * application artifact. Tested with Node.js 22.16.0.
 */
const fs=require('fs'), path=require('path'), vm=require('vm'), cryptoNode=require('crypto');
const htmlPath=process.argv[2]||path.join(__dirname,'..','index.html');
if(!fs.existsSync(htmlPath)){console.error(`Missing artifact: ${htmlPath}`);process.exit(2);}
const htmlBytes=fs.readFileSync(htmlPath), html=htmlBytes.toString('utf8');
const sha=cryptoNode.createHash('sha256').update(htmlBytes).digest('hex');
function scripts(s){const o=[];const re=/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi;let m;while((m=re.exec(s)))o.push(m[1]);return o;}
const ss=scripts(html); if(ss.length<3) throw new Error(`Expected >=3 inline scripts, found ${ss.length}`);
vm.runInThisContext(ss[2],{filename:'embedded-noblex.js'}); vm.runInThisContext(ss[0],{filename:'embedded-fenc-core.js'});
const F=globalThis.FENC; if(!F) throw new Error('FENC core did not initialize');
function rand(n){return new Uint8Array(crypto.getRandomValues(new Uint8Array(n)));}
function file(b,n='edge.bin'){return new File([b],n,{type:'application/octet-stream'});}
function writer(){const a=[];return{kind:'mem',write:c=>a.push(c instanceof Uint8Array?c:new Uint8Array(c)),finish:async()=>({bytes:collect()}),collect};function collect(){let n=0;for(const p of a)n+=p.length;const o=new Uint8Array(n);let k=0;for(const p of a){o.set(p,k);k+=p.length;}return o;}}
function eq(a,b){if(a.length!==b.length)return false;for(let i=0;i<a.length;i++)if(a[i]!==b[i])return false;return true;}
async function reject(fn){try{await fn();return false;}catch{return true;}}
async function shamirRoundTrip(data,chunkSize){const w=writer();const r=await F.encryptFile(file(data),{keyMode:'shamir',shamirN:3,shamirK:2,cipher:'xchacha',chunkSize},null,w);const shares=r.shares.slice(0,2).map(p=>{const s=F.shareFromPEM(p);return{x:s.x,y:s.y};});const dw=writer();await F.decryptFile(new Blob([w.collect()]),{shares},null,dw);return {ok:eq(dw.collect(),data),bytes:w.collect(),shares};}
const tests=[]; const add=(name,fn)=>tests.push({name,fn});
add('empty-file round trip at 1 KiB chunk size',async()=> (await shamirRoundTrip(new Uint8Array(0),1024)).ok);
add('minimum 1 KiB chunk size round trip across multiple chunks',async()=> (await shamirRoundTrip(rand(2049),1024)).ok);
add('maximum parser-supported 128 MiB chunk-size value round trip',async()=> (await shamirRoundTrip(rand(3),134217728)).ok);
add('reader rejects chunk-size header above 128 MiB',async()=>{const r=await shamirRoundTrip(rand(3),4096);const t=r.bytes.slice();t.set([0x08,0x00,0x00,0x01],8);const dw=writer();return reject(()=>F.decryptFile(new Blob([t]),{shares:r.shares},null,dw));});
add('writer rejects chunk size below 1 KiB',async()=>{const w=writer();return reject(()=>F.encryptFile(file(rand(3)),{keyMode:'shamir',shamirN:3,shamirK:2,cipher:'gcm',chunkSize:1023},null,w));});
(async()=>{console.log('FENC Boundary / Edge-Case Validation Report');console.log(`Node: ${process.version}`);console.log(`Artifact: ${path.basename(htmlPath)}`);console.log(`SHA-256: ${sha}`);let pass=0;for(let i=0;i<tests.length;i++){let ok=false,e='';const st=performance.now();try{ok=await tests[i].fn();}catch(err){e=String(err);}const ms=(performance.now()-st).toFixed(1);if(ok){pass++;console.log(`PASS ${i+1}/${tests.length}  ${tests[i].name}  (${ms} ms)`);}else console.log(`FAIL ${i+1}/${tests.length}  ${tests[i].name}  (${ms} ms)${e?' — '+e:''}`);}console.log(`Boundary / edge-case checks: ${pass}/${tests.length} passed`);process.exitCode=pass===tests.length?0:1;})().catch(e=>{console.error(e);process.exitCode=1;});
