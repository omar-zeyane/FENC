#!/usr/bin/env node
'use strict';

/**
 * FENC reproducibility harness.
 * Reads the published single-file index.html, extracts the embedded Noble bundle
 * and FENC crypto core verbatim, and executes regression/security checks under Node.js.
 * Tested with Node.js 22.16.0.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const cryptoNode = require('crypto');

const htmlPath = process.argv[2] || path.join(__dirname, '..', 'index.html');
if (!fs.existsSync(htmlPath)) {
  console.error(`Missing artifact: ${htmlPath}`);
  process.exit(2);
}
const htmlBytes = fs.readFileSync(htmlPath);
const html = htmlBytes.toString('utf8');
const artifactSha256 = cryptoNode.createHash('sha256').update(htmlBytes).digest('hex');

function scriptBodies(s) {
  const out = [];
  const re = /<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(s))) out.push(m[1]);
  return out;
}
const scripts = scriptBodies(html);
if (scripts.length < 3) throw new Error(`Expected >=3 inline scripts, found ${scripts.length}`);

// Script 2 is the bundled NobleX implementation; script 0 is FENC crypto-core.
vm.runInThisContext(scripts[2], { filename: 'embedded-noblex.js' });
vm.runInThisContext(scripts[0], { filename: 'embedded-fenc-core.js' });
if (!globalThis.FENC) throw new Error('FENC core did not initialize');
const FENC = globalThis.FENC;

const TEST_PWD = 'Harness-Pwd-9f3K!';
const CHUNK = 4096;
const ARGON = { kdf:'argon2id', argonMem:19456, argonTime:2, argonPar:1 };

function randBytes(n) { return new Uint8Array(crypto.getRandomValues(new Uint8Array(n))); }
function mkFile(bytes, name='test.bin') { return new File([bytes], name, {type:'application/octet-stream'}); }
function eq(a,b) { if (a.length !== b.length) return false; for (let i=0;i<a.length;i++) if (a[i]!==b[i]) return false; return true; }
function memWriter(){
  const parts=[];
  return {
    kind:'mem',
    write:c=>parts.push(c instanceof Uint8Array ? c : new Uint8Array(c)),
    finish:async()=>({bytes:collect()}),
    _collect:collect,
  };
  function collect(){
    let n=0; for(const p of parts)n+=p.length;
    const out=new Uint8Array(n); let o=0;
    for(const p of parts){ out.set(p,o); o+=p.length; }
    return out;
  }
}
async function encryptToBytes(file, opts){ const w=memWriter(); const ret=await FENC.encryptFile(file,opts,null,w); return {bytes:w._collect(), ret}; }
async function decryptToBytes(bytes, opts){ const w=memWriter(); await FENC.decryptFile(new Blob([bytes]),opts,null,w); return w._collect(); }
async function expectReject(fn){ try { await fn(); return false; } catch { return true; } }
function u32be(a,o){ return ((a[o]<<24)>>>0)+(a[o+1]<<16)+(a[o+2]<<8)+a[o+3]; }

function passwordArgonLayout(bytes){
  // Header 12 bytes; Argon key block = 1 + 16 + 4 + 4 + 1 = 26 bytes.
  const metaOff=38;
  const mLen=u32be(bytes, metaOff+12);
  const chunk0=metaOff+16+mLen;
  const cipherId=bytes[6];
  const prefix = cipherId===2 ? 28 : cipherId===3 ? 40 : 16;
  function recordAt(off){ const clen=u32be(bytes,off+prefix-4); return {off,len:prefix+clen}; }
  return {metaOff,mLen,chunk0,prefix,recordAt};
}

const regression=[];
function reg(name, fn){ regression.push({name,fn}); }

for (const cipher of ['gcm','chacha','xchacha','cascade']) {
  reg(`${cipher} round trip`, async()=>{
    const data=randBytes(9000);
    const {bytes}=await encryptToBytes(mkFile(data), {keyMode:'password',password:TEST_PWD,cipher,chunkSize:CHUNK,...ARGON});
    return eq(await decryptToBytes(bytes,{keyMode:'password',password:TEST_PWD}),data);
  });
}
reg('valid Algorithm-ID substitution rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  const t=bytes.slice(); t[6]=0; return expectReject(()=>decryptToBytes(t,{keyMode:'password',password:TEST_PWD}));
});
reg('valid chunk-size substitution rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  const t=bytes.slice(); t.set([0,0,32,0],8); return expectReject(()=>decryptToBytes(t,{keyMode:'password',password:TEST_PWD}));
});
reg('valid Key-mode substitution rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  const t=bytes.slice(); t[5]=6; return expectReject(()=>decryptToBytes(t,{shares:[]}));
});
reg('salt mutation rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  const t=bytes.slice(); t[20]^=1; return expectReject(()=>decryptToBytes(t,{keyMode:'password',password:TEST_PWD}));
});
reg('trailing bytes rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'gcm',chunkSize:CHUNK,...ARGON});
  const t=new Uint8Array(bytes.length+1); t.set(bytes); t[t.length-1]=1; return expectReject(()=>decryptToBytes(t,{keyMode:'password',password:TEST_PWD}));
});
reg('truncation rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'gcm',chunkSize:CHUNK,...ARGON});
  return expectReject(()=>decryptToBytes(bytes.slice(0,-8),{keyMode:'password',password:TEST_PWD}));
});
reg('PBKDF2 round trip', async()=>{
  const data=randBytes(900);
  const {bytes}=await encryptToBytes(mkFile(data),{keyMode:'password',password:TEST_PWD,cipher:'gcm',kdf:'pbkdf2',pbkdf2Iters:600000,chunkSize:CHUNK});
  return eq(await decryptToBytes(bytes,{keyMode:'password',password:TEST_PWD}),data);
});
reg('RSA round trip', async()=>{
  const kp=await FENC.generateRSAKeyPair(2048), data=randBytes(700);
  const {bytes}=await encryptToBytes(mkFile(data),{keyMode:'rsa',publicKeyPEM:kp.publicKeyPEM,cipher:'xchacha',chunkSize:CHUNK});
  return eq(await decryptToBytes(bytes,{privateKeyPEM:kp.privateKeyPEM}),data);
});
reg('X25519 round trip', async()=>{
  const kp=FENC.generateECCKeyPair('x25519'), data=randBytes(700);
  const {bytes}=await encryptToBytes(mkFile(data),{keyMode:'ecc',eccPublicKey:kp.publicKeyPEM,cipher:'xchacha',chunkSize:CHUNK});
  return eq(await decryptToBytes(bytes,{eccSecretKey:kp.privateKeyPEM}),data);
});
reg('multi-recipient recovery via RSA', async()=>{
  const rsa=await FENC.generateRSAKeyPair(2048), ecc=FENC.generateECCKeyPair('x25519'), data=randBytes(700);
  const {bytes}=await encryptToBytes(mkFile(data),{keyMode:'multi',recipients:[{type:'rsa',publicKeyPEM:rsa.publicKeyPEM},{type:'ecc',publicKeyPEM:ecc.publicKeyPEM}],cipher:'xchacha',chunkSize:CHUNK});
  return eq(await decryptToBytes(bytes,{privateKeyPEM:rsa.privateKeyPEM}),data);
});
reg('multi-recipient recovery via ECC', async()=>{
  const rsa=await FENC.generateRSAKeyPair(2048), ecc=FENC.generateECCKeyPair('x25519'), data=randBytes(700);
  const {bytes}=await encryptToBytes(mkFile(data),{keyMode:'multi',recipients:[{type:'rsa',publicKeyPEM:rsa.publicKeyPEM},{type:'ecc',publicKeyPEM:ecc.publicKeyPEM}],cipher:'xchacha',chunkSize:CHUNK});
  return eq(await decryptToBytes(bytes,{eccSecretKey:ecc.privateKeyPEM}),data);
});
reg('Shamir-key round trip', async()=>{
  const data=randBytes(700), w=memWriter();
  const ret=await FENC.encryptFile(mkFile(data),{keyMode:'shamir',shamirN:5,shamirK:3,cipher:'xchacha',chunkSize:CHUNK},null,w);
  const shares=ret.shares.slice(0,3).map(p=>{const s=FENC.shareFromPEM(p); return {x:s.x,y:s.y};});
  return eq(await decryptToBytes(w._collect(),{shares}),data);
});
reg('decoy real-password round trip', async()=>{
  const real=randBytes(600), decoy=randBytes(400);
  const {bytes}=await encryptToBytes(mkFile(real,'real.bin'),{keyMode:'decoy',password:'real-X1!',decoyPassword:'decoy-Y2!',decoyFile:mkFile(decoy,'decoy.bin'),cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  return eq(await decryptToBytes(bytes,{password:'real-X1!'}),real);
});
reg('decoy alternate-password round trip', async()=>{
  const real=randBytes(600), decoy=randBytes(400);
  const {bytes}=await encryptToBytes(mkFile(real,'real.bin'),{keyMode:'decoy',password:'real-X1!',decoyPassword:'decoy-Y2!',decoyFile:mkFile(decoy,'decoy.bin'),cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  return eq(await decryptToBytes(bytes,{password:'decoy-Y2!'}),decoy);
});

const targeted=[];
function tgt(name, fn){ targeted.push({name,fn}); }
tgt('valid password-protected round trip', async()=>{
  const data=randBytes(9000); const {bytes}=await encryptToBytes(mkFile(data),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  return eq(await decryptToBytes(bytes,{keyMode:'password',password:TEST_PWD}),data);
});
tgt('wrong password rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  return expectReject(()=>decryptToBytes(bytes,{keyMode:'password',password:'wrong'}));
});
tgt('corrupted encrypted metadata rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  const t=bytes.slice(), L=passwordArgonLayout(t); t[L.metaOff+16]^=1;
  return expectReject(()=>decryptToBytes(t,{keyMode:'password',password:TEST_PWD}));
});
tgt('modified chunk ciphertext rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(9000)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  const t=bytes.slice(), L=passwordArgonLayout(t); t[L.chunk0+L.prefix]^=1;
  return expectReject(()=>decryptToBytes(t,{keyMode:'password',password:TEST_PWD}));
});
tgt('reordered first two chunks rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(9000)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  const L=passwordArgonLayout(bytes), a=L.recordAt(L.chunk0), b=L.recordAt(L.chunk0+a.len);
  const t=new Uint8Array(bytes.length), before=bytes.slice(0,a.off), ra=bytes.slice(a.off,a.off+a.len), rb=bytes.slice(b.off,b.off+b.len), after=bytes.slice(b.off+b.len);
  let o=0; for(const p of [before,rb,ra,after]){t.set(p,o);o+=p.length;}
  return expectReject(()=>decryptToBytes(t,{keyMode:'password',password:TEST_PWD}));
});
tgt('wrong RSA private key rejected', async()=>{
  const a=await FENC.generateRSAKeyPair(2048), b=await FENC.generateRSAKeyPair(2048);
  const {bytes}=await encryptToBytes(mkFile(randBytes(500)),{keyMode:'rsa',publicKeyPEM:a.publicKeyPEM,cipher:'gcm',chunkSize:CHUNK});
  return expectReject(()=>decryptToBytes(bytes,{privateKeyPEM:b.privateKeyPEM}));
});
tgt('modified password-mode salt rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  const t=bytes.slice(); t[20]^=1; return expectReject(()=>decryptToBytes(t,{keyMode:'password',password:TEST_PWD}));
});
tgt('wrong ECDH private key rejected', async()=>{
  const a=FENC.generateECCKeyPair('x25519'), b=FENC.generateECCKeyPair('x25519');
  const {bytes}=await encryptToBytes(mkFile(randBytes(500)),{keyMode:'ecc',eccPublicKey:a.publicKeyPEM,cipher:'gcm',chunkSize:CHUNK});
  return expectReject(()=>decryptToBytes(bytes,{eccSecretKey:b.privateKeyPEM}));
});
tgt('valid Algorithm-ID substitution 2->0 rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  const t=bytes.slice(); t[6]=0; return expectReject(()=>decryptToBytes(t,{keyMode:'password',password:TEST_PWD}));
});
tgt('valid chunk-size substitution 4096->8192 rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:4096,...ARGON});
  const t=bytes.slice(); t.set([0,0,32,0],8); return expectReject(()=>decryptToBytes(t,{keyMode:'password',password:TEST_PWD}));
});
tgt('valid Key-mode substitution Password->Shamir rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  const t=bytes.slice(); t[5]=6; return expectReject(()=>decryptToBytes(t,{shares:[]}));
});
tgt('truncated container rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  return expectReject(()=>decryptToBytes(bytes.slice(0,-8),{keyMode:'password',password:TEST_PWD}));
});
tgt('trailing bytes rejected', async()=>{
  const {bytes}=await encryptToBytes(mkFile(randBytes(900)),{keyMode:'password',password:TEST_PWD,cipher:'xchacha',chunkSize:CHUNK,...ARGON});
  const t=new Uint8Array(bytes.length+1); t.set(bytes); t[t.length-1]=1; return expectReject(()=>decryptToBytes(t,{keyMode:'password',password:TEST_PWD}));
});

const extra=[{name:'writer rejects chunk counts beyond MAX_CHUNKS before processing',fn:async()=>{
  const fake={size:(16777216+1)*1024,name:'huge.bin',type:'application/octet-stream',slice(){throw new Error('slice should not be reached');}};
  const w=memWriter();
  return expectReject(()=>FENC.encryptFile(fake,{keyMode:'shamir',shamirN:3,shamirK:2,cipher:'gcm',chunkSize:1024},null,w));
}}];

async function runSet(label, tests){
  let passed=0;
  console.log(`\n${label} (${tests.length} checks)`);
  for(let i=0;i<tests.length;i++){
    const t=tests[i], start=performance.now(); let ok=false, err='';
    try { ok=await t.fn(); } catch(e){ err=e && e.stack ? e.stack.split('\n')[0] : String(e); }
    const ms=(performance.now()-start).toFixed(1);
    if(ok){ passed++; console.log(`PASS ${String(i+1).padStart(2,'0')}/${tests.length}  ${t.name}  (${ms} ms)`); }
    else console.log(`FAIL ${String(i+1).padStart(2,'0')}/${tests.length}  ${t.name}  (${ms} ms)${err?' — '+err:''}`);
  }
  console.log(`${label}: ${passed}/${tests.length} passed`);
  return {passed,total:tests.length};
}

(async()=>{
  console.log(`Node: ${process.version}`);
  console.log(`Artifact: ${path.basename(htmlPath)}`);
  console.log(`SHA-256: ${artifactSha256}`);
  const a=await runSet('Regression',regression);
  const b=await runSet('Targeted security subset',targeted);
  const c=await runSet('Counter-limit guard',extra);
  const ok=a.passed===a.total && b.passed===b.total && c.passed===c.total;
  console.log(`\nOverall: ${a.passed+b.passed+c.passed}/${a.total+b.total+c.total} passed`);
  process.exitCode=ok?0:1;
})().catch(e=>{console.error(e);process.exitCode=1;});
