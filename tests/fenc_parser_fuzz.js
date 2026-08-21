#!/usr/bin/env node
'use strict';

/**
 * FENC parser/decryption mutation fuzz harness.
 *
 * This is a deterministic negative-testing campaign over the exact published
 * single-file artifact. It is NOT a proof of security and is not intended to
 * replace a coverage-guided native fuzzer. The goal is to exercise parser,
 * structural-validation, length-handling, and AEAD-rejection paths with a
 * reproducible corpus of malformed containers.
 *
 * Tested with Node.js 22.16.0.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const cryptoNode = require('crypto');

const htmlPath = process.argv[2] || path.join(__dirname, '..', 'index.html');
const requestedSeed = process.argv[3] ? Number(process.argv[3]) >>> 0 : 0xF3E0C123;
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
vm.runInThisContext(scripts[2], { filename: 'embedded-noblex.js' });
vm.runInThisContext(scripts[0], { filename: 'embedded-fenc-core.js' });
if (!globalThis.FENC) throw new Error('FENC core did not initialize');
const FENC = globalThis.FENC;

function memWriter() {
  const parts = [];
  return {
    kind: 'mem',
    write: c => parts.push(c instanceof Uint8Array ? c : new Uint8Array(c)),
    finish: async () => ({ bytes: collect() }),
    _collect: collect,
  };
  function collect() {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }
}
function eq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function mkFile(bytes, name='fuzz-seed.bin') {
  return new File([bytes], name, { type: 'application/octet-stream' });
}
async function decryptToBytes(bytes, opts) {
  const w = memWriter();
  await FENC.decryptFile(new Blob([bytes]), opts, null, w);
  return w._collect();
}

let rngState = requestedSeed || 1;
function rng32() {
  let x = rngState >>> 0;
  x ^= (x << 13) >>> 0;
  x ^= x >>> 17;
  x ^= (x << 5) >>> 0;
  rngState = x >>> 0;
  return rngState;
}
function rnd(max) { return max <= 0 ? 0 : rng32() % max; }
function rndByte() { return rng32() & 255; }
function randomBytes(n) {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = rndByte();
  return b;
}

async function isRejected(bytes, opts) {
  try {
    await decryptToBytes(bytes, opts);
    return false;
  } catch (_) {
    return true;
  }
}

async function main() {
  const plaintext = randomBytes(9000);
  const w = memWriter();
  const ret = await FENC.encryptFile(
    mkFile(plaintext),
    { keyMode:'shamir', shamirN:5, shamirK:3, cipher:'xchacha', chunkSize:4096 },
    null,
    w
  );
  const baseline = w._collect();
  const shares = ret.shares.slice(0, 3).map(p => {
    const s = FENC.shareFromPEM(p);
    return { x:s.x, y:s.y };
  });
  const opts = { shares };

  const roundTrip = await decryptToBytes(baseline, opts);
  if (!eq(roundTrip, plaintext)) throw new Error('Baseline round trip failed before fuzzing');

  const campaigns = [];
  const failures = [];

  async function runCampaign(name, count, makeCase) {
    let rejected = 0, accepted = 0;
    const start = performance.now();
    for (let i = 0; i < count; i++) {
      const candidate = makeCase(i);
      const ok = await isRejected(candidate, opts);
      if (ok) rejected++;
      else {
        accepted++;
        if (failures.length < 20) failures.push({ campaign:name, case:i, size:candidate.length });
      }
    }
    const ms = performance.now() - start;
    campaigns.push({ name, count, rejected, accepted, ms });
  }

  await runCampaign('single-byte mutation', 5000, () => {
    const t = baseline.slice();
    const pos = rnd(t.length);
    let mask = rndByte();
    if (mask === 0) mask = 1;
    t[pos] ^= mask;
    return t;
  });

  await runCampaign('truncation', 1000, () => {
    const newLen = rnd(baseline.length);
    return baseline.slice(0, newLen);
  });

  await runCampaign('trailing-byte extension', 1000, () => {
    const extraLen = 1 + rnd(32);
    const t = new Uint8Array(baseline.length + extraLen);
    t.set(baseline);
    t.set(randomBytes(extraLen), baseline.length);
    return t;
  });

  await runCampaign('arbitrary random blob', 2000, () => randomBytes(rnd(513)));

  await runCampaign('FENC-looking malformed structure', 1000, () => {
    const len = 12 + rnd(500);
    const t = randomBytes(len);
    t.set([0x46,0x45,0x4e,0x43], 0);
    t[4] = rnd(4) === 0 ? 3 : rndByte();
    t[5] = rndByte();
    t[6] = rndByte();
    t[7] = rndByte();
    return t;
  });

  const total = campaigns.reduce((a,c)=>a+c.count,0);
  const rejected = campaigns.reduce((a,c)=>a+c.rejected,0);
  const accepted = campaigns.reduce((a,c)=>a+c.accepted,0);

  console.log('FENC Parser/Mutation Fuzz Report');
  console.log(`Node: ${process.version}`);
  console.log(`Artifact: ${path.basename(htmlPath)}`);
  console.log(`SHA-256: ${artifactSha256}`);
  console.log(`Seed: 0x${requestedSeed.toString(16).padStart(8,'0')}`);
  console.log(`Baseline bytes: ${baseline.length}`);
  console.log('Baseline round trip: PASS');
  console.log('');
  for (const c of campaigns) {
    console.log(`${c.name}: ${c.rejected}/${c.count} rejected, ${c.accepted} unexpected accepts (${c.ms.toFixed(1)} ms)`);
  }
  console.log('');
  console.log(`Total mutated/malformed cases: ${total}`);
  console.log(`Rejected as expected: ${rejected}/${total}`);
  console.log(`Unexpected accepts: ${accepted}`);
  if (failures.length) {
    console.log('First unexpected accepts:');
    for (const f of failures) console.log(`- ${f.campaign} case=${f.case} size=${f.size}`);
  }
  console.log('Scope note: mutation fuzzing is negative testing, not formal verification or an independent security audit.');

  process.exitCode = accepted === 0 ? 0 : 1;
}

main().catch(e => {
  console.error(e && e.stack ? e.stack : e);
  process.exitCode = 1;
});
