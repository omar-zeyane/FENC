#!/usr/bin/env python3
from pathlib import Path
import re, hashlib, base64, sys

TARGET = Path(sys.argv[1] if len(sys.argv)>1 else 'index.html')
OLD_SHA = '945737b4b799240b84d588affdbbf116d0b354d5b92ee4dddc06af73c34b303a'
NEW_SHA = '2c1e0b679f412a4d8f68aae3a097188b8bae729d43c0773df7069ca511e46de9'

def sha256(p): return hashlib.sha256(p.read_bytes()).hexdigest()
cur = sha256(TARGET)
if cur == NEW_SHA:
    print('index.html already final:', cur)
    raise SystemExit(0)
if cur != OLD_SHA:
    raise SystemExit(f'Unexpected input SHA-256: {cur}')

s = TARGET.read_text(encoding='utf-8')
old = "const BIG_BLOB_LIMIT=1610612736; /* 1.5 ج.بايت: فوقه يجب استخدام الحفظ المتدفّق */\n  const KM_PASSWORD=0"
new = "const BIG_BLOB_LIMIT=1610612736; /* 1.5 ج.بايت: فوقه يجب استخدام الحفظ المتدفّق */\n  const MAX_CHUNKS=16777216; /* حدّ دفاعي أدنى بكثير من مجال عدّاد uint32 ويطابق حدّ القارئ */\n  const KM_PASSWORD=0"
if old not in s: raise SystemExit('constant insertion anchor not found')
s = s.replace(old,new,1)

old = "function checkAbort(sig){ if(sig && sig.aborted) throw abortErr(); }\n  function u64(n)"
new = "function checkAbort(sig){ if(sig && sig.aborted) throw abortErr(); }\n  function checkedTotalChunks(fileSize,chunkSize){\n    const totalChunks=Math.max(1,Math.ceil(fileSize/chunkSize));\n    if(!Number.isSafeInteger(totalChunks)||totalChunks>MAX_CHUNKS)\n      throw new Error('عدد القطع يتجاوز الحد الآمن المدعوم ('+MAX_CHUNKS+')');\n    return totalChunks;\n  }\n  function u64(n)"
if old not in s: raise SystemExit('helper insertion anchor not found')
s = s.replace(old,new,1)

first_end = s.find('</script>')
if first_end < 0: raise SystemExit('first script end not found')
core, rest = s[:first_end], s[first_end:]
core = core.replace('const totalChunks=Math.max(1,Math.ceil(file.size/chunkSize));','const totalChunks=checkedTotalChunks(file.size,chunkSize);')
core = core.replace('meta.totalChunks>16777216','meta.totalChunks>MAX_CHUNKS')
s = core + rest

bodies=[]
for m in re.finditer(r'<script(?:\s[^>]*)?>', s, re.I):
    st=m.end(); en=s.find('</script>',st)
    if en<0: raise SystemExit('unclosed script')
    bodies.append(s[st:en])
hashes=[]
for b in bodies:
    h=base64.b64encode(hashlib.sha256(b.encode('utf-8')).digest()).decode()
    hashes.append("'sha256-%s'" % h)
m=re.search(r"script-src\s+([^;]+);",s)
if not m: raise SystemExit('CSP script-src not found')
s=s[:m.start(1)]+' '.join(hashes)+s[m.end(1):]

TARGET.write_text(s,encoding='utf-8',newline='')
final=sha256(TARGET)
if final != NEW_SHA:
    raise SystemExit(f'Final SHA mismatch: {final}')
print('updated index.html:', final)
