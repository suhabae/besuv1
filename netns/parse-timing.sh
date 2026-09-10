#!/usr/bin/env bash
# parse-timing.sh <warmup> <csvout> <log1> [log2 ...]
# Parses Besu "Handshake timing" lines -> per-sample CSV + steady summary.
# Units: log is microseconds; output ms.
# 환경변수 TARGET_N: 지정하면 steady를 정확히 그 개수로 자름(논문용 표본 통일). 부족하면 경고.
set -u
WARMUP="$1"; CSV="$2"; shift 2
python3 - "$WARMUP" "$CSV" "$@" <<'PY'
import sys, re, math, os, csv as csvmod
warmup=int(sys.argv[1]); csvout=sys.argv[2]; logs=sys.argv[3:]
target=int(os.environ.get('TARGET_N','0') or 0)
rx=re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+).*?'
              r'TCP\(T1-T0\)=(?P<setup>[\d.]+).*?AuthAckRTT\(T5-T2\)=(?P<rtt>[\d.]+).*?'
              r'(?:keyReady\(T6a-T1\)=(?P<key>[\d.]+).*?)?'
              r'(?:respAKE\(T6a-T5\)=(?P<resp>[\d.]+).*?)?'
              r'crypto\(T6-T1\)=(?P<hs>[\d.]+).*?helloAuth\(T7-T1\)=(?P<hello>[\d.]+).*?'
              r'peer\(T8-T1\)=(?P<peer>[\d.]+).*?peerTotal\(T8-T0\)=(?P<total>[\d.]+)'
              r'(?:.*?prep\(Tb-Ta\)=(?P<prep>[\d.]+))?(?:.*?pureTCP\(T1-Tb\)=(?P<ptcp>[\d.]+))?')
def f(m,k):
    v=m.group(k); return float(v)/1000 if v is not None else None
rows=[]
for lp in logs:
    try:
        for line in open(lp, encoding='utf-8', errors='ignore'):
            m=rx.search(line)
            if m:
                rows.append({'ts':m.group('ts'),
                    'setup':f(m,'setup'),'rtt':f(m,'rtt'),'key':f(m,'key'),'resp':f(m,'resp'),'hs':f(m,'hs'),
                    'hello':f(m,'hello'),'peer':f(m,'peer'),'total':f(m,'total'),
                    'prep':f(m,'prep'),'ptcp':f(m,'ptcp')})
    except FileNotFoundError:
        print("missing:", lp)
rows.sort(key=lambda r:r['ts'])
n=len(rows)
if n==0:
    print("no timing lines found"); sys.exit()
steady=rows[warmup:]
if target>0:
    if len(steady) < target:
        print(f"⚠⚠ WARNING: steady 표본 {len(steady)}개 < TARGET_N {target}개 → N 부족! 이 조건은 버퍼↑ 후 재측정 필요")
    else:
        steady=steady[:target]
with open(csvout,'w',newline='') as fh:
    w=csvmod.writer(fh)
    w.writerow(['run','phase','ts','setup','prep','pureTcp','authAckRtt','keyReady','respAKE','hs2secrets','helloAuth','peer','peerTotal'])
    steady_ids=set(id(r) for r in steady)
    for i,r in enumerate(rows):
        if i<warmup: phase='cold' if i==0 else 'warmup'
        elif id(r) in steady_ids: phase='steady'
        else: phase='excess'   # 버퍼 초과분(집계 제외)
        w.writerow([i+1,phase,r['ts'],r['setup'],r['prep'],r['ptcp'],r['rtt'],r['key'],r['resp'],r['hs'],r['hello'],r['peer'],r['total']])
print(f"per-sample rows: {n}  (steady={len(steady)}, CSV -> {csvout})")
def stat(v):
    s=sorted(x for x in v if x is not None); c=len(s)
    if c==0: return None
    mean=sum(s)/c
    med=s[c//2] if c%2 else (s[c//2-1]+s[c//2])/2
    std=math.sqrt(sum((x-mean)**2 for x in s)/c)
    P=lambda p:s[min(c-1,math.ceil(p*c)-1)]
    return mean,med,std,s[0],s[-1],P(0.9),P(0.95)
print(f"\n=== steady summary (N={len(steady)}, ms) ===")
print(f"{'metric':<20}{'mean':>8}{'median':>8}{'std':>7}{'min':>8}{'max':>8}{'p90':>8}{'p95':>8}")
for name,k in [('setup(T1-T0)','setup'),('  prep(Tb-Ta)','prep'),('  pureTCP(T1-Tb)','ptcp'),
               ('AuthAckRTT(T5-T2)','rtt'),('keyReady(T6a-T1)','key'),('respAKE(T6a-T5)','resp'),('hs2secrets(T6-T1)','hs'),
               ('peer(T8-T1)','peer'),('peerTotal(T8-T0)','total')]:
    r=stat([x[k] for x in steady])
    if r: print(f"{name:<20}{r[0]:>8.2f}{r[1]:>8.2f}{r[2]:>7.2f}{r[3]:>8.2f}{r[4]:>8.2f}{r[5]:>8.2f}{r[6]:>8.2f}")
print("\nsetup(T1-T0)=connect→active(=prep+실TCP+init). prep=firstMessage 암호. pureTCP=prep후~active.")
PY
