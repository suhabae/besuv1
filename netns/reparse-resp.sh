#!/usr/bin/env bash
# reparse-resp.sh -- 저장된 raw .resp.timing 에서 '진짜 responder'만 골라
#   respAKE(T6a-T5) 통계를 재계산한다 (재측정 불필요).
# 핵심: 응답자 로그에는 Node2가 우연히 initiator가 된 줄(TCP=숫자)이 섞일 수 있음.
#   진짜 responder 줄만 = TCP(T1-T0)=n/a. 이 줄만 사용한다.
#   결과 CSV(run,phase,respAKE_ms) + steady 요약 출력.
#   usage: bash reparse-resp.sh <warmup=15> <measure=100> results/xwing2-rtt50.resp.timing [...]
set -u
W="${1:-15}"; M="${2:-100}"; shift 2
python3 - "$W" "$M" "$@" <<'PY'
import sys,re,math,csv as C
W=int(sys.argv[1]); M=int(sys.argv[2]); files=sys.argv[3:]
ts=re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)')
rx=re.compile(r'respAKE\(T6a-T5\)=([\d.]+)')
def stat(v):
    s=sorted(v); n=len(s)
    if not n: return None
    mean=sum(s)/n; med=s[n//2] if n%2 else (s[n//2-1]+s[n//2])/2
    std=math.sqrt(sum((x-mean)**2 for x in s)/n)
    P=lambda p:s[min(n-1,math.ceil(p*n)-1)]
    return n,mean,med,std,s[0],s[-1],P(.9),P(.95)
for f in files:
    rows=[]; skipped_init=0
    for ln in open(f,encoding='utf-8',errors='ignore'):
        if 'peerTotal(T8-T0)=' not in ln: continue
        if 'TCP(T1-T0)=n/a' not in ln:      # Node2가 initiator였던 줄
            skipped_init+=1; continue
        m=rx.search(ln); t=ts.search(ln)
        if m and t: rows.append((t.group(1),float(m.group(1))/1000))
    rows.sort(key=lambda r:r[0])
    out=f.rsplit('.',1)[0]+'.respAKE.csv'
    with open(out,'w',newline='') as fh:
        w=C.writer(fh); w.writerow(['run','phase','ts','respAKE_ms'])
        for i,(t,v) in enumerate(rows):
            ph='warmup' if i<W else ('steady' if i<W+M else 'extra')
            w.writerow([i+1,ph,t,v])
    steady=[v for i,(_,v) in enumerate(rows) if W<=i<W+M]
    r=stat(steady)
    print(f"\n{f}")
    print(f"  진짜 responder={len(rows)}  (initiator혼입 제거={skipped_init})  CSV->{out}")
    if r:
        print(f"  [respAKE steady N={r[0]}] mean={r[1]:.2f} median={r[2]:.2f} std={r[3]:.2f} min={r[4]:.2f} max={r[5]:.2f} p90={r[6]:.2f} p95={r[7]:.2f} ms")
PY
