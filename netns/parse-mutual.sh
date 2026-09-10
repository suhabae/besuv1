#!/usr/bin/env bash
# parse-mutual.sh -- 두 노드 모두 Hello 완료(상호 완료, mutual)까지의 시간 계산.
#   fullHandshake = max(wallDone_I, wallDone_R) - wallStart_I   (공유 벽시계 ms, 같은 호스트)
# 전제: measure/mutual-hello 브랜치 빌드로 로그에 role/wallStart/wallDone 이 찍혀 있어야 함.
#   개시자(node1.log): role=INITIATOR wallStart=.. wallDone=..
#   응답자(node2.log): role=RESPONDER wallDone=..  (TCP=n/a 인 진짜 responder만)
# 순차 측정(measure-collect)이라 k번째 개시자 ↔ k번째 응답자로 짝짓는다.
#   usage: bash parse-mutual.sh <node1.log> <node2.log> [warmup=15] [measure=100]
set -u
LOG1="${1:?need node1.log}"; LOG2="${2:?need node2.log}"; W="${3:-15}"; M="${4:-100}"
python3 - "$LOG1" "$LOG2" "$W" "$M" <<'PY'
import sys,re,math
log1,log2,W,M=sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4])
def grab(path, role):
    out=[]
    for ln in open(path,encoding='utf-8',errors='ignore'):
        if 'Handshake timing' not in ln or f'role={role}' not in ln: continue
        if role=='RESPONDER' and 'TCP(T1-T0)=n/a' not in ln: continue   # 진짜 responder만
        ws=re.search(r'wallStart=(\d+)', ln); wd=re.search(r'wallDone=(\d+)', ln)
        ts=re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)', ln)
        if not wd or not ts: continue
        out.append((ts.group(1), int(ws.group(1)) if ws else None, int(wd.group(1))))
    out.sort(key=lambda r:r[0])
    return out
I=grab(log1,'INITIATOR'); R=grab(log2,'RESPONDER')
n=min(len(I),len(R))
print(f"개시자 INITIATOR 줄={len(I)}, 응답자 RESPONDER 줄={len(R)}, 짝지음={n}")
if n < W+M:
    print(f"  ⚠⚠ WARNING: 짝지은 표본 {n}개 < warmup{W}+measure{M}={W+M} → mutual N 부족! 버퍼↑ 후 재측정 필요")
rows=[]
for k in range(n):
    _,sI,dI=I[k]; _,_,dR=R[k]
    if sI is None: continue
    peerTotal=dI-sI            # 개시자 관점(참고, ms 해상도)
    mutual=max(dI,dR)-sI       # 상호 완료
    rows.append((peerTotal,mutual))
steady=rows[W:W+M]
def st(v):
    s=sorted(v); c=len(s)
    if not c: return None
    mean=sum(s)/c; med=s[c//2] if c%2 else (s[c//2-1]+s[c//2])/2
    std=math.sqrt(sum((x-mean)**2 for x in s)/c)
    P=lambda p:s[min(c-1,math.ceil(p*c)-1)]
    return c,mean,med,std,s[0],s[-1],P(.9),P(.95)
for name,idx in [("peerTotal_I(ms)",0),("mutual_bothHello(ms)",1)]:
    r=st([x[idx] for x in steady])
    if r: print(f"  [{name}] N={r[0]} mean={r[1]:.1f} median={r[2]:.1f} std={r[3]:.1f} min={r[4]:.0f} max={r[5]:.0f} p90={r[6]:.0f} p95={r[7]:.0f}")
print("  ※ currentTimeMillis 해상도 ~1ms → RTT10/30/50 신뢰, RTT0은 참고용. median 사용 권장.")
PY
