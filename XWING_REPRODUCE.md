# PQ-RLPx (X-Wing) 성능 재현 가이드

이 브랜치(`measure/ecies-tcp`)를 **다른 노트북에서 clone → 그대로 성능분석**하기 위한 절차. 기존 Besu 대비 X-Wing RLPx 핸드셰이크(3-메시지, Init 제거)를 WSL2 netns+netem 통제 환경에서 ECIES와 비교 측정한다.

## 0. 준비물 (한 번만)
- Windows + WSL2 Ubuntu, `sudo apt install -y iproute2 iputils-ping curl python3 unzip zip`
- 리눅스 JDK 25: `sudo apt install -y openjdk-25-jdk` → `export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64`
- (회사망이 HTTPS 프록시면 sdkman 대신 apt 사용)

## 1. 코드 clone & 빌드 (Windows PowerShell)
```
git clone -b measure/ecies-tcp https://github.com/suhabae/besuv1.git
cd besuv1
.\gradlew installDist
```
빌드 후 리눅스 런처의 실험옵션 제거(JDK25에서 거부됨):
```
sed -i 's/ "-XX:+UseCompactObjectHeaders"//' build/install/besu/bin/besu
```

## 2. 노드 개인키 배치 (git에 없음 — 수동 복사)
보안상 개인키 4개는 git에서 제외되어 있다. **기존 노트북에서 아래 4개 파일을 새 노트북의 같은 경로로 복사**(USB/보안채널):
```
QBFT-Network/Node-1/data/key
QBFT-Network/Node-1/data/xwing-key
QBFT-Network/Node-2/data/key
QBFT-Network/Node-2/data/xwing-key
```
git에 포함된 genesis / xwing-addressbook / *.pub / static-nodes.json 은 이 키들과 정확히 대응하므로, 복사만 하면 동일 네트워크가 된다.
(주소록 형식: 한 줄 `nodeId(hex)=xwing공개키(hex)`. 키를 새로 만들면 이 주소록·genesis도 다시 맞춰야 하므로, 동일 재현에는 위 복사를 권장.)

## 3. 네트워크 네임스페이스 생성 (WSL, 재부팅마다 1회)
```
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64
cd /mnt/c/Users/<you>/.../besuv1/netns
sudo bash setup-netns.sh up          # ns1(10.0.0.1) <-> veth <-> ns2(10.0.0.2)
```

## 4. 노드 2개 실행 (창 A, B)
```
# 창 A (node1),  proto = xwing | ecies
sudo ip netns exec ns1 env JAVA_HOME="$JAVA_HOME" bash run-node.sh node1 xwing ~/node1.log
# 창 B (node2)
sudo ip netns exec ns2 env JAVA_HOME="$JAVA_HOME" bash run-node.sh node2 xwing ~/node2.log
```
run-node.sh 가 자동 설정: `-Dbesu.rlpx.measurement=true`, xwing이면 `-Dbesu.rlpx.xwing=true` + keyFile/addressBook.

## 5. RTT 스윕 측정 (창 C)
```
sudo bash sweep.sh xwing2 "$HOME/node1.log" 100 15 1.0 "0 10 30 50"
# ECIES: 노드를 ecies로 재시작 후
sudo bash sweep.sh ecies2 "$HOME/node1.log" 100 15 1.0 "0 10 30 50"
```
- 인자: label, 개시자로그, MEASURE(=100), WARMUP(=15 폐기), SETTLE(초), "RTT 목록(ms)"
- netem: 각 방향 delay=RTT/2. 결과는 `netns/results/<label>-rtt<RTT>.csv` (+ `.timing`, 응답자 `.resp.timing`).

## 6. 지표 (단위 ms)
- prep(Tb-Ta): 개시자 firstMessage 암호  · pureTCP(T1-Tb): 실제 TCP(≈1×RTT)
- keyReady(T6a-T1): 개시자 키 준비+상대 인증(개시자 시계)
- respAKE(T6a-T5): 응답자 시계, X-Wing=tag_I 검증(상호 확인 완료), ECIES=응답자 처리 완료
- peerTotal(T8-T0): Besu 전체 peer 확립. hsFail: 재시도(성공분만 통계).
- 서로 다른 JVM 시계는 직접 빼지 않음. setup(T1-T0)는 순수 TCP 아님(prep 포함).

## 7. 참고
- 재부팅하면 netns가 사라짐 → 3번만 다시. 빌드/키/데이터는 유지.
- 측정 상세·결과·해석: 저장소 루트의 PQ-RLPx_*.docx, XWING_CHANGELOG.md 참고.
- push는 fork(myfork)에만. 공식 besu(origin) 금지.
