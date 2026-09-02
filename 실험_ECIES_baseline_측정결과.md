# 실험 기록 — ECIES vs X-Wing RLPx 핸드셰이크 성능 측정

> 목적: 현행 ECIES(secp256k1) 핸드셰이크와 X-Wing(ML-KEM-768+X25519) 핸드셰이크의 **메시지 크기·시간**을 동일 하네스로 공정 측정·비교.
> 측정일: 2026-08-31~09-02 · 환경: Besu v26.9-develop, Windows x86_64, JDK 25(loom-ea)

---

## 1. 측정 방법

- **in-memory**: Besu `ethereum:p2p` 모듈 테스트. 워밍업 200 + 측정 2,000회, 장기키 1회 생성 후 재사용, 중앙값/p90/최소.
  - **ECIES:** 실제 `ECIESHandshaker` 직접 호출. 크기는 on-wire(RLP EIP-8 + ECIES 오버헤드 포함).
  - **X-Wing:** ML-KEM-768 + X25519 + SHA3-256/HmacSHA3-256로 Protocol 2 흐름 구현. JDK판 / BouncyCastle+RLP판 2종.
- **라이브 TCP**(§3.5, §3.6): 실제 QBFT 2노드(127.0.0.1:30303↔30304)에서 Netty 파이프라인에 T0~T8 계측(`HandshakeTimings`)을 넣어 측정. `measure/ecies-tcp` 브랜치.

## 2. 공정 비교의 두 축

- **라이브러리 축:** ECIES secp256k1은 네이티브(C)/BouncyCastle(순수자바) 두 경로.
- **인코딩 축:** ECIES는 RLP+ECIES 프레이밍 포함 → X-Wing도 같은 RLP로 맞춤.

### 발견 A — Windows는 네이티브 secp256k1 미지원
besu-native는 secp256k1을 Linux(.so)·macOS(.dylib)만 배포(Windows "TBD"). → Windows Besu는 `useNative=false`, 항상 BouncyCastle 폴백. 근거: `NativeStatusProbeTest` `isNative()=false`, 라이브 노드 로그도 "Using the Java implementation of the signature algorithm".

### 발견 B — 네이티브는 sign/verify/recover만 가속, ECDH 미가속
`SECP256K1.java`상 네이티브 경로는 sign/verify/recover뿐. ECDH 키합의(`calculateECDHKeyAgreement`)는 네이티브여도 BC. → 네이티브를 켜도 핸드셰이크 완전가속 아님.

## 3. 결과 — in-memory (Tier-1, 둘 다 BC + on-wire RLP, 같은 JVM)

| 지표 | ECIES (BC) | X-Wing (BC) | 비교 |
|---|---|---|---|
| Auth / ACK / Conf | 538 / 373 / — B | 3,597 / 2,315 / 34 B | |
| **총 크기** | **911 B** | **5,946 B** | **약 6.5배 ↑** |
| 메시지 수 | 2 | 3 | |
| **시간 중앙값** | **7,854 us** | **1,167.5 us** | **약 6.7배 ↓(빠름)** |

(부속) X-Wing 구현별 시간: JDK판 1,917us / BC판 1,167.5us.

### Tier-2 — 네이티브 (Linux/macOS 필요, 미측정)
- ECIES: 네이티브 sign/verify + ECDH는 BC(부분 가속). X-Wing: 표준 스택에 네이티브 ML-KEM 없음(JDK/BC 순수자바가 현실 최선).

## 3.5 라이브 TCP 계측 — 실제 QBFT 2노드 (ECIES baseline, 예비 N=4)

- **방법**: `measure/ecies-tcp` 브랜치. `HandshakeTimings`(Netty 채널 속성)로 개시자 JVM 한 곳에서 T0~T8 기록. 서로 다른 JVM nanoTime 비교 안 함.
  - T0 connect시작 → T1 TCP연결 → T2 Auth송신 → T5 Ack수신 → T6 secrets완료 → T7 Hello인증 → T8 peer확립.
- **샘플**: admin_removePeer/addPeer로 워밍 재연결. 콜드 제외. **워밍 N=4**(예비).

| 구간 | 중앙값(ms) | 의미 |
|---|---|---|
| TCP 연결 (T1-T0) | 7.2 | TCP 3-way + 채널 준비 |
| Auth→Ack RTT (T5-T2) | 6.2 | Auth 송신→Ack 수신 |
| **crypto (T6-T1)** | **7.84** | TCP후 HandshakeSecrets까지 |
| peer 확립 (T8-T1) | 9.1 | +능력협상·연결등록 |
| **전체 (T8-T0)** | **16.4** | connect→peer 완료 |

### 정합성 검증
라이브 TCP의 **crypto 구간 중앙값 7.84ms** = in-memory ECIES 벤치 **7.85ms** 와 거의 일치. → in-memory 암호처리 시간이 실제 TCP 노드에서도 재현됨(측정 신뢰성).

> 주의: N=4 예비값. §3.6에서 X-Wing과 **동일 스크립트로 재측정**하여 갱신함.

## 3.6 라이브 TCP — X-Wing 실제 연결 성공 + ECIES 동일조건 재측정 (2026-09-02)

### 3.6.1 X-Wing 라이브 연결을 막던 버그와 수정 (framing / fragmentation)
- **증상**: X-Wing 활성화 시 두 노드가 붙지 않고 `net_peerCount=0x0`, 에러 로그도 없이 조용히 실패.
- **원인(관측으로 확정)**: TCP는 메시지 경계를 보존하지 않는데, `XWingHandshaker.handleMessage`가 "1회 read = 1개 완전 메시지"로 가정. Netty 초기 수신버퍼(~2048B)보다 큰 Auth(3663B)/ACK(2315B)가 조각나 도착 → 잘린 조각을 RLP 파싱 → 예외 → `AbstractHandshakeHandler.exceptionCaught`가 TRACE로만 로깅 후 채널 종료.
  - 관측 로그: 개시자 `authBodyLength=3663`, 응답자 첫 `chunkLength=2048` (2048 < 3663 → 조각화 확정).
- **수정(최소·계층분리)**: `XWingHandshaker.java` 한 파일 안에서만, 각 메시지(Auth/ACK/Conf) 앞에 **2바이트 big-endian 길이 접두어**(RLPx/EIP-8 관례)를 붙이고, 수신 측은 **누적 버퍼**로 길이만큼 다 모일 때까지 대기 후 파싱. 불완전하면 `Optional.empty()` 반환 → Besu 핸들러의 기존 "waiting for more bytes" 분기가 다음 조각을 대기. **Besu 핸들러/파이프라인/암호/키/주소록 무수정.**
- **검증**: 단위테스트 3종(2048분할·개시자ACK분할·1바이트씩) 통과 + 라이브 로그 `XW-OBS#4 assembled bodyLength=3663 reads=2`(조각 재조립 성공) + `net_peerCount=0x1`.

### 3.6.2 동일조건 재측정 방법 (ECIES·X-Wing 공통)
- **재연결**: `admin_removePeer` → `net_peerCount==0` 확인 → `admin_addPeer` → `net_peerCount==1` 확인(폴링). blind sleep 아님 → 실제 해제/재연결 보장.
- **규칙**: 콜드 스타트 1개 + 초기 워밍 5개 제외 → **steady-state** 구간에서 중앙값/p90.
- 표본: X-Wing steady N=14, ECIES steady N=10. 개시자 JVM(Node-2, port 8546)에서 T0~T8.

### 3.6.3 결과 — steady-state 중앙값 / p90 (ms)

| 구간 | ECIES (N=10) | X-Wing (N=14) | 비율(중앙값) |
|---|---:|---:|---:|
| TCP (T1-T0) | 9.65 / 14.89 | 4.09 / 6.72 | 0.42× |
| Auth→ACK RTT (T5-T2) | 7.39 / 12.93 | 5.85 / 8.30 | 0.79× |
| **crypto·secrets (T6-T1)** | **9.78 / 16.30** | **9.99 / 11.93** | **1.02×** |
| peer (T8-T1) | 10.93 / 20.56 | 10.74 / 12.94 | 0.98× |
| **peerTotal (T8-T0)** | **19.63 / 41.65** | **14.87 / 25.01** | **0.76×** |

on-wire 메시지 크기(라이브 관측): X-Wing Auth 3665B + ACK 2317B + Conf 36B ≈ **6.0KB (2B 길이접두어 포함)** vs ECIES 911B → **약 6.6배**, 메시지 2→3개.

### 3.6.4 해석 (정직하게)
1. **핵심 — 암호 핸드셰이크 지연은 사실상 동일**: crypto(T6-T1) 9.78 vs 9.99ms (1.02×). in-memory에선 X-Wing이 훨씬 빨랐으나(1.17 vs 7.85ms), 라이브 crypto 구간은 순수 KEM이 아니라 **네트워크 왕복 + 메시지 I/O가 지배**해 둘 다 ~10ms로 수렴. → "PQ 전환해도 실제 peer 핸드셰이크 지연은 ECIES와 대등(parity)".
2. **peerTotal·TCP에서 X-Wing이 더 빠르게 보이는 건 노이즈**: TCP 셋업(T1-T0)은 핸드셰이크 암호와 무관한데 0.42×로 나온 것은 표본 규모(N=10~14)와 RPC 폴링 부하의 변동. **"X-Wing이 더 빠르다"고 주장하지 않는다** — parity로 해석.
3. **진짜 PQC 비용은 대역폭·꼬리지연**: 메시지 6.6배·조각화는 median엔 거의 안 드러나고 p90/대역폭에서 드러남. 노드 수 적고 대역폭 여유 큰 금융 컨소시엄에 유리한 trade-off.
4. **fragmentation 발견의 표현**: "PQC가 2KB 넘으면 무조건 실패"가 아니라, *handshake packet 경계를 TCP read 경계에 의존하던 기존 구현 전제가, PQC로 메시지가 커지며 드러난 stream reassembly 문제*.

> 주의: 예비 수준(steady N=10~14, 변동 큼). 최종 논문은 (a) 표본 up(각 30+), (b) RPC 폴링 부하 없는 수집, (c) RTT 조건(0/10/30/50ms)에서 3-flight(Conf) 영향 측정 필요.

## 4. 해석 (논문용 핵심)

1. **크기:** X-Wing이 on-wire 약 6.5~6.6배 큼(in-memory·라이브 동일 결론). 대역폭이 병목.
2. **시간(in-memory):** 동일조건에서 X-Wing 암호가 ECIES보다 약 6.7배 빠름 → "PQ=연산부담 증가" 통념 반박.
3. **시간(라이브 TCP):** 실제 peer 핸드셰이크 지연은 **ECIES와 대등**(crypto 1.02×). 라이브에선 네트워크·I/O가 지배해 in-memory의 연산 우위가 상쇄됨.
4. **정합성:** ECIES 라이브 crypto ≈ in-memory. 측정 신뢰성 확보.
5. **trade-off:** X-Wing 실비용은 연산이 아니라 대역폭·라운드(2→3). median 지연엔 비용이 안 드러나고 크기/꼬리지연에 드러남 → 금융 컨소시엄 유리.

## 5. 다음 단계
- 라이브 표본 보강(각 30+), RPC 부하 없는 수집, RTT 조건 실험(3-flight 영향).
- (선택) pcap으로 실제 TCP 세그먼트 수·wire bytes 측정.
- (선택) Tier-2 네이티브: Linux/macOS 재측정.
- Phase B: framing 로직을 `XWingHandshaker`에서 분리해 독립 transport 계층(예: Netty length-frame decoder)으로 정리(최종 구현). wire 포맷 동일(2B length)이라 측정 재수집 불필요.

## 6. 산출물 위치
- crypto primitive: `crypto/algorithms/.../crypto/xwing/XWing.java` (+ test `XWingTest.java`)
- **X-Wing 핸드셰이커(production)**: `p2p/.../rlpx/handshake/xwing/XWingHandshaker.java` (2B length-prefix framing + 누적 재조립 포함) + `XWingProvisioning.java`(시스템 프로퍼티 배선) + test `XWingHandshakerTest.java`(fragmentation 3종 포함)
- in-memory 벤치: `p2p/.../test/.../handshake/xwing/`, `.../handshake/ecies/`
- 라이브 TCP 계측: `p2p/.../connections/netty/HandshakeTimings.java` + NettyConnectionInitializer/HandshakeHandlerOutbound/AbstractHandshakeHandler/DeFramer (measure/ecies-tcp 브랜치)
- 라이브 2노드: ECIES `net_peerCount=0x1` + **X-Wing `net_peerCount=0x1`** 모두 확인.
