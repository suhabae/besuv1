# X-Wing PQ-RLPx 연구 변경기록 (fork: suhabae/besuv1)

> 목적: Hyperledger Besu의 RLPx 핸드셰이크(ECIES)를 X-Wing(ML-KEM-768 + X25519) 기반으로
> 전환·비교 연구. 이 파일은 기존 Besu 대비 "무엇을 왜 어떻게" 바꿨는지 누적 기록한다.
>
> remote: origin = besu-eth/besu (upstream, **절대 push 안 함**) · myfork = suhabae/besuv1 (연구 백업)
> 원칙: Besu 코어 로직 무변경, 작업은 대부분 새 파일 추가(additive).

---

## [main] X-Wing primitive 도입 + 저장소 정리

**무엇**
- 신규 `crypto/algorithms/.../crypto/xwing/XWing.java` — X-Wing KEM primitive(keygen/encapsulate/decapsulate, SHA3-256 combiner). BouncyCastle의 ML-KEM/X25519를 감쌈. (SECP256K1과 동급 위치). SecureRandomProvider/MessageDigestFactory 사용(-Werror 대응).
- 신규 `crypto/algorithms/.../test/.../crypto/xwing/XWingTest.java` — 왕복·크기·오복호 단위테스트.
- 신규 `p2p/.../test/.../handshake/xwing/XWingHandshakeBaselineTest.java`, `XWingBcHandshakeBaselineTest.java` — X-Wing in-memory 벤치(프로토타입). ecies/→xwing/ 이동.
- 신규 `p2p/.../test/.../handshake/ecies/EciesHandshakeBaselineTest.java`, `NativeStatusProbeTest.java` — ECIES 벤치 / secp256k1 네이티브 프로브.

**besu 원본 대비**: 코어 로직 무변경. `gradle-wrapper.properties`만 Gradle 9.3.1→9.7.1(빌드 환경). ECIESHandshaker/Hash는 원본 복구. QBFT-Network/networkFiles는 `.git/info/exclude`.

---

## [measure/ecies-tcp] 기존 ECIES 실제 TCP 계측(T0~T8)

**무엇 (계측 추가 — 로직 변경 없음)**
- 신규 `p2p/.../connections/netty/HandshakeTimings.java` — 연결 단위 T0~T8 타임스탬프 holder(Netty 채널 속성).
- 수정 `NettyConnectionInitializer`(T0), `HandshakeHandlerOutbound`(T1,T2), `AbstractHandshakeHandler`(T5,T6), `DeFramer`(T7,T8+요약 INFO 로그).

**결과(라이브 TCP baseline, 워밍 N=25)**: peerTotal 중앙값 ~24ms(최소 10.7 / 다수 13~18ms / 꼬리 최대 51 — 재연결 부하 영향), crypto(T6-T1) 중앙값 ~11.8ms(최소 5.3). **crypto 최소~중앙이 in-memory 7.85ms를 브래킷** → 계층 정합성 확인.

---

## [measure/ecies-tcp] Phase 2-A: XWingHandshaker 골격 + 시크릿 유도

**무엇 (신규)**
- 신규 `p2p/.../handshake/xwing/XWingHandshaker.java` — `Handshaker` 구현. X-Wing 3-메시지 명시적 AKE(Auth→ACK→Conf, 컨소시엄 PDK 변형).
  - crypto `XWing` primitive로 K_R/K_I/K_E 캡슐화·복호, `K_eph=Keccak256(K_I‖K_R‖K_E)`.
  - **KDF/MAC은 Keccak-256**(이더리움 정합)으로 aes/mac/token + egress/ingress MAC 시드 유도 → **기존 `HandshakeSecrets`/`Framer` 그대로 재사용**.
  - 신원: secp256k1 유지, 상대 X-Wing 정적키는 nodeId→pk 주소록(PDK)에서 조회. 키확인 태그 tag_R/tag_I.
- 신규 `p2p/.../test/.../handshake/xwing/XWingHandshakerTest.java` — 전체 흐름에서 **양측 동일 시크릿(거울대칭 MAC)** + 오설정 키 시 tag 검증 실패 확인. 통과 ✅.

**왜**: 핸드셰이크 이후(Framer/Hello/eth)를 기존 Besu 그대로 두고 핸드셰이커만 X-Wing으로 교체하기 위한 핵심 부품. -Werror/Error Prone 통과.

**다음 (미완)**
- Step C: `AbstractHandshakeHandler`의 2-메시지 전제를 3-메시지(Conf 후 곧장 Hello)로 확장.
- Step D: `NettyConnectionInitializer.buildInstance()`를 플래그로 ECIES↔X-Wing 전환.
- 이후: 실제 2노드 X-Wing 연결 + T0~T8로 ECIES와 직접 비교.

---

## [measure/ecies-tcp] Phase 2-D~E: 배선 + framing 수정 → 실제 2노드 X-Wing 연결 성공

**Step C 정정**: `AbstractHandshakeHandler`는 2-메시지 전제가 아님(소스 확인). `nextHandshakeMessage`가 응답을 반환하면 계속 보내고, 응답 없이 `SUCCESS`면 다음 단계로 전환 + `Optional.empty()`면 "waiting for more bytes"로 대기. → **3-메시지(Auth→ACK→Conf) 그대로 지원, 핸들러 수정 불필요.**

**무엇 (배선)**
- 신규 `p2p/.../handshake/xwing/XWingProvisioning.java` — 시스템 프로퍼티로 X-Wing on/off + 정적키/주소록 로드. `-Dbesu.rlpx.xwing=true|.keyFile=|.addressBook=`. (CLI/BesuCommand 무수정)
- 수정 `NettyConnectionInitializer.buildInstance()` — `enabled()`이면 `XWingHandshaker`, 아니면 `ECIESHandshaker`. **단일 배선점.**
- 신규 `XWing.KeyPair.privateKeyBundle()` / `keyPairFromPrivateBundle()` — 정적키 파일 저장/복원(수동 길이접두어 직렬화).

**무엇 (framing 수정 — 라이브 실패의 진짜 원인)**
- **증상**: X-Wing 켜면 `net_peerCount=0x0`, 조용히 실패. **원인**: `handleMessage`가 "1 read=1 완전 메시지" 가정. TCP는 메시지 경계를 보존하지 않아 큰 메시지가 여러 read로 나뉠 수 있고(항상 2048B는 아님), **본 실험에선 Auth 3663B가 첫 2048B + 후속으로 나뉘어 도착**하는 것이 관측됨 → 잘린 조각 RLP 파싱 → 예외 → TRACE로만 로깅 후 채널 종료. (관측: 개시자 `authBodyLength=3663`, 응답자 첫 `chunkLength=2048`.)
- **수정 (계층분리·최소)**: `XWingHandshaker.java` 한 파일 안에서만 — 각 메시지에 **2바이트 BE 길이 접두어**(RLPx/EIP-8 관례) + 수신 **누적 버퍼**로 완전한 프레임이 모일 때까지 대기. 불완전 시 `Optional.empty()`→기존 핸들러 "waiting for more bytes" 활용. **Besu 핸들러/파이프라인/암호/키/주소록 무수정.** 헬퍼 `frame()/nextCompleteFrame()/concat()` 추가.
- 수정 `AbstractHandshakeHandler` — 진단용 임시 로그 제거(T5/T6 계측만 유지, 원본에 근접).
- 신규 테스트 3종(`XWingHandshakerTest`): Auth 2048분할, 개시자 ACK 분할, 1바이트씩 조각화 — 모두 재조립·완주 확인 ✅.

**결과 (라이브 2노드, 2026-09-02)**
- **X-Wing `net_peerCount=0x1`** — 실제 TCP에서 X-Wing 핸드셰이크로 연결 성공. `XW-OBS#4 assembled bodyLength=3663 reads=2`로 조각 재조립 실측.
- **동일조건 비교(steady-state 중앙값, X-Wing N=14 / ECIES N=10, 동일 peerCount-검증 재연결 스크립트, localhost 예비)**:
  - handshake→secrets(T6-T1): ECIES 9.78 / X-Wing 9.99 ms → **1.02×** (순수 암호 아님 — 네트워크 왕복·I/O 포함 구간)
  - peerTotal(T8-T0): ECIES 19.63 / X-Wing 14.87 ms
  - 직렬화 핸드셰이크 바이트(application-layer): ECIES 911B / X-Wing ~6.0KB (약 6.6배). 진짜 on-wire는 pcap 필요.
- **해석(정직히)**: handshake→secrets 지연이 ECIES와 **유사(parity)** — '암호 연산 동일'이 아니라 라이브에선 네트워크·I/O가 이 구간을 지배해서다. peerTotal/TCP의 X-Wing 우세는 표본·부하 노이즈로 우월 주장 안 함. **확인된 PQC 비용은 크기(약 6.6배)+flight(2→3)**이며, **꼬리지연(tail latency) 영향은 미확정**(소표본에선 X-Wing p90이 더 낮은 구간도 있었음). in-memory 우위(약 6.7배)는 본 구현·환경 조건의 결과이지 일반화된 통념 반박이 아님. AKE 보안성(mutual auth·FS·KCI 등)은 미증명.

**다음**
- 표본 보강(각 30+), RPC 부하 없는 수집, RTT 조건(0/10/30/50ms) 실험(3-flight 영향), WAN/컨소시엄 수용성 검증.
- Phase B: framing을 독립 transport 계층으로 분리. wire 포맷(2B length)은 동일하나 메모리 복사·버퍼 관리·Netty 콜백 비용이 달라질 수 있어 **분리 후 기능·성능 regression 재측정 필요**.

---

## [measure/ecies-tcp] Phase 2-F: Auth에서 secp nodeId 제거 + 주소록 역조회 신원 바인딩

**무엇**
- **Auth 메시지에서 secp nodeId(64B) 제거.** `Auth = [XWpk_I, XWpk_eph, CT_R, n_I]` (기존: 맨 앞에 `secp_I(64)` 있었음).
- 응답자는 Auth의 개시자 X-Wing 공개키(`XWpk_I`)를 **역주소록(X-Wing pk → nodeId)으로 역조회**해 개시자 신원(nodeId)을 확정. 주소록에 없는 키면 **거절**.
- `XWingHandshaker` 생성자에 역조회 함수 파라미터 추가. `XWingProvisioning`이 주소록 로드 시 정방향·역방향 맵을 함께 구성해 전달. 미사용이 된 `nodeKey` 필드 제거.
- 테스트: 모든 생성자 3-인자로 갱신 + **`unregisteredInitiatorRejectedAtAuth`**(미등록 개시자 거절) 추가. 총 6개 통과.

**왜**
- 신원(nodeId)이 이미 컨소시엄 주소록에 있으므로 secp nodeId를 전선에 다시 실을 필요가 없음(중복 제거).
- 더 중요: 응답자가 `XWpk_I`를 그냥 신뢰하던 기존 방식의 약점을 없앰 → **주소록에 등록된 멤버의 X-Wing 키만 통과**하므로 신원이 KEM 인증(개시자가 `XWpk_I` 개인키 보유 증명)과 결합되어 바인딩 성립. Phase 4로 미뤘던 신원 바인딩을 자연스럽게 당겨옴.

**결과**: Auth 소폭 감소 — RLP 본문 **3663B→3597B**(on-wire 3665→3599B), secp 64B + RLP 오버헤드 제거분. 실제 2노드 X-Wing 연결 `net_peerCount=0x1` 재확인. 단위테스트 6/6 통과.

**주의**: wire 포맷 변경(Auth 필드 구성) → 두 노드 모두 이 빌드여야 함. 주소록 파일 형식(`nodeId=xwingpub`)은 불변이라 기존 키·주소록 그대로 사용. **Besu 원본 무수정**(우리 파일 2개 + 테스트만).

---

## [measure/ecies-tcp] Phase 3: 통제 네트워크(WSL netns+netem) 반복측정 + 계측 구간 정밀화

**무엇 (측정 하네스 — 프로덕션 로직 무영향)**
- **반복 재연결 30초 벽 해결**: `RlpxAgent.peersConnectingCache`(`expireAfterWrite(30s)`, "we will at most try to connect every 30 seconds")가 `admin_removePeer`→`admin_addPeer` 반복측정을 30초에 1회로 제한하고, `disconnect()`가 이 캐시를 무효화하지 않아 재연결이 30초씩 지연됨. → **측정 모드(`-Dbesu.rlpx.measurement=true`)에서만** `disconnect()` 시 `peersConnectingCache.invalidate(peerId)` 추가. 평상시 30초 throttle 그대로 유지. ECIES/X-Wing 공통 경로.
- 런치 플래그(소스 아님) `--Xp2p-check-maintained-connections-frequency=2`: 즉시연결 경합 시 재시도 안전망(양쪽 프로토콜 동일 적용).

**무엇 (계측 구간 정밀화 — nanoTime 기록만 추가)**
- `setup(T1-T0)`가 순수 TCP가 아님을 확인(생성자에서 `firstMessage()` 실행 후 `channelActive`). → **직접 분리 계측**: `HandshakeHandlerOutbound`에서 `firstMessage` 앞뒤 `Ta/Tb` 기록 → `prep(Tb-Ta)`=개시자 first-message 암호, `pureTCP(T1-Tb)`=실제 TCP.
- **`keyReady(T6a-T1)` 추가**: `AbstractHandshakeHandler`에서 `nextHandshakeMessage` 직후 `status==SUCCESS`가 되는 순간(=개시자가 세션키 도출 + 상대 `tag_R` 인증)을 프로토콜 무관하게 1회 기록. 기존 `crypto(T6-T1)`은 X-Wing이 이때 Conf를 반환하는 탓에 T6가 응답자 Hello 수신까지 밀려 **프로토콜 간 의미가 달랐음** → `keyReady`로 교정(양쪽 ≈1×RTT 기대).
- `XWingHandshaker`의 관측용 OBS 로그 `info`→`debug` (X-Wing 측정 편향·로그노이즈 제거).
- `parse-timing.sh` 갱신: `prep/pureTCP/keyReady` 파싱·요약.

**하네스 스크립트 (신규, `netns/`)**: `setup-netns.sh`(ns1↔veth↔ns2 + netem delay/rate), `run-node.sh`(netns 내 besu 실행), `measure-collect.sh`(실 handshake N개 보장 수집, hsFail 구분), `parse-timing.sh`(구간별 통계+CSV), `sweep.sh`(RTT 0/10/30/50 스윕).

**계측 원칙 (논문 정합)**: 개시자 단일 JVM 시계 구간차만 사용, 서로 다른 JVM timestamp 직접 차감 금지(cf. Paquin–Stebila–Tamvada 2020; KEMTLS 2020, netns+netem·개시자측 end-to-end). 응답자측 명시적 키확인(`tag_I` 검증) 완료 계측은 응답자 자기 시계로 별도 추가 예정.

**주의**: 위 계측/측정모드는 `System.nanoTime()` 기록과 측정모드 캐시무효화뿐, RLPx/암호/키/주소록/TCP 동작은 불변.

**추가 (응답자측 AKE 완료 계측)**: inbound(응답자) 채널에도 `HandshakeTimings` 부착 → 응답자 자기 시계로 `respAKE(T6a-T5)` = Auth 수신 → 첫 SUCCESS(=X-Wing: `tag_I` 검증 완료 = **상호 명시적 키 확인 완료**; ECIES: Auth 처리 완료) 기록. 서로 다른 JVM 시계는 여전히 직접 차감하지 않음(개시자 지표는 node1.log, 응답자 지표는 node2.log). `sweep.sh`가 조건별로 node2.log의 respAKE도 추출·요약.

---

## [measure/ecies-tcp] Phase 3-B: 응답자 respAKE 통계 오염 발견 및 파서 교정 (재측정 불필요)

**발견 (GitHub raw 로그 직접 대조로 확정)**
- `sweep.sh`의 응답자 수집이 `grep 'peerTotal(T8-T0)='` 로 node2.log의 **모든** handshake timing 줄을 긁은 뒤 `respAKE`만 뽑아 통계에 넣었음.
- 그런데 node2.log에는 **Node2가 우연히 initiator가 된 연결**(빠른 재연결 사이클 중 Node2측 P2P 연결유지/탐색이 Node1에게 먼저 outbound 다이얼)의 줄이 섞임. 이 줄은 `TCP(T1-T0)=숫자`(개시자형), respAKE≈0.5~2ms(개시자측: ACK 수신→키). 진짜 responder 줄은 `TCP(T1-T0)=n/a`, respAKE≈RTT.
- 실측 혼입 개수: xwing2 rtt0/10/30/50 = 6/6/9/**28**, ecies2 = 5/6/8/7. (진짜 responder는 전 조건 정확히 **115개**로 일정 = warmup15+measure100.) → 과거 "respAKE N=128은 hsFail 때문"이라던 설명은 **틀림**. hsFail(재연결 실패)은 응답자 timing 줄 자체를 만들지 않으므로 respAKE N에 애초에 들어오지 않음. N 부풀림의 원인은 **100% 역할 혼입**.

**영향 (중요)**
- **중앙값은 견고**(혼입<50%): 예) X-Wing rtt50 median 52.74→52.89. 기존 보고서의 median 기반 해석·회귀(응답자 respAKE X-Wing≈3.3+0.99·RTT, ECIES≈6.5−0.02·RTT)는 **그대로 유효**.
- **평균/표준편차/N은 왜곡**되어 있었음: X-Wing rtt50 mean 42.90→**53.08**(≈0.9ms 값 28개가 끌어내림, 19% 과소). 교정 후 std 0.78~1.05로 매우 타이트.
- **Node1(개시자) 지표는 무오염**: `parse-timing.sh` 정규식이 `TCP(T1-T0)=([\d.]+)`로 **숫자를 강제**해 node1.log에 섞인 responder 줄(`=n/a`)을 자동 배제. 실제 CSV steady 행수 전 조건 정확히 100. prep/pureTCP/AuthAckRTT/keyReady/peerTotal 신뢰.
- 즉 raw 로그·계측코드는 정상, **문제는 응답자 로그의 역할 분류(파서)뿐**.

**수정 (측정 파이프라인만, Besu 프로덕션/암호/계측 무변경)**
- `sweep.sh` 응답자 python: 줄 채택 조건에 `'TCP(T1-T0)=n/a' in ln`(진짜 responder만) 추가.
- 신규 `netns/reparse-resp.sh`: 저장된 raw `.resp.timing`에서 진짜 responder만 골라 respAKE 재계산 + 조건별 `*.respAKE.csv`(run/phase/respAKE_ms) 산출. **재측정 없이 원자료에서 정정값 도출**.
- `setup-netns.sh`: `if [ "$3" = ... ]` → `"${3:-}"`(선택 인자 방어, 결과엔 영향 없던 잠재버그).

**교정 후 응답자 respAKE (진짜 responder, warmup15폐기, steady N=100)**
| RTT | X-Wing median(mean±std) | ECIES median(mean±std) |
|--|--|--|
|0 | 3.62 (4.45±2.73) | 7.29 (8.36±4.18) |
|10| 12.71 (13.04±1.05) | 5.16 (5.17±2.05) |
|30| 33.35 (33.34±0.78) | 5.97 (6.28±2.30) |
|50| 52.89 (53.08±0.97) | 5.60 (5.82±2.61) |

회귀(median): X-Wing 3.31+0.993·RTT (≈1왕복, Conf 대기), ECIES 6.46−0.020·RTT (평평). **결론 불변, 오히려 더 선명**.

**선택(미적용, 논문용 권장)**: DeFramer 로그에 `role=INITIATOR|RESPONDER`와 `runId` 추가 → 역할 분류를 파싱 대신 원천 태깅으로, 개시자/응답자 run 1:1 대응. 지금은 `TCP=n/a` 규칙만으로 정확 분류되어 재측정 불요.
