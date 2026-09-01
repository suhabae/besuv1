# X-Wing PQ-RLPx 연구 변경기록 (fork: suhabae/besuv1)

> 목적: Hyperledger Besu의 RLPx 핸드셰이크(ECIES)를 X-Wing(ML-KEM-768 + X25519) 기반으로
> 전환·비교 연구. 이 파일은 기존 Besu 대비 "무엇을 왜 어떻게" 바꿨는지 누적 기록한다.
>
> remote: origin = besu-eth/besu (upstream, **절대 push 안 함**) · myfork = suhabae/besuv1 (연구 백업)
> 원칙: Besu 코어 로직 무변경, 작업은 대부분 새 파일 추가(additive).

---

## [main] X-Wing primitive 도입 + 저장소 정리

**무엇**
- 신규 `crypto/algorithms/.../crypto/xwing/XWing.java` — X-Wing KEM primitive(keygen/encapsulate/decapsulate, SHA3-256 combiner). BouncyCastle의 ML-KEM/X25519를 감쌈. (SECP256K1과 동급 위치)
- 신규 `crypto/algorithms/.../test/.../crypto/xwing/XWingTest.java` — 왕복·크기·오복호 단위테스트.
- 신규 `p2p/.../test/.../handshake/xwing/XWingHandshakeBaselineTest.java`, `XWingBcHandshakeBaselineTest.java` — X-Wing in-memory 벤치(프로토타입). ecies/ 에서 xwing/ 로 이동.
- 신규 `p2p/.../test/.../handshake/ecies/EciesHandshakeBaselineTest.java`, `NativeStatusProbeTest.java` — ECIES 벤치 / secp256k1 네이티브 프로브.

**왜**
- 암호 primitive(crypto)와 프로토콜(handshake)을 Besu 관례대로 분리하기 위함.
- 기존 ECIES와 X-Wing의 성능(크기·시간)을 공정 비교하기 위함.

**besu 원본 대비**
- 코어 로직 변경 없음. 단 `gradle/wrapper/gradle-wrapper.properties`: Gradle 9.3.1 → 9.7.1(빌드 환경 요구).
- 한때 수정됐던 `ECIESHandshaker.java`(빈 줄), `Hash.java`(오타)는 원본 복구.
- `QBFT-Network/`, `networkFiles/`(개인키·DB)는 `.git/info/exclude`로 git 제외.

---

## [measure/ecies-tcp] 기존 ECIES 실제 TCP 핸드셰이크 계측(T0~T8)

**무엇 (계측 추가 — 로직 변경 없음, 타임스탬프만)**
- 신규 `p2p/.../connections/netty/HandshakeTimings.java` — 연결 단위 T0~T8 타임스탬프 holder(Netty 채널 속성).
- 수정 `NettyConnectionInitializer.java` — connect()에서 **T0**(TCP connect 시작) 기록 + 채널에 부착.
- 수정 `HandshakeHandlerOutbound.java` — **T1**(channelActive=TCP 연결), **T2**(Auth 전송 완료).
- 수정 `AbstractHandshakeHandler.java` — **T5**(개시자 Ack 수신), **T6**(HandshakeSecrets 완료).
- 수정 `DeFramer.java` — **T7**(암호화 Hello 인증), **T8**(peer 확립) + 개시자 측 구간 요약 INFO 로그.
- 수정 `crypto/.../xwing/XWing.java` — Besu Error Prone(-Werror) 대응: `new SecureRandom()` → `SecureRandomProvider.publicSecureRandom()`, `MessageDigest.getInstance` → `MessageDigestFactory.create`.

**왜**
- in-memory 벤치(handshake processing latency)와 별개로, **실제 노드↔노드 TCP** 상의 TCP연결/암호핸드셰이크/Hello/peer확립 구간을 분리 측정하기 위함.
- 서로 다른 JVM의 nanoTime을 직접 빼지 않도록, 개시자 JVM 한 곳에서만 구간 차이를 계산.

**측정 산출(로그)**: `Handshake timing nodeId=… [RLPx-TCP us] TCP(T1-T0) AuthAckRTT(T5-T2) crypto(T6-T1) helloAuth(T7-T1) peer(T8-T1) peerTotal(T8-T0)`

**주의**: 이 브랜치는 "측정용 비계"다. production 배포용 아님. X-Wing 통합(다음 단계)은 별도 브랜치에서 진행.
