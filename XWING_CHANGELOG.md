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
