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
- **증상**: X-Wing 켜면 `net_peerCount=0x0`, 조용히 실패. **원인**: `handleMessage`가 "1 read=1 완전 메시지" 가정. Auth(3663B)/ACK(2315B)가 Netty 초기 수신버퍼(~2048B)보다 커서 조각화 → 잘린 조각 RLP 파싱 → 예외 → TRACE로만 로깅 후 채널 종료. (관측: 개시자 `authBodyLength=3663`, 응답자 첫 `chunkLength=2048`.)
- **수정 (계층분리·최소)**: `XWingHandshaker.java` 한 파일 안에서만 — 각 메시지에 **2바이트 BE 길이 접두어**(RLPx/EIP-8 관례) + 수신 **누적 버퍼**로 완전한 프레임이 모일 때까지 대기. 불완전 시 `Optional.empty()`→기존 핸들러 "waiting for more bytes" 활용. **Besu 핸들러/파이프라인/암호/키/주소록 무수정.** 헬퍼 `frame()/nextCompleteFrame()/concat()` 추가.
- 수정 `AbstractHandshakeHandler` — 진단용 임시 로그 제거(T5/T6 계측만 유지, 원본에 근접).
- 신규 테스트 3종(`XWingHandshakerTest`): Auth 2048분할, 개시자 ACK 분할, 1바이트씩 조각화 — 모두 재조립·완주 확인 ✅.

**결과 (라이브 2노드, 2026-09-02)**
- **X-Wing `net_peerCount=0x1`** — 실제 TCP에서 X-Wing 핸드셰이크로 연결 성공. `XW-OBS#4 assembled bodyLength=3663 reads=2`로 조각 재조립 실측.
- **동일조건 비교(steady-state 중앙값, X-Wing N=14 / ECIES N=10, 동일 peerCount-검증 재연결 스크립트)**:
  - crypto·secrets(T6-T1): ECIES 9.78 / X-Wing 9.99 ms → **1.02× (대등)**
  - peerTotal(T8-T0): ECIES 19.63 / X-Wing 14.87 ms
  - on-wire 크기: ECIES 911B / X-Wing ~6.0KB (약 6.6배)
- **해석**: 라이브 peer 핸드셰이크 지연은 ECIES와 **대등(parity)**. PQC 비용은 연산이 아니라 대역폭·꼬리지연(p90)·라운드(2→3)에 드러남. (peerTotal/TCP의 X-Wing 우세는 표본·부하 노이즈로, 우월 주장 안 함.)

**다음**
- 표본 보강(각 30+), RPC 부하 없는 수집, RTT 조건(0/10/30/50ms) 실험(3-flight 영향).
- Phase B: framing을 독립 transport 계층으로 분리(wire 포맷 2B length 동일 → 재측정 불필요).
