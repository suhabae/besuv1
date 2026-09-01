package org.hyperledger.besu.ethereum.p2p.rlpx.handshake.ecies;

// ── import 문: 이 파일에서 쓸 클래스들이 어느 패키지에 있는지 컴파일러에게 알려주는 자바 문법 ──
import java.security.KeyFactory;                 // 원시 바이트 → 공개키 객체 복원용 (JDK 표준)
import java.security.KeyPair;                    // (개인키, 공개키) 한 쌍을 담는 JDK 표준 클래스
import java.security.KeyPairGenerator;           // 키쌍 생성기 (JDK 표준, 여기선 provider "BC"로 호출)
import java.security.MessageDigest;              // 해시(SHA3-256) 계산 (JDK 표준)
import java.security.PrivateKey;                 // 개인키 인터페이스
import java.security.PublicKey;                  // 공개키 인터페이스
import java.security.SecureRandom;               // 암호학적 난수 생성기
import java.security.Security;                   // 보안 provider 등록/조회 (BC 등록에 사용)
import java.security.spec.X509EncodedKeySpec;    // SPKI(표준 공개키 인코딩) → 키 객체 복원 스펙
import java.util.Arrays;                         // 배열 자르기/비교/정렬 유틸
import javax.crypto.KeyAgreement;                // Diffie-Hellman 키합의(X25519) 실행기
import javax.crypto.KeyGenerator;                // BouncyCastle에서 ML-KEM 캡슐화를 수행하는 통로
import javax.crypto.Mac;                         // HMAC(키확인 태그) 계산기
import javax.crypto.spec.SecretKeySpec;          // 원시 바이트를 HMAC 키로 감싸는 스펙
import org.apache.tuweni.bytes.Bytes;                          // Besu가 쓰는 바이트열 타입(RLP 입력용)
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;      // BC ML-KEM 캡슐화 결과(ct+ss) 담는 타입
import org.bouncycastle.jcajce.spec.KEMExtractSpec;             // BC ML-KEM "복호(decapsulate)" 지시 스펙
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;            // BC ML-KEM "캡슐화(encapsulate)" 지시 스펙
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;         // ML-KEM 파라미터(512/768/1024) 선택 스펙
import org.bouncycastle.jce.provider.BouncyCastleProvider;      // BouncyCastle 메인 provider("BC")
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;   // Besu의 진짜 RLP 인코더(on-wire 크기 측정용)
import org.junit.jupiter.api.Test;               // JUnit5의 @Test 애너테이션

/**
 * [무엇을 하는 파일인가]
 * X-Wing(ML-KEM-768 + X25519) "Protocol 2" 핸드셰이크를, 순수 자바 BouncyCastle 구현으로 측정한다.
 * 메시지 크기는 Besu의 실제 RLP 인코더로 "전선(on-wire) 크기"를 잰다 → ECIES baseline과 같은 기준.
 *
 * [왜 만드는가 — Tier-1 공정비교]
 * - ECIES baseline은 Besu 내부의 BouncyCastle secp256k1 + RLP 프레이밍으로 돌았다(전선 크기 911B).
 * - 그래서 X-Wing도 (1) 같은 BouncyCastle로 ML-KEM/X25519를 돌리고, (2) 같은 RLP로 프레이밍해서
 *   "같은 라이브러리 · 같은 인코딩" 기준의 사과 대 사과 비교를 만든다.
 *
 * [무슨 언어/도구로 작성됐나]
 * - 언어: Java. 실행: Besu Gradle 테스트(JUnit5). PQ/DH provider: BouncyCastle("BC", Besu 번들 bcprov 1.84).
 * - RLP: Besu의 org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput (실제 devp2p가 쓰는 인코더).
 * - 해시(SHA3-256)/HMAC은 JDK 표준(두 X-Wing 테스트가 동일해야 'ML-KEM/X25519 provider'만 변수로 남음).
 */
@SuppressWarnings("all") // 연구용 테스트: 사소한 경고 무시
public class XWingBcHandshakeBaselineTest {

  private static final byte[] LABEL = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}; // X-Wing combiner 라벨(드래프트 §5.3)
  private static final SecureRandom RNG = new SecureRandom();               // 전역 난수기 1개 재사용

  // static 초기화 블록: 클래스 최초 로드 시 1번 실행 → "BC" provider 없으면 등록
  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test // JUnit5 테스트 1개. IntelliJ 왼쪽 초록 실행버튼으로 단독 실행 가능
  public void measureXWingHandshakeBC() throws Exception {
    XWing initiator = XWing.generate(); // 개시자(A) 장기키
    XWing responder = XWing.generate(); // 응답자(B) 장기키

    // (1) 크기: 한 번 왕복. r = {authWire, ackWire, confWire, authRaw, ackRaw, confRaw}
    int[] r = runHandshake(initiator, responder);
    System.out.println("=== X-Wing 핸드셰이크 (BouncyCastle · RLP on-wire · Tier-1) ===");
    System.out.println("[on-wire 크기 = RLP 인코딩 포함, ECIES와 동일 기준]");
    System.out.println("  Auth : " + r[0] + " bytes");
    System.out.println("  ACK  : " + r[1] + " bytes");
    System.out.println("  Conf : " + r[2] + " bytes");
    System.out.println("  총    : " + (r[0] + r[1] + r[2]) + " bytes (3 메시지)");
    System.out.println("[참고: RLP 미포함 순수 필드합]");
    System.out.println("  총    : " + (r[3] + r[4] + r[5]) + " bytes");

    // (2) 시간: 워밍업(JIT 최적화 유도) 후 본 측정
    int warmup = 200, iters = 2000;
    for (int i = 0; i < warmup; i++) {
      runHandshake(initiator, responder);
    }
    long[] t = new long[iters];
    for (int i = 0; i < iters; i++) {
      long s = System.nanoTime();
      runHandshake(initiator, responder);
      t[i] = System.nanoTime() - s;
    }
    Arrays.sort(t);
    System.out.println("\n[전체 핸드셰이크 시간] 단위: 마이크로초(us)");
    System.out.printf("  중앙값 %.1f | p90 %.1f | 최소 %.1f%n",
        t[iters / 2] / 1000.0, t[(int) (iters * 0.9)] / 1000.0, t[0] / 1000.0);
  }

  /** 핸드셰이크 1회. 반환 = {authWire, ackWire, confWire, authRaw, ackRaw, confRaw} */
  private int[] runHandshake(XWing initiator, XWing responder) throws Exception {
    // === 개시자 A: Auth 생성 ===
    XWing eph = XWing.generate();          // 임시 X-Wing 키(전방향 비밀성)
    byte[] nI = random32();                // 개시자 논스
    Enc encR = encap(responder);           // K_R, CT_R : 응답자 정적키로 캡슐화(=응답자 인증)
    byte[] iPub = initiator.pubBytes();    // 개시자 정적 공개키(전송)
    byte[] ePub = eph.pubBytes();          // 개시자 임시 공개키(전송)
    int authRaw = iPub.length + ePub.length + encR.ct.length + nI.length;
    int authWire = rlp(iPub, ePub, encR.ct, nI);   // ← 실제 RLP 인코딩한 on-wire 크기

    // === 응답자 B: Auth 처리 → ACK 생성 ===
    byte[] kR = decap(encR.ct, responder); // 응답자가 CT_R 복호 → encR.ss와 같아야 함
    Enc encI = encap(initiator);           // K_I, CT_I : 개시자 정적키로 캡슐화(=개시자 인증)
    Enc encE = encap(eph);                 // K_E, CT_E : 개시자 임시키로 캡슐화(=전방향 비밀성)
    byte[] nR = random32();                // 응답자 논스
    byte[] kEphB = sha3(concat(encI.ss, kR, encE.ss));      // K_eph = SHA3(K_I||K_R||K_E)
    byte[] kConfB = sha3(concat("conf".getBytes(), kEphB)); // 확인키(세 KEM비밀 모두에서 유도)
    byte[] tagR = hmac(kConfB, concat(nI, nR));             // 응답자 키확인 태그
    int ackRaw = encI.ct.length + encE.ct.length + tagR.length + nR.length;
    int ackWire = rlp(encI.ct, encE.ct, tagR, nR);

    // === 개시자 A: ACK 처리 → 세션키/확인 → Conf 생성 ===
    byte[] kI = decap(encI.ct, initiator); // == encI.ss
    byte[] kE = decap(encE.ct, eph);       // == encE.ss
    byte[] kEphA = sha3(concat(kI, encR.ss, kE));           // A가 계산한 K_eph (encR.ss==K_R)
    byte[] kConfA = sha3(concat("conf".getBytes(), kEphA));
    byte[] tagRcheck = hmac(kConfA, concat(nI, nR));
    if (!Arrays.equals(tagRcheck, tagR)) {
      throw new IllegalStateException("tag_R 검증 실패");
    }
    byte[] tagI = hmac(kConfA, concat(nR, nI));             // 개시자 확인 태그(Conf 메시지)
    int confRaw = tagI.length;
    int confWire = rlp(tagI);

    // === 응답자 B: Conf 검증 ===
    byte[] tagIcheck = hmac(kConfB, concat(nR, nI));
    if (!Arrays.equals(tagIcheck, tagI)) {
      throw new IllegalStateException("tag_I 검증 실패");
    }
    if (!Arrays.equals(kEphA, kEphB)) {                     // 양측 세션키 일치 확인
      throw new IllegalStateException("세션키 불일치");
    }
    return new int[] {authWire, ackWire, confWire, authRaw, ackRaw, confRaw};
  }

  // ===================== X-Wing 암호 (전부 BouncyCastle provider "BC") =====================

  /** X-Wing 키쌍 = ML-KEM-768 키쌍 + X25519 키쌍 */
  static final class XWing {
    final KeyPair mlkem;
    final KeyPair x25519;

    XWing(KeyPair m, KeyPair x) {
      mlkem = m;
      x25519 = x;
    }

    static XWing generate() throws Exception {
      KeyPairGenerator km = KeyPairGenerator.getInstance("ML-KEM", "BC");
      km.initialize(MLKEMParameterSpec.ml_kem_768, RNG);
      KeyPairGenerator kx = KeyPairGenerator.getInstance("X25519", "BC");
      return new XWing(km.generateKeyPair(), kx.generateKeyPair());
    }

    /** 전송용 공개키 직렬화: ML-KEM ek(1184) + X25519 pub(32) = 1216 */
    byte[] pubBytes() {
      byte[] ek = mlkem.getPublic().getEncoded();                        // BC는 SPKI로 감싼 형태
      byte[] ekRaw = Arrays.copyOfRange(ek, ek.length - 1184, ek.length); // 뒤 1184B가 실제 ek
      return concat(ekRaw, rawX(x25519.getPublic()));
    }
  }

  /** 캡슐화 결과: 암호문(ct) + 공유비밀(ss) */
  static final class Enc {
    final byte[] ct; // ML-KEM ct(1088) + X25519 임시공개키(32) = 1120
    final byte[] ss; // 32

    Enc(byte[] c, byte[] s) {
      ct = c;
      ss = s;
    }
  }

  /** 상대 X-Wing 공개키로 캡슐화 (ML-KEM=BC, X25519=BC) */
  static Enc encap(XWing peer) throws Exception {
    // (1) ML-KEM 캡슐화 (BC): KeyGenerator + KEMGenerateSpec 이 BC의 캡슐화 통로
    KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", "BC");
    kg.init(new KEMGenerateSpec(peer.mlkem.getPublic(), "Secret"), RNG); // getPublic()이 이미 PublicKey → 캐스팅 불필요
    SecretKeyWithEncapsulation e = (SecretKeyWithEncapsulation) kg.generateKey();
    byte[] ctM = e.getEncapsulation();   // 1088
    byte[] ssM = e.getEncoded();         // 32 (ML-KEM 공유비밀)

    // (2) X25519: 임시 키쌍 생성 후 DH
    KeyPair ephX = KeyPairGenerator.getInstance("X25519", "BC").generateKeyPair();
    byte[] ctX = rawX(ephX.getPublic());                 // 32 (임시 공개키 = 암호문 일부)
    byte[] ssX = dh(ephX.getPrivate(), peer.x25519.getPublic());
    byte[] pkX = rawX(peer.x25519.getPublic());          // 32 (수신자 X25519 공개키)

    // (3) SHA3-256 combiner (드래프트 구조)
    byte[] ss = sha3(concat(ssM, ssX, ctX, pkX, LABEL));
    return new Enc(concat(ctM, ctX), ss);                // ct = ML-KEM ct || X25519 임시공개키
  }

  /** 내 X-Wing 개인키로 복호 */
  static byte[] decap(byte[] ct, XWing me) throws Exception {
    byte[] ctM = Arrays.copyOfRange(ct, 0, ct.length - 32);           // ML-KEM ct
    byte[] ctX = Arrays.copyOfRange(ct, ct.length - 32, ct.length);   // 임시 X25519 공개키(32)

    // (1) ML-KEM 복호 (BC): KeyGenerator + KEMExtractSpec
    KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", "BC");
    kg.init(new KEMExtractSpec(me.mlkem.getPrivate(), ctM, "Secret"));  // getPrivate()이 이미 PrivateKey → 캐스팅 불필요
    SecretKeyWithEncapsulation d = (SecretKeyWithEncapsulation) kg.generateKey();
    byte[] ssM = d.getEncoded();

    // (2) X25519 DH (내 개인키 × 상대 임시공개키)
    byte[] ssX = dh(me.x25519.getPrivate(), pubFromRaw(ctX));
    byte[] pkX = rawX(me.x25519.getPublic());
    return sha3(concat(ssM, ssX, ctX, pkX, LABEL));
  }

  // ===================== 헬퍼 =====================

  /** Besu 실제 RLP 인코더로 필드들을 리스트로 인코딩 → on-wire 바이트 수 */
  static int rlp(byte[]... fields) {
    BytesValueRLPOutput out = new BytesValueRLPOutput();
    out.startList();
    for (byte[] f : fields) {
      out.writeBytes(Bytes.wrap(f));
    }
    out.endList();
    return out.encoded().size();
  }

  /** X25519 Diffie-Hellman: 내 개인키 × 상대 공개키 → 32B 공유비밀 */
  static byte[] dh(PrivateKey myPriv, PublicKey peerPub) throws Exception {
    KeyAgreement ka = KeyAgreement.getInstance("X25519", "BC");
    ka.init(myPriv);
    ka.doPhase(peerPub, true);
    return ka.generateSecret();
  }

  /** 공개키 객체 → 원시 32바이트 (SPKI 44바이트의 마지막 32B) */
  static byte[] rawX(PublicKey pk) {
    byte[] enc = pk.getEncoded();
    return Arrays.copyOfRange(enc, enc.length - 32, enc.length);
  }

  // X25519 공개키의 표준 SPKI 헤더(12바이트 고정): 30 2a 30 05 06 03 2b 65 6e 03 21 00
  private static final byte[] X25519_SPKI_PREFIX = {
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
  };

  /** 원시 32바이트 → X25519 공개키 객체 복원 (표준 SPKI 헤더를 붙여 X509EncodedKeySpec으로 → provider 무관 안정적) */
  static PublicKey pubFromRaw(byte[] raw32) throws Exception {
    byte[] spki = concat(X25519_SPKI_PREFIX, raw32);   // 12 + 32 = 44바이트 SPKI
    return KeyFactory.getInstance("X25519", "BC").generatePublic(new X509EncodedKeySpec(spki));
  }

  static byte[] sha3(byte[] in) throws Exception {
    return MessageDigest.getInstance("SHA3-256").digest(in);  // JDK 표준(두 X-Wing 테스트 공통)
  }

  static byte[] hmac(byte[] key, byte[] in) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA3-256");
    mac.init(new SecretKeySpec(key, "HmacSHA3-256"));
    return mac.doFinal(in);
  }

  static byte[] random32() {
    byte[] b = new byte[32];
    RNG.nextBytes(b);
    return b;
  }

  static byte[] concat(byte[]... parts) {
    int len = 0;
    for (byte[] p : parts) {
      len += p.length;
    }
    byte[] out = new byte[len];
    int off = 0;
    for (byte[] p : parts) {
      System.arraycopy(p, 0, out, off, p.length);
      off += p.length;
    }
    return out;
  }
}
