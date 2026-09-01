package org.hyperledger.besu.ethereum.p2p.rlpx.handshake.xwing;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

/**
 * X-Wing(ML-KEM-768 + X25519) 핸드셰이크 측정 — ECIES baseline과 비교용.
 *
 * ECIES 테스트(EciesHandshakeBaselineTest)와 같은 방식(워밍업 200 + 측정 2000, 중앙값/p90/최소)으로,
 * X-Wing "Protocol 2" 핸드셰이크의 메시지 크기(Auth/ACK/Conf)와 전체 시간을 잰다.
 *
 * 순수 JDK 표준 암호만 사용(ML-KEM-768, X25519, SHA3-256, HmacSHA3-256) → JDK 25 필요.
 * combiner는 X-Wing 드래프트 구조(SHA3-256(ss_M || ss_X || ct_X || pk_X || label))를 따름.
 * (연구 프로토타입: 양쪽이 같은 코드라 동작·크기·시간 측정엔 충분. 실제 이더리움 통합 시엔 KDF/MAC을 Keccak-256으로.)
 */
@SuppressWarnings("all")
public class XWingHandshakeBaselineTest {

  private static final byte[] LABEL = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}; // X-Wing 라벨
  private static final SecureRandom RNG = new SecureRandom();

  @Test
  public void measureXWingHandshake() throws Exception {
    // 개시자(A)·응답자(B)의 장기 X-Wing 키를 1회 생성 후 재사용
    XWing initiator = XWing.generate();
    XWing responder = XWing.generate();

    // (1) 크기 측정: 한 번 왕복
    int[] sizes = runHandshake(initiator, responder);
    System.out.println("=== X-Wing 핸드셰이크 (측정) ===");
    System.out.println("Auth 메시지 크기 : " + sizes[0] + " bytes");
    System.out.println("ACK  메시지 크기 : " + sizes[1] + " bytes");
    System.out.println("Conf 메시지 크기 : " + sizes[2] + " bytes");
    System.out.println("총 크기          : " + (sizes[0] + sizes[1] + sizes[2]) + " bytes (3 메시지)");

    // (2) 시간 측정
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

  /** 핸드셰이크 1회. 반환값 = {Auth크기, ACK크기, Conf크기} */
  private int[] runHandshake(XWing initiator, XWing responder) throws Exception {
    // === 개시자 A: Auth 생성 ===
    XWing eph = XWing.generate();          // 임시 X-Wing 키 (전방향 비밀성)
    byte[] nI = random32();
    Enc encR = encap(responder);           // K_R, CT_R : 응답자 정적키로 캡슐화(=응답자 인증)
    int authSize = initiator.pubBytes().length + eph.pubBytes().length + encR.ct.length + nI.length;

    // === 응답자 B: Auth 처리 → ACK 생성 ===
    byte[] kR = decap(encR.ct, responder); // 응답자가 CT_R 복호 (== encR.ss)
    Enc encI = encap(initiator);           // K_I, CT_I : 개시자 정적키로 캡슐화(=개시자 인증)
    Enc encE = encap(eph);                 // K_E, CT_E : 개시자 임시키로 캡슐화(=전방향 비밀성)
    byte[] nR = random32();
    byte[] kEphB = sha3(concat(encI.ss, kR, encE.ss));      // K_eph = SHA3(K_I||K_R||K_E)
    byte[] kConfB = sha3(concat("conf".getBytes(), kEphB)); // 확인키(전체 비밀에서 유도)
    byte[] tagR = hmac(kConfB, concat(nI, nR));             // 응답자 키확인 태그
    int ackSize = encI.ct.length + encE.ct.length + tagR.length + nR.length;

    // === 개시자 A: ACK 처리 → 세션키/확인 → Conf 생성 ===
    byte[] kI = decap(encI.ct, initiator); // == encI.ss
    byte[] kE = decap(encE.ct, eph);       // == encE.ss
    byte[] kEphA = sha3(concat(kI, encR.ss, kE));           // A가 계산한 K_eph (encR.ss==K_R)
    byte[] kConfA = sha3(concat("conf".getBytes(), kEphA));
    byte[] tagRcheck = hmac(kConfA, concat(nI, nR));
    if (!Arrays.equals(tagRcheck, tagR)) {
      throw new IllegalStateException("tag_R 검증 실패");
    }
    byte[] tagI = hmac(kConfA, concat(nR, nI));             // 개시자 확인 태그
    int confSize = tagI.length;

    // === 응답자 B: Conf 검증 ===
    byte[] tagIcheck = hmac(kConfB, concat(nR, nI));
    if (!Arrays.equals(tagIcheck, tagI)) {
      throw new IllegalStateException("tag_I 검증 실패");
    }
    // 양측 세션키(K_eph) 일치 확인
    if (!Arrays.equals(kEphA, kEphB)) {
      throw new IllegalStateException("세션키 불일치");
    }
    return new int[] {authSize, ackSize, confSize};
  }

  // ===================== X-Wing 암호 =====================

  /** X-Wing 키쌍 = ML-KEM-768 키쌍 + X25519 키쌍 */
  static final class XWing {
    final KeyPair mlkem;
    final KeyPair x25519;

    XWing(KeyPair m, KeyPair x) {
      mlkem = m;
      x25519 = x;
    }

    static XWing generate() throws Exception {
      return new XWing(
          KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair(),
          KeyPairGenerator.getInstance("X25519").generateKeyPair());
    }

    /** 전송용 공개키 직렬화(크기 측정용): ML-KEM ek(1184) + X25519 pub(32) = 1216 */
    byte[] pubBytes() {
      byte[] ek = mlkem.getPublic().getEncoded();
      byte[] ekRaw = Arrays.copyOfRange(ek, ek.length - 1184, ek.length);
      return concat(ekRaw, rawX(x25519.getPublic()));
    }
  }

  static final class Enc {
    final byte[] ct; // ML-KEM ct(1088) + X25519 임시공개키(32) = 1120
    final byte[] ss; // 32

    Enc(byte[] c, byte[] s) {
      ct = c;
      ss = s;
    }
  }

  /** 상대 X-Wing 공개키로 캡슐화 */
  static Enc encap(XWing peer) throws Exception {
    KEM kem = KEM.getInstance("ML-KEM-768");
    KEM.Encapsulated e = kem.newEncapsulator(peer.mlkem.getPublic()).encapsulate();
    byte[] ctM = e.encapsulation();
    byte[] ssM = e.key().getEncoded();

    KeyPair ephX = KeyPairGenerator.getInstance("X25519").generateKeyPair();
    byte[] ctX = rawX(ephX.getPublic());
    byte[] ssX = dh(ephX.getPrivate(), peer.x25519.getPublic());
    byte[] pkX = rawX(peer.x25519.getPublic());

    byte[] ss = sha3(concat(ssM, ssX, ctX, pkX, LABEL));
    return new Enc(concat(ctM, ctX), ss);
  }

  /** 내 X-Wing 개인키로 복호 */
  static byte[] decap(byte[] ct, XWing me) throws Exception {
    byte[] ctM = Arrays.copyOfRange(ct, 0, ct.length - 32);
    byte[] ctX = Arrays.copyOfRange(ct, ct.length - 32, ct.length);

    KEM kem = KEM.getInstance("ML-KEM-768");
    SecretKey ssMk = kem.newDecapsulator(me.mlkem.getPrivate()).decapsulate(ctM);
    byte[] ssM = ssMk.getEncoded();

    byte[] ssX = dh(me.x25519.getPrivate(), pubFromRaw(ctX));
    byte[] pkX = rawX(me.x25519.getPublic());
    return sha3(concat(ssM, ssX, ctX, pkX, LABEL));
  }

  // ===================== 헬퍼 =====================

  static byte[] dh(PrivateKey myPriv, PublicKey peerPub) throws Exception {
    KeyAgreement ka = KeyAgreement.getInstance("X25519");
    ka.init(myPriv);
    ka.doPhase(peerPub, true);
    return ka.generateSecret();
  }

  static byte[] rawX(PublicKey pk) {
    byte[] enc = pk.getEncoded();
    return Arrays.copyOfRange(enc, enc.length - 32, enc.length);
  }

  static PublicKey pubFromRaw(byte[] raw32) throws Exception {
    byte[] le = raw32.clone();
    le[31] &= 0x7f;
    byte[] be = new byte[32];
    for (int i = 0; i < 32; i++) {
      be[i] = le[31 - i];
    }
    BigInteger u = new BigInteger(1, be);
    return KeyFactory.getInstance("X25519")
        .generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, u));
  }

  static byte[] sha3(byte[] in) throws Exception {
    return MessageDigest.getInstance("SHA3-256").digest(in);
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
