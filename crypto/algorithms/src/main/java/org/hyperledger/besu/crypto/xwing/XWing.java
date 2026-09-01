/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.crypto.xwing;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hyperledger.besu.crypto.MessageDigestFactory;
import org.hyperledger.besu.crypto.SecureRandomProvider;

/**
 * X-Wing hybrid KEM (ML-KEM-768 + X25519), following draft-connolly-cfrg-xwing-kem.
 *
 * <p>이 클래스는 "무엇"을 하나? — 두 개의 키교환을 하나로 합친 하이브리드 KEM이다.
 *
 * <ul>
 *   <li>ML-KEM-768 : 양자내성 격자 기반 KEM (BouncyCastle 구현 사용)
 *   <li>X25519 : 고전 타원곡선 DH (BouncyCastle 구현 사용)
 *   <li>combiner : ss = SHA3-256(ss_MLKEM || ss_X25519 || ct_X25519 || pk_X25519 || label)
 * </ul>
 *
 * <p>"무슨 도구로?" — 순수 자바 + BouncyCastle provider("BC"). Besu가 이미 번들한 라이브러리라 추가
 * 의존성이 없다. 해시는 JDK 표준 SHA3-256(드래프트 규정).
 *
 * <p>배치: crypto 모듈의 재사용 가능한 암호 primitive(SECP256K1 과 동급). 핸드셰이크 프로토콜
 * (XWingHandshaker)은 ethereum/p2p 쪽에서 이 primitive 를 사용한다.
 *
 * <p>신원 모델(컨소시엄): enode/nodeId 등 노드 신원은 기존 secp256k1을 유지하고, 이 X-Wing 정적
 * 공개키는 컨소시엄 주소록으로 사전 배포(PDK)해 전송계층 핸드셰이크에만 쓴다.
 */
public final class XWing {

  /** X-Wing combiner 라벨(드래프트 §5.3): 바이트열 5c 2e 2f 2f 5e 5c. */
  private static final byte[] LABEL = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c};

  /** 전송용 공개키 길이 = ML-KEM ek(1184) + X25519 pub(32). */
  public static final int PUBLIC_KEY_BYTES = 1216;

  /** 전송용 암호문 길이 = ML-KEM ct(1088) + X25519 임시공개키(32). */
  public static final int CIPHERTEXT_BYTES = 1120;

  /** 공유비밀 길이. */
  public static final int SHARED_SECRET_BYTES = 32;

  private static final int MLKEM_EK_BYTES = 1184; // ML-KEM-768 공개키(ek) 원시 길이
  private static final int MLKEM_CT_BYTES = 1088; // ML-KEM-768 암호문 원시 길이
  private static final int X25519_RAW_BYTES = 32; // X25519 공개키 원시 길이

  private static final SecureRandom RNG = SecureRandomProvider.publicSecureRandom();

  // BouncyCastle의 ML-KEM/X25519 공개키는 SPKI(X.509)로 감싸여 나온다. 원시 바이트만 전송했다가
  // 다시 키 객체로 복원할 때 붙일 "SPKI 헤더"를 런타임에 1회 추출해 둔다(하드코딩 대신 → provider가
  // 어떤 인코딩을 쓰든 항상 정확히 일치).
  private static final byte[] MLKEM_SPKI_PREFIX;
  private static final byte[] X25519_SPKI_PREFIX;

  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    try {
      byte[] mlkemEncoded = newMlKemGenerator().generateKeyPair().getPublic().getEncoded();
      MLKEM_SPKI_PREFIX = Arrays.copyOfRange(mlkemEncoded, 0, mlkemEncoded.length - MLKEM_EK_BYTES);
      byte[] xEncoded = newX25519Generator().generateKeyPair().getPublic().getEncoded();
      X25519_SPKI_PREFIX = Arrays.copyOfRange(xEncoded, 0, xEncoded.length - X25519_RAW_BYTES);
    } catch (final Exception e) {
      throw new IllegalStateException("X-Wing 초기화 실패(ML-KEM/X25519 provider 확인)", e);
    }
  }

  private XWing() {}

  /** X-Wing 키쌍: ML-KEM 키쌍 + X25519 키쌍을 함께 보관. */
  public static final class KeyPair {
    private final java.security.KeyPair mlkem;
    private final java.security.KeyPair x25519;

    private KeyPair(final java.security.KeyPair mlkem, final java.security.KeyPair x25519) {
      this.mlkem = mlkem;
      this.x25519 = x25519;
    }

    /** 상대에게 배포할 전송용 공개키(1216B) = ek(1184) || x25519 pub(32). */
    public byte[] encodedPublicKey() {
      final byte[] ek = mlkem.getPublic().getEncoded();
      final byte[] ekRaw = Arrays.copyOfRange(ek, ek.length - MLKEM_EK_BYTES, ek.length);
      return concat(ekRaw, rawX25519(x25519.getPublic()));
    }
  }

  /** 캡슐화 결과: 전송용 암호문(1120B) + 공유비밀(32B). */
  public static final class Encapsulation {
    private final byte[] ciphertext;
    private final byte[] sharedSecret;

    private Encapsulation(final byte[] ciphertext, final byte[] sharedSecret) {
      this.ciphertext = ciphertext;
      this.sharedSecret = sharedSecret;
    }

    /** 전송할 암호문(1120B). */
    public byte[] ciphertext() {
      return ciphertext;
    }

    /** 도출된 공유비밀(32B). */
    public byte[] sharedSecret() {
      return sharedSecret;
    }
  }

  /** 새 X-Wing 키쌍 생성. */
  public static KeyPair generateKeyPair() {
    try {
      return new KeyPair(
          newMlKemGenerator().generateKeyPair(), newX25519Generator().generateKeyPair());
    } catch (final Exception e) {
      throw new IllegalStateException("X-Wing 키 생성 실패", e);
    }
  }

  /**
   * 상대의 전송용 공개키(1216B)로 캡슐화.
   *
   * @param peerPublicKey 상대 X-Wing 공개키(1216B). 주소록에서 로드.
   * @return 암호문(1120B) + 공유비밀(32B)
   */
  public static Encapsulation encapsulate(final byte[] peerPublicKey) {
    if (peerPublicKey.length != PUBLIC_KEY_BYTES) {
      throw new IllegalArgumentException("공개키 길이 오류: " + peerPublicKey.length);
    }
    try {
      final PublicKey peerMlkem = mlkemPublicFromRaw(head(peerPublicKey, MLKEM_EK_BYTES));
      final PublicKey peerX25519 = x25519PublicFromRaw(tail(peerPublicKey, X25519_RAW_BYTES));

      // (1) ML-KEM 캡슐화 (BC): KeyGenerator + KEMGenerateSpec 이 BC의 캡슐화 통로
      final KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", "BC");
      kg.init(new KEMGenerateSpec(peerMlkem, "Secret"), RNG);
      final SecretKeyWithEncapsulation e = (SecretKeyWithEncapsulation) kg.generateKey();
      final byte[] ctM = e.getEncapsulation(); // 1088
      final byte[] ssM = e.getEncoded(); // 32

      // (2) X25519: 임시 키쌍 생성 후 DH
      final java.security.KeyPair ephX = newX25519Generator().generateKeyPair();
      final byte[] ctX = rawX25519(ephX.getPublic()); // 32
      final byte[] ssX = dh(ephX.getPrivate(), peerX25519); // 32
      final byte[] pkX = rawX25519(peerX25519); // 32

      // (3) SHA3-256 combiner
      final byte[] ss = sha3(concat(ssM, ssX, ctX, pkX, LABEL));
      return new Encapsulation(concat(ctM, ctX), ss);
    } catch (final Exception e) {
      throw new IllegalStateException("X-Wing 캡슐화 실패", e);
    }
  }

  /**
   * 내 개인키로 암호문(1120B)을 복호해 공유비밀(32B)을 얻는다.
   *
   * @param ciphertext 상대가 보낸 암호문(1120B)
   * @param myKeys 내 X-Wing 키쌍
   * @return 공유비밀(32B) — encapsulate 가 만든 값과 동일
   */
  public static byte[] decapsulate(final byte[] ciphertext, final KeyPair myKeys) {
    if (ciphertext.length != CIPHERTEXT_BYTES) {
      throw new IllegalArgumentException("암호문 길이 오류: " + ciphertext.length);
    }
    try {
      final byte[] ctM = head(ciphertext, MLKEM_CT_BYTES); // ML-KEM ct
      final byte[] ctX = tail(ciphertext, X25519_RAW_BYTES); // 임시 X25519 공개키

      // (1) ML-KEM 복호 (BC): KeyGenerator + KEMExtractSpec
      final KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", "BC");
      kg.init(new KEMExtractSpec(myKeys.mlkem.getPrivate(), ctM, "Secret"));
      final SecretKeyWithEncapsulation d = (SecretKeyWithEncapsulation) kg.generateKey();
      final byte[] ssM = d.getEncoded();

      // (2) X25519 DH (내 개인키 × 상대 임시공개키)
      final byte[] ssX = dh(myKeys.x25519.getPrivate(), x25519PublicFromRaw(ctX));
      final byte[] pkX = rawX25519(myKeys.x25519.getPublic());

      // (3) 같은 combiner
      return sha3(concat(ssM, ssX, ctX, pkX, LABEL));
    } catch (final Exception e) {
      throw new IllegalStateException("X-Wing 복호 실패", e);
    }
  }

  // ===================== 내부 헬퍼 =====================

  private static KeyPairGeneratorHolder newMlKemGenerator() throws Exception {
    final KeyPairGenerator g = KeyPairGenerator.getInstance("ML-KEM", "BC");
    g.initialize(MLKEMParameterSpec.ml_kem_768, RNG);
    return new KeyPairGeneratorHolder(g);
  }

  private static KeyPairGeneratorHolder newX25519Generator() throws Exception {
    return new KeyPairGeneratorHolder(KeyPairGenerator.getInstance("X25519", "BC"));
  }

  /** KeyPairGenerator 를 얇게 감싼 홀더(제네릭 호출부를 단순화하기 위함). */
  private static final class KeyPairGeneratorHolder {
    private final KeyPairGenerator generator;

    private KeyPairGeneratorHolder(final KeyPairGenerator generator) {
      this.generator = generator;
    }

    private java.security.KeyPair generateKeyPair() {
      return generator.generateKeyPair();
    }
  }

  private static byte[] dh(final PrivateKey myPriv, final PublicKey peerPub) throws Exception {
    final KeyAgreement ka = KeyAgreement.getInstance("X25519", "BC");
    ka.init(myPriv);
    ka.doPhase(peerPub, true);
    return ka.generateSecret();
  }

  private static byte[] rawX25519(final PublicKey pk) {
    final byte[] enc = pk.getEncoded();
    return Arrays.copyOfRange(enc, enc.length - X25519_RAW_BYTES, enc.length);
  }

  private static PublicKey x25519PublicFromRaw(final byte[] raw32) throws Exception {
    final byte[] spki = concat(X25519_SPKI_PREFIX, raw32);
    return KeyFactory.getInstance("X25519", "BC").generatePublic(new X509EncodedKeySpec(spki));
  }

  private static PublicKey mlkemPublicFromRaw(final byte[] ek1184) throws Exception {
    final byte[] spki = concat(MLKEM_SPKI_PREFIX, ek1184);
    return KeyFactory.getInstance("ML-KEM", "BC").generatePublic(new X509EncodedKeySpec(spki));
  }

  private static byte[] sha3(final byte[] in) throws Exception {
    return MessageDigestFactory.create("SHA3-256").digest(in);
  }

  private static byte[] head(final byte[] a, final int n) {
    return Arrays.copyOfRange(a, 0, n);
  }

  private static byte[] tail(final byte[] a, final int n) {
    return Arrays.copyOfRange(a, a.length - n, a.length);
  }

  private static byte[] concat(final byte[]... parts) {
    int len = 0;
    for (final byte[] p : parts) {
      len += p.length;
    }
    final byte[] out = new byte[len];
    int off = 0;
    for (final byte[] p : parts) {
      System.arraycopy(p, 0, out, off, p.length);
      off += p.length;
    }
    return out;
  }
}
