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
package org.hyperledger.besu.ethereum.p2p.rlpx.handshake.xwing;

import static org.hyperledger.besu.crypto.Hash.keccak256;

import org.hyperledger.besu.crypto.SECPPublicKey;
import org.hyperledger.besu.crypto.SecureRandomProvider;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.xwing.XWing;
import org.hyperledger.besu.cryptoservices.NodeKey;
import org.hyperledger.besu.ethereum.p2p.rlpx.handshake.HandshakeException;
import org.hyperledger.besu.ethereum.p2p.rlpx.handshake.HandshakeSecrets;
import org.hyperledger.besu.ethereum.p2p.rlpx.handshake.Handshaker;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;

import java.security.SecureRandom;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Post-quantum RLPx handshaker based on the X-Wing hybrid KEM (ML-KEM-768 + X25519).
 *
 * <p>이 클래스는 "무엇"을 하나? — 기존 {@code ECIESHandshaker}(secp256k1 ECIES)를 대체하는, X-Wing
 * 기반의 3-메시지 명시적 AKE(Ethereum Research Protocol 2의 허가형 컨소시엄 변형) 핸드셰이커다.
 * 핸드셰이크 이후 계층(Framer/Hello/eth 등)은 기존 Besu 코드를 그대로 재사용하도록, 결과를 동일한
 * {@link HandshakeSecrets}(aes/mac/token + egress/ingress Keccak MAC)로 만들어 낸다.
 *
 * <p>메시지 흐름 (개시자 I ↔ 응답자 R):
 *
 * <pre>
 *   Auth (I→R) = [ secp_I(64) , XWpk_I(1216) , XWpk_eph(1216) , CT_R(1120) , n_I(32) ]
 *   ACK  (R→I) = [ CT_I(1120) , CT_E(1120) , tag_R(32) , n_R(32) ]
 *   Conf (I→R) = [ tag_I(32) ]
 * </pre>
 *
 * <p>키 재료: K_R=Encap(XWpk_R)(응답자 인증), K_I=Encap(XWpk_I)(개시자 인증),
 * K_E=Encap(XWpk_eph)(전방향 비밀성). K_eph = Keccak256(K_I ‖ K_R ‖ K_E).
 *
 * <p>신원 모델(컨소시엄 PDK): 노드 신원은 기존 secp256k1 유지. 개시자는 상대(응답자)의 X-Wing 정적
 * 공개키를 nodeId→X-Wing pk 주소록({@code peerStaticXWingByNodeId})에서 조회한다. 응답자는 개시자의
 * X-Wing 정적 공개키를 Auth에서 받는다(주소록과의 일치 검증=신원 바인딩은 Phase 4 하드닝).
 *
 * <p>참고: KDF/MAC은 이더리움 스택에 맞춰 Keccak-256 사용. combiner(SHA3-256)는 {@link XWing}
 * primitive 내부 규정을 따른다.
 */
public class XWingHandshaker implements Handshaker {

  private static final int SECP_PUBKEY_BYTES = 64;
  private static final int NONCE_BYTES = 32;
  private static final SecureRandom RANDOM = SecureRandomProvider.publicSecureRandom();

  // 도메인 분리 라벨 (KDF/태그 유도용)
  private static final Bytes L_AES = Bytes.of('x', 'w', 'a', 'e', 's');
  private static final Bytes L_MAC = Bytes.of('x', 'w', 'm', 'a', 'c');
  private static final Bytes L_TOK = Bytes.of('x', 'w', 't', 'o', 'k');
  private static final Bytes L_TAGR = Bytes.of('x', 'w', 't', 'a', 'g', 'R');
  private static final Bytes L_TAGI = Bytes.of('x', 'w', 't', 'a', 'g', 'I');

  private final AtomicReference<HandshakeStatus> status =
      new AtomicReference<>(HandshakeStatus.UNINITIALIZED);
  private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithmFactory.getInstance();

  // 우리 정적 X-Wing 키 + (nodeId→상대 X-Wing pk) 주소록
  private final XWing.KeyPair localStatic;
  private final Function<Bytes, byte[]> peerStaticXWingByNodeId;

  private boolean initiator;
  private NodeKey nodeKey; // 우리 secp 신원
  private SECPPublicKey partyPubKey; // 상대 secp 신원

  // 개시자 전용
  private byte[] peerStaticXWingPub; // 응답자 정적 X-Wing pk (주소록 조회)
  private XWing.KeyPair eph; // 임시 X-Wing 키

  // 공통 상태
  private byte[] nI;
  private byte[] nR;
  private byte[] kR; // 응답자 정적으로의 공유비밀
  private int responderStep; // 응답자: 0=Auth 대기, 1=Conf 대기
  private byte[] expectedTagI; // 응답자: Conf 검증용 기대 tag_I (ACK 생성 시 미리 계산)
  private HandshakeSecrets secrets;

  /**
   * @param localStatic 우리 노드의 X-Wing 정적 키쌍
   * @param peerStaticXWingByNodeId secp nodeId(64B 인코딩)→상대 X-Wing 정적 공개키(1216B) 조회 함수
   *     (컨소시엄 PDK 주소록). 개시자가 응답자 공개키를 얻는 데 사용.
   */
  public XWingHandshaker(
      final XWing.KeyPair localStatic, final Function<Bytes, byte[]> peerStaticXWingByNodeId) {
    this.localStatic = localStatic;
    this.peerStaticXWingByNodeId = peerStaticXWingByNodeId;
  }

  @Override
  public void prepareInitiator(final NodeKey nodeKey, final SECPPublicKey theirPubKey) {
    if (!status.compareAndSet(HandshakeStatus.UNINITIALIZED, HandshakeStatus.PREPARED)) {
      throw new IllegalStateException("handshake was already prepared");
    }
    this.initiator = true;
    this.nodeKey = nodeKey;
    this.partyPubKey = theirPubKey;
    this.peerStaticXWingPub = peerStaticXWingByNodeId.apply(theirPubKey.getEncodedBytes());
    if (this.peerStaticXWingPub == null) {
      status.set(HandshakeStatus.FAILED);
      throw new IllegalStateException("no X-Wing public key in address book for peer");
    }
    this.eph = XWing.generateKeyPair();
    this.nI = random(NONCE_BYTES);
  }

  @Override
  public void prepareResponder(final NodeKey nodeKey) {
    if (!status.compareAndSet(HandshakeStatus.UNINITIALIZED, HandshakeStatus.IN_PROGRESS)) {
      throw new IllegalStateException("handshake was already prepared");
    }
    this.initiator = false;
    this.nodeKey = nodeKey;
    this.nR = random(NONCE_BYTES);
    this.responderStep = 0;
  }

  @Override
  public ByteBuf firstMessage() throws HandshakeException {
    if (!initiator) {
      throw new IllegalStateException("only the initiator may send the first message");
    }
    if (!status.compareAndSet(HandshakeStatus.PREPARED, HandshakeStatus.IN_PROGRESS)) {
      throw new IllegalStateException("firstMessage called at an illegal time");
    }
    try {
      final XWing.Encapsulation encR = XWing.encapsulate(peerStaticXWingPub);
      this.kR = encR.sharedSecret();

      final BytesValueRLPOutput out = new BytesValueRLPOutput();
      out.startList();
      out.writeBytes(nodeKey.getPublicKey().getEncodedBytes()); // secp_I (신원)
      out.writeBytes(Bytes.wrap(localStatic.encodedPublicKey())); // XWpk_I
      out.writeBytes(Bytes.wrap(eph.encodedPublicKey())); // XWpk_eph
      out.writeBytes(Bytes.wrap(encR.ciphertext())); // CT_R
      out.writeBytes(Bytes.wrap(nI)); // n_I
      out.endList();
      return Unpooled.wrappedBuffer(out.encoded().toArrayUnsafe());
    } catch (final RuntimeException e) {
      status.set(HandshakeStatus.FAILED);
      throw new HandshakeException("failed to build X-Wing Auth message", e);
    }
  }

  @Override
  public Optional<ByteBuf> handleMessage(final ByteBuf buf) throws HandshakeException {
    if (status.get() != HandshakeStatus.IN_PROGRESS) {
      throw new IllegalStateException("handshake is not in progress");
    }
    final byte[] raw = new byte[buf.readableBytes()];
    buf.readBytes(raw);
    try {
      if (initiator) {
        return handleAckAndBuildConf(raw);
      } else if (responderStep == 0) {
        return Optional.of(handleAuthAndBuildAck(raw));
      } else {
        handleConf(raw);
        return Optional.empty();
      }
    } catch (final HandshakeException e) {
      status.set(HandshakeStatus.FAILED);
      throw e;
    } catch (final RuntimeException e) {
      status.set(HandshakeStatus.FAILED);
      throw new HandshakeException("X-Wing handshake message processing failed", e);
    }
  }

  /** 응답자: Auth 수신 → K_R/K_I/K_E 도출 → ACK 생성. */
  private ByteBuf handleAuthAndBuildAck(final byte[] authBytes) throws HandshakeException {
    final RLPInput in = RLP.input(Bytes.wrap(authBytes));
    in.enterList();
    final byte[] secpI = in.readBytes().toArrayUnsafe();
    final byte[] xwPkI = in.readBytes().toArrayUnsafe();
    final byte[] xwPkEph = in.readBytes().toArrayUnsafe();
    final byte[] ctRIn = in.readBytes().toArrayUnsafe();
    this.nI = in.readBytes().toArrayUnsafe();
    in.leaveList();

    if (secpI.length != SECP_PUBKEY_BYTES) {
      throw new HandshakeException("bad initiator secp key length");
    }
    this.partyPubKey = signatureAlgorithm.createPublicKey(Bytes.wrap(secpI));

    this.kR = XWing.decapsulate(ctRIn, localStatic); // == 개시자의 encR.ss
    final XWing.Encapsulation encI = XWing.encapsulate(xwPkI); // K_I, CT_I
    final XWing.Encapsulation encE = XWing.encapsulate(xwPkEph); // K_E, CT_E

    final byte[] kEph = kEph(encI.sharedSecret(), kR, encE.sharedSecret());
    deriveSecrets(kEph);
    final byte[] tagR = tag(kEph, L_TAGR);

    final BytesValueRLPOutput out = new BytesValueRLPOutput();
    out.startList();
    out.writeBytes(Bytes.wrap(encI.ciphertext())); // CT_I
    out.writeBytes(Bytes.wrap(encE.ciphertext())); // CT_E
    out.writeBytes(Bytes.wrap(tagR)); // tag_R
    out.writeBytes(Bytes.wrap(nR)); // n_R
    out.endList();

    this.responderStep = 1; // 이제 Conf 대기
    return Unpooled.wrappedBuffer(out.encoded().toArrayUnsafe());
  }

  /** 개시자: ACK 수신 → K_I/K_E 복호 → tag_R 검증 → Conf 생성 → SUCCESS. */
  private Optional<ByteBuf> handleAckAndBuildConf(final byte[] ackBytes) throws HandshakeException {
    final RLPInput in = RLP.input(Bytes.wrap(ackBytes));
    in.enterList();
    final byte[] ctI = in.readBytes().toArrayUnsafe();
    final byte[] ctE = in.readBytes().toArrayUnsafe();
    final byte[] tagRIn = in.readBytes().toArrayUnsafe();
    this.nR = in.readBytes().toArrayUnsafe();
    in.leaveList();

    final byte[] kI = XWing.decapsulate(ctI, localStatic);
    final byte[] kE = XWing.decapsulate(ctE, eph);

    final byte[] kEph = kEph(kI, kR, kE);
    deriveSecrets(kEph);

    final byte[] tagRExpect = tag(kEph, L_TAGR);
    if (!constantTimeEquals(tagRExpect, tagRIn)) {
      throw new HandshakeException("responder key-confirmation tag_R mismatch");
    }
    final byte[] tagI = tag(kEph, L_TAGI);

    final BytesValueRLPOutput out = new BytesValueRLPOutput();
    out.startList();
    out.writeBytes(Bytes.wrap(tagI)); // tag_I
    out.endList();

    status.set(HandshakeStatus.SUCCESS);
    return Optional.of(Unpooled.wrappedBuffer(out.encoded().toArrayUnsafe()));
  }

  /** 응답자: Conf 수신 → tag_I 검증 → SUCCESS. */
  private void handleConf(final byte[] confBytes) throws HandshakeException {
    final RLPInput in = RLP.input(Bytes.wrap(confBytes));
    in.enterList();
    final byte[] tagIIn = in.readBytes().toArrayUnsafe();
    in.leaveList();

    // expectedTagI 는 ACK 생성 시(deriveSecrets) 미리 계산해 두었다.
    if (!constantTimeEquals(expectedTagI, tagIIn)) {
      throw new HandshakeException("initiator key-confirmation tag_I mismatch");
    }
    status.set(HandshakeStatus.SUCCESS);
  }

  private byte[] kEph(final byte[] ssI, final byte[] ssR, final byte[] ssE) {
    return keccak256(Bytes.concatenate(Bytes.wrap(ssI), Bytes.wrap(ssR), Bytes.wrap(ssE)))
        .toArray();
  }

  private byte[] tag(final byte[] kEph, final Bytes label) {
    return keccak256(
            Bytes.concatenate(Bytes.wrap(kEph), label, Bytes.wrap(nI), Bytes.wrap(nR)))
        .toArray();
  }

  /** K_eph + 논스에서 aes/mac/token 및 egress/ingress MAC 시드를 만들어 HandshakeSecrets 구성. */
  private void deriveSecrets(final byte[] kEph) {
    final Bytes kEphB = Bytes.wrap(kEph);
    final Bytes s = keccak256(Bytes.concatenate(kEphB, Bytes.wrap(nI), Bytes.wrap(nR)));
    final Bytes32 aes = keccak256(Bytes.concatenate(kEphB, s, L_AES));
    final Bytes32 mac = keccak256(Bytes.concatenate(kEphB, s, L_MAC));
    final Bytes32 token = keccak256(Bytes.concatenate(s, L_TOK));

    final HandshakeSecrets hs = new HandshakeSecrets(aes.toArray(), mac.toArray(), token.toArray());

    // egress/ingress 시드: 양측이 거울처럼 맞도록 (initiator.egress == responder.ingress 등)
    final Bytes32 seedNi = mac.xor(pad32(nI));
    final Bytes32 seedNr = mac.xor(pad32(nR));
    if (initiator) {
      hs.updateEgress(seedNr.toArray());
      hs.updateIngress(seedNi.toArray());
    } else {
      hs.updateEgress(seedNi.toArray());
      hs.updateIngress(seedNr.toArray());
    }
    this.secrets = hs;

    // 응답자는 Conf 검증용 tag_I 기대값을 지금 계산해 둔다.
    if (!initiator) {
      this.expectedTagI = tag(kEph, L_TAGI);
    }
  }

  private static Bytes32 pad32(final byte[] n) {
    return Bytes32.leftPad(Bytes.wrap(n));
  }

  @Override
  public HandshakeStatus getStatus() {
    return status.get();
  }

  @Override
  public HandshakeSecrets secrets() {
    if (status.get() != HandshakeStatus.SUCCESS) {
      throw new IllegalStateException("cannot obtain secrets from an unsuccessful handshake");
    }
    return secrets;
  }

  @Override
  public SECPPublicKey partyPubKey() {
    if (!initiator && status.get() != HandshakeStatus.SUCCESS) {
      throw new IllegalStateException(
          "under the responder role, party public key is unavailable until success");
    }
    return partyPubKey;
  }

  private static byte[] random(final int size) {
    final byte[] b = new byte[size];
    RANDOM.nextBytes(b);
    return b;
  }

  private static boolean constantTimeEquals(final byte[] a, final byte[] b) {
    if (a.length != b.length) {
      return false;
    }
    int r = 0;
    for (int i = 0; i < a.length; i++) {
      r |= a[i] ^ b[i];
    }
    return r == 0;
  }
}
