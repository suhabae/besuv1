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
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 *   Auth (I→R) = [ XWpk_I(1216) , XWpk_eph(1216) , CT_R(1120) , n_I(32) ]
 *   ACK  (R→I) = [ CT_I(1120) , CT_E(1120) , tag_R(32) , n_R(32) ]
 *   Conf (I→R) = [ tag_I(32) ]
 * </pre>
 *
 * <p>키 재료: K_R=Encap(XWpk_R)(응답자 인증), K_I=Encap(XWpk_I)(개시자 인증),
 * K_E=Encap(XWpk_eph)(전방향 비밀성). K_eph = Keccak256(K_I ‖ K_R ‖ K_E).
 *
 * <p>신원 모델(컨소시엄 PDK): 노드 신원은 기존 secp256k1(nodeId) 유지. 개시자는 상대(응답자)의 X-Wing
 * 정적 공개키를 nodeId→X-Wing pk 주소록({@code peerStaticXWingByNodeId})에서 조회한다. 응답자는 Auth의
 * 개시자 X-Wing 공개키를 X-Wing pk→nodeId 역주소록({@code nodeIdByPeerStaticXWing})으로 역조회해
 * 개시자 신원(nodeId)을 확정한다. 주소록에 없는 키면 거절 → 신원 바인딩이 성립하므로 Auth에 secp
 * nodeId를 별도로 실을 필요가 없다(등록된 멤버만 통과).
 *
 * <p>참고: KDF/MAC은 이더리움 스택에 맞춰 Keccak-256 사용. combiner(SHA3-256)는 {@link XWing}
 * primitive 내부 규정을 따른다.
 */
public class XWingHandshaker implements Handshaker {

  private static final Logger LOG = LoggerFactory.getLogger(XWingHandshaker.class);

  private static final int SECP_PUBKEY_BYTES = 64;
  private static final int NONCE_BYTES = 32;
  private static final SecureRandom RANDOM = SecureRandomProvider.publicSecureRandom();

  // [transport framing] 각 핸드셰이크 패킷(Auth/ACK/Conf)은 on-wire 에서 "2바이트 big-endian
  // 길이 접두어 ‖ 본문" 형태로 나간다. 이는 RLPx/EIP-8 이 handshake packet 크기를 2바이트 헤더로
  // 붙이는 관례를 그대로 따른 것이다(암호 봉투는 ECIES 가 아닌 KEM 기반으로 다름). TCP 는 메시지
  // 경계를 보존하지 않으므로, 수신 측은 이 길이만큼 바이트가 다 모일 때까지 누적한 뒤 파싱한다.
  private static final int LENGTH_PREFIX_BYTES = 2;
  private static final int MAX_FRAME_BODY = 0xFFFF; // 2바이트 길이의 최대(65535B)

  // 수신 누적 버퍼: 완전한 프레임 1개가 모일 때까지 조각을 이어붙인다.
  private byte[] inbound = new byte[0];
  private int inboundReadCount; // 관측용: 한 프레임을 모으는 데 걸린 read 횟수

  // 도메인 분리 라벨 (KDF/태그 유도용)
  private static final Bytes L_AES = Bytes.of('x', 'w', 'a', 'e', 's');
  private static final Bytes L_MAC = Bytes.of('x', 'w', 'm', 'a', 'c');
  private static final Bytes L_TOK = Bytes.of('x', 'w', 't', 'o', 'k');
  private static final Bytes L_TAGR = Bytes.of('x', 'w', 't', 'a', 'g', 'R');
  private static final Bytes L_TAGI = Bytes.of('x', 'w', 't', 'a', 'g', 'I');

  private final AtomicReference<HandshakeStatus> status =
      new AtomicReference<>(HandshakeStatus.UNINITIALIZED);
  private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithmFactory.getInstance();

  // 우리 정적 X-Wing 키 + 주소록(양방향)
  private final XWing.KeyPair localStatic;
  private final Function<Bytes, byte[]> peerStaticXWingByNodeId; // nodeId → 상대 X-Wing pk (개시자용)
  private final Function<Bytes, Bytes> nodeIdByPeerStaticXWing; // 상대 X-Wing pk → nodeId (응답자용)

  private boolean initiator;
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
   * @param nodeIdByPeerStaticXWing 상대 X-Wing 정적 공개키(1216B)→secp nodeId(64B) 역조회 함수.
   *     응답자가 Auth의 X-Wing 공개키로 개시자의 신원(nodeId)을 확정하는 데 사용. 없으면(주소록 미등록)
   *     null 반환 → 응답자는 연결을 거절한다(신원 바인딩). 이로써 Auth에 secp nodeId를 실을 필요가 없다.
   */
  public XWingHandshaker(
      final XWing.KeyPair localStatic,
      final Function<Bytes, byte[]> peerStaticXWingByNodeId,
      final Function<Bytes, Bytes> nodeIdByPeerStaticXWing) {
    this.localStatic = localStatic;
    this.peerStaticXWingByNodeId = peerStaticXWingByNodeId;
    this.nodeIdByPeerStaticXWing = nodeIdByPeerStaticXWing;
  }

  @Override
  public void prepareInitiator(final NodeKey nodeKey, final SECPPublicKey theirPubKey) {
    if (!status.compareAndSet(HandshakeStatus.UNINITIALIZED, HandshakeStatus.PREPARED)) {
      throw new IllegalStateException("handshake was already prepared");
    }
    this.initiator = true;
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
      out.writeBytes(Bytes.wrap(localStatic.encodedPublicKey())); // XWpk_I (신원은 이 키로 역조회)
      out.writeBytes(Bytes.wrap(eph.encodedPublicKey())); // XWpk_eph
      out.writeBytes(Bytes.wrap(encR.ciphertext())); // CT_R
      out.writeBytes(Bytes.wrap(nI)); // n_I
      out.endList();
      final byte[] authEncoded = out.encoded().toArrayUnsafe();
      // [관측용 OBS#3] Auth RLP 본문 길이(설계상 ≈3.6KB). 2바이트 접두어를 더한 값이 on-wire 크기.
      LOG.debug("XW-OBS#3 firstMessage authBodyLength={}", authEncoded.length);
      return frame(authEncoded);
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
    // 이번 read 로 도착한 조각을 누적 버퍼에 이어붙인다(TCP 는 메시지 경계를 보존하지 않음).
    final byte[] chunk = new byte[buf.readableBytes()];
    buf.readBytes(chunk);
    inboundReadCount++;
    // [관측용 OBS#2] 이번 read 로 받은 조각 길이 / 지금까지 누적된 길이.
    LOG.debug(
        "XW-OBS#2 handleMessage chunkLength={} buffered={} initiator={} responderStep={}",
        chunk.length,
        inbound.length + chunk.length,
        initiator,
        responderStep);
    inbound = concat(inbound, chunk);

    // 완전한 프레임(2바이트 길이 + 본문)이 아직 안 모였으면 empty → Besu 가 다음 조각을 기다린다.
    final Optional<byte[]> body = nextCompleteFrame();
    if (body.isEmpty()) {
      return Optional.empty();
    }
    // [관측용 OBS#4] 완전한 패킷 복원 완료(fragmentation 재조립 성공 증거).
    LOG.debug(
        "XW-OBS#4 assembled frame bodyLength={} reads={} initiator={} responderStep={}",
        body.get().length,
        inboundReadCount,
        initiator,
        responderStep);
    inboundReadCount = 0;

    try {
      if (initiator) {
        return handleAckAndBuildConf(body.get());
      } else if (responderStep == 0) {
        return Optional.of(handleAuthAndBuildAck(body.get()));
      } else {
        handleConf(body.get());
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

  /** 누적 버퍼에서 완전한 {@code [2B length][body]} 프레임 1개를 꺼낸다(남은 바이트는 보존). */
  private Optional<byte[]> nextCompleteFrame() {
    if (inbound.length < LENGTH_PREFIX_BYTES) {
      return Optional.empty();
    }
    final int bodyLen = ((inbound[0] & 0xFF) << 8) | (inbound[1] & 0xFF);
    final int frameLen = LENGTH_PREFIX_BYTES + bodyLen;
    if (inbound.length < frameLen) {
      return Optional.empty();
    }
    final byte[] body = Arrays.copyOfRange(inbound, LENGTH_PREFIX_BYTES, frameLen);
    inbound = Arrays.copyOfRange(inbound, frameLen, inbound.length);
    return Optional.of(body);
  }

  /** 본문 앞에 2바이트 big-endian 길이 접두어를 붙여 on-wire 프레임을 만든다(RLPx/EIP-8 관례). */
  private static ByteBuf frame(final byte[] body) {
    if (body.length > MAX_FRAME_BODY) {
      throw new IllegalStateException(
          "X-Wing handshake body too large for 2-byte length prefix: " + body.length);
    }
    final byte[] framed = new byte[LENGTH_PREFIX_BYTES + body.length];
    framed[0] = (byte) ((body.length >>> 8) & 0xFF);
    framed[1] = (byte) (body.length & 0xFF);
    System.arraycopy(body, 0, framed, LENGTH_PREFIX_BYTES, body.length);
    return Unpooled.wrappedBuffer(framed);
  }

  private static byte[] concat(final byte[] a, final byte[] b) {
    if (a.length == 0) {
      return b;
    }
    if (b.length == 0) {
      return a;
    }
    final byte[] out = new byte[a.length + b.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }

  /** 응답자: Auth 수신 → K_R/K_I/K_E 도출 → ACK 생성. */
  private ByteBuf handleAuthAndBuildAck(final byte[] authBytes) throws HandshakeException {
    final RLPInput in = RLP.input(Bytes.wrap(authBytes));
    in.enterList();
    final byte[] xwPkI = in.readBytes().toArrayUnsafe();
    final byte[] xwPkEph = in.readBytes().toArrayUnsafe();
    final byte[] ctRIn = in.readBytes().toArrayUnsafe();
    this.nI = in.readBytes().toArrayUnsafe();
    in.leaveList();

    // 신원 확정(바인딩): 개시자 X-Wing 공개키로 주소록을 역조회해 secp nodeId를 얻는다.
    // 주소록에 없는(미등록) 키면 거절한다.
    final Bytes peerNodeId = nodeIdByPeerStaticXWing.apply(Bytes.wrap(xwPkI));
    if (peerNodeId == null || peerNodeId.size() != SECP_PUBKEY_BYTES) {
      throw new HandshakeException("initiator X-Wing key not found in address book");
    }
    this.partyPubKey = signatureAlgorithm.createPublicKey(peerNodeId);

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
    return frame(out.encoded().toArrayUnsafe());
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
    return Optional.of(frame(out.encoded().toArrayUnsafe()));
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
