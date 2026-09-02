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

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.xwing.XWing;
import org.hyperledger.besu.cryptoservices.NodeKey;
import org.hyperledger.besu.cryptoservices.NodeKeyUtils;
import org.hyperledger.besu.ethereum.p2p.rlpx.handshake.Handshaker;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

/** XWingHandshaker 전체 3-메시지 흐름(Auth→ACK→Conf)을 in-memory로 검증. */
class XWingHandshakerTest {

  @Test
  void fullHandshakeYieldsMatchingSecrets() throws Exception {
    // secp 신원 (기존 유지) + X-Wing 정적 키(신규)
    final NodeKey initNodeKey = NodeKeyUtils.generate();
    final NodeKey respNodeKey = NodeKeyUtils.generate();
    final XWing.KeyPair initXW = XWing.generateKeyPair();
    final XWing.KeyPair respXW = XWing.generateKeyPair();

    // 컨소시엄 PDK 주소록: secp nodeId(64B) → 상대 X-Wing 정적 공개키(1216B)
    final Map<Bytes, byte[]> book = new HashMap<>();
    book.put(respNodeKey.getPublicKey().getEncodedBytes(), respXW.encodedPublicKey());
    book.put(initNodeKey.getPublicKey().getEncodedBytes(), initXW.encodedPublicKey());

    final XWingHandshaker initiator = new XWingHandshaker(initXW, book::get, reverse(book)::get);
    final XWingHandshaker responder = new XWingHandshaker(respXW, book::get, reverse(book)::get);

    initiator.prepareInitiator(initNodeKey, respNodeKey.getPublicKey());
    responder.prepareResponder(respNodeKey);

    final ByteBuf auth = initiator.firstMessage(); // Auth
    final ByteBuf ack = responder.handleMessage(auth).orElseThrow(); // ACK
    final ByteBuf conf = initiator.handleMessage(ack).orElseThrow(); // Conf
    final Optional<ByteBuf> none = responder.handleMessage(conf); // 완료

    assertThat(none).isEmpty();
    assertThat(initiator.getStatus()).isEqualTo(Handshaker.HandshakeStatus.SUCCESS);
    assertThat(responder.getStatus()).isEqualTo(Handshaker.HandshakeStatus.SUCCESS);

    // 양측 aes/mac/token 동일 + egress/ingress 거울 대칭(flipMacs=true) → 기존 Framer 호환
    assertThat(initiator.secrets().equals(responder.secrets(), true)).isTrue();

    // 상대 secp 신원 인식 확인
    assertThat(responder.partyPubKey().getEncodedBytes())
        .isEqualTo(initNodeKey.getPublicKey().getEncodedBytes());
    assertThat(initiator.partyPubKey().getEncodedBytes())
        .isEqualTo(respNodeKey.getPublicKey().getEncodedBytes());
  }

  @Test
  void wrongAddressBookKeyFailsTagVerification() throws Exception {
    final NodeKey initNodeKey = NodeKeyUtils.generate();
    final NodeKey respNodeKey = NodeKeyUtils.generate();
    final XWing.KeyPair initXW = XWing.generateKeyPair();
    final XWing.KeyPair respXW = XWing.generateKeyPair();
    final XWing.KeyPair wrongXW = XWing.generateKeyPair(); // 공격자/오설정

    // 개시자 주소록에 응답자의 "틀린" X-Wing 공개키를 넣음 → K_R 불일치 → tag 검증 실패해야 함
    final Map<Bytes, byte[]> initBook = new HashMap<>();
    initBook.put(respNodeKey.getPublicKey().getEncodedBytes(), wrongXW.encodedPublicKey());
    // 응답자는 개시자를 (올바른) 역주소록으로 식별할 수 있어야 tag 검증 단계까지 도달한다.
    final Map<Bytes, byte[]> respBook = new HashMap<>();
    respBook.put(initNodeKey.getPublicKey().getEncodedBytes(), initXW.encodedPublicKey());

    final XWingHandshaker initiator =
        new XWingHandshaker(initXW, initBook::get, reverse(initBook)::get);
    final XWingHandshaker responder =
        new XWingHandshaker(respXW, respBook::get, reverse(respBook)::get);

    initiator.prepareInitiator(initNodeKey, respNodeKey.getPublicKey());
    responder.prepareResponder(respNodeKey);

    final ByteBuf auth = initiator.firstMessage();
    final ByteBuf ack = responder.handleMessage(auth).orElseThrow();

    // 개시자가 ACK 처리 시 tag_R 검증 실패 → 예외, 상태 FAILED
    try {
      initiator.handleMessage(ack);
    } catch (final Exception expected) {
      // ok
    }
    assertThat(initiator.getStatus()).isEqualTo(Handshaker.HandshakeStatus.FAILED);
  }

  /**
   * [framing] Auth(≈3.6KB)가 TCP/Netty 에서 2048B + 나머지로 쪼개져 도착해도 재조립되어 정상 처리되는지.
   * 이것이 라이브에서 net_peerCount=0x0 을 유발한 fragmentation 의 회귀 테스트다.
   */
  @Test
  void fragmentedAuthReassemblesAndCompletes() throws Exception {
    final NodeKey initNodeKey = NodeKeyUtils.generate();
    final NodeKey respNodeKey = NodeKeyUtils.generate();
    final XWing.KeyPair initXW = XWing.generateKeyPair();
    final XWing.KeyPair respXW = XWing.generateKeyPair();
    final Map<Bytes, byte[]> book = new HashMap<>();
    book.put(respNodeKey.getPublicKey().getEncodedBytes(), respXW.encodedPublicKey());
    book.put(initNodeKey.getPublicKey().getEncodedBytes(), initXW.encodedPublicKey());

    final XWingHandshaker initiator = new XWingHandshaker(initXW, book::get, reverse(book)::get);
    final XWingHandshaker responder = new XWingHandshaker(respXW, book::get, reverse(book)::get);
    initiator.prepareInitiator(initNodeKey, respNodeKey.getPublicKey());
    responder.prepareResponder(respNodeKey);

    final byte[] authFramed = toBytes(initiator.firstMessage());
    assertThat(authFramed.length).isGreaterThan(2048); // 실제로 조각나는 크기여야 의미가 있음
    final ByteBuf ack = feedFragmented(responder, authFramed, 2048).orElseThrow();

    final ByteBuf conf = initiator.handleMessage(ack).orElseThrow();
    assertThat(responder.handleMessage(conf)).isEmpty();
    assertThat(initiator.getStatus()).isEqualTo(Handshaker.HandshakeStatus.SUCCESS);
    assertThat(responder.getStatus()).isEqualTo(Handshaker.HandshakeStatus.SUCCESS);
    assertThat(initiator.secrets().equals(responder.secrets(), true)).isTrue();
  }

  /** [framing] ACK(≈2.4KB)도 2048B 를 넘으므로 개시자 수신 시 조각난다. 개시자 재조립 경로 검증. */
  @Test
  void fragmentedAckReassemblesOnInitiator() throws Exception {
    final NodeKey initNodeKey = NodeKeyUtils.generate();
    final NodeKey respNodeKey = NodeKeyUtils.generate();
    final XWing.KeyPair initXW = XWing.generateKeyPair();
    final XWing.KeyPair respXW = XWing.generateKeyPair();
    final Map<Bytes, byte[]> book = new HashMap<>();
    book.put(respNodeKey.getPublicKey().getEncodedBytes(), respXW.encodedPublicKey());
    book.put(initNodeKey.getPublicKey().getEncodedBytes(), initXW.encodedPublicKey());

    final XWingHandshaker initiator = new XWingHandshaker(initXW, book::get, reverse(book)::get);
    final XWingHandshaker responder = new XWingHandshaker(respXW, book::get, reverse(book)::get);
    initiator.prepareInitiator(initNodeKey, respNodeKey.getPublicKey());
    responder.prepareResponder(respNodeKey);

    final ByteBuf auth = initiator.firstMessage();
    final byte[] ackFramed = toBytes(responder.handleMessage(auth).orElseThrow());
    assertThat(ackFramed.length).isGreaterThan(2048);

    final ByteBuf conf = feedFragmented(initiator, ackFramed, 2048).orElseThrow();
    assertThat(responder.handleMessage(conf)).isEmpty();
    assertThat(initiator.getStatus()).isEqualTo(Handshaker.HandshakeStatus.SUCCESS);
    assertThat(responder.getStatus()).isEqualTo(Handshaker.HandshakeStatus.SUCCESS);
    assertThat(initiator.secrets().equals(responder.secrets(), true)).isTrue();
  }

  /** [framing] 극단적 조각화: Auth 를 1바이트씩 흘려넣어도 정확히 마지막 바이트에서만 완성되어야 함. */
  @Test
  void byteByByteFragmentationReassembles() throws Exception {
    final NodeKey initNodeKey = NodeKeyUtils.generate();
    final NodeKey respNodeKey = NodeKeyUtils.generate();
    final XWing.KeyPair initXW = XWing.generateKeyPair();
    final XWing.KeyPair respXW = XWing.generateKeyPair();
    final Map<Bytes, byte[]> book = new HashMap<>();
    book.put(respNodeKey.getPublicKey().getEncodedBytes(), respXW.encodedPublicKey());
    book.put(initNodeKey.getPublicKey().getEncodedBytes(), initXW.encodedPublicKey());

    final XWingHandshaker initiator = new XWingHandshaker(initXW, book::get, reverse(book)::get);
    final XWingHandshaker responder = new XWingHandshaker(respXW, book::get, reverse(book)::get);
    initiator.prepareInitiator(initNodeKey, respNodeKey.getPublicKey());
    responder.prepareResponder(respNodeKey);

    final byte[] authFramed = toBytes(initiator.firstMessage());
    final ByteBuf ack = feedFragmented(responder, authFramed, 1).orElseThrow();

    final ByteBuf conf = initiator.handleMessage(ack).orElseThrow();
    assertThat(responder.handleMessage(conf)).isEmpty();
    assertThat(initiator.getStatus()).isEqualTo(Handshaker.HandshakeStatus.SUCCESS);
    assertThat(responder.getStatus()).isEqualTo(Handshaker.HandshakeStatus.SUCCESS);
    assertThat(initiator.secrets().equals(responder.secrets(), true)).isTrue();
  }

  /** [신원 바인딩] 응답자 주소록에 없는 X-Wing 키를 제시한 개시자는 Auth 처리 단계에서 거절된다. */
  @Test
  void unregisteredInitiatorRejectedAtAuth() throws Exception {
    final NodeKey initNodeKey = NodeKeyUtils.generate();
    final NodeKey respNodeKey = NodeKeyUtils.generate();
    final XWing.KeyPair initXW = XWing.generateKeyPair();
    final XWing.KeyPair respXW = XWing.generateKeyPair();

    // 개시자는 응답자 키를 알지만, 응답자 주소록엔 개시자 항목이 없음(미등록).
    final Map<Bytes, byte[]> initBook = new HashMap<>();
    initBook.put(respNodeKey.getPublicKey().getEncodedBytes(), respXW.encodedPublicKey());
    final Map<Bytes, byte[]> respBook = new HashMap<>(); // 개시자 미등록

    final XWingHandshaker initiator =
        new XWingHandshaker(initXW, initBook::get, reverse(initBook)::get);
    final XWingHandshaker responder =
        new XWingHandshaker(respXW, respBook::get, reverse(respBook)::get);
    initiator.prepareInitiator(initNodeKey, respNodeKey.getPublicKey());
    responder.prepareResponder(respNodeKey);

    final ByteBuf auth = initiator.firstMessage();
    try {
      responder.handleMessage(auth); // 미등록 X-Wing 키 → 역조회 실패 → 거절
    } catch (final Exception expected) {
      // ok
    }
    assertThat(responder.getStatus()).isEqualTo(Handshaker.HandshakeStatus.FAILED);
  }

  /** framed 바이트열을 chunkSize 바이트씩 쪼개 handleMessage 에 흘려넣고, 나온 응답(있으면)을 반환. */
  private static Optional<ByteBuf> feedFragmented(
      final XWingHandshaker hs, final byte[] framed, final int chunkSize) throws Exception {
    Optional<ByteBuf> response = Optional.empty();
    for (int off = 0; off < framed.length; off += chunkSize) {
      final int end = Math.min(off + chunkSize, framed.length);
      final Optional<ByteBuf> r =
          hs.handleMessage(Unpooled.wrappedBuffer(Arrays.copyOfRange(framed, off, end)));
      if (r.isPresent()) {
        response = r; // 완전한 프레임이 모이기 전까지는 empty 여야 하고, 마지막에만 응답이 나옴
      }
    }
    return response;
  }

  /** 주소록(nodeId→X-Wing pk)에서 역방향 맵(X-Wing pk→nodeId)을 만든다. 응답자 신원 역조회용. */
  private static Map<Bytes, Bytes> reverse(final Map<Bytes, byte[]> book) {
    final Map<Bytes, Bytes> rev = new HashMap<>();
    for (final Map.Entry<Bytes, byte[]> e : book.entrySet()) {
      rev.put(Bytes.wrap(e.getValue()), e.getKey());
    }
    return rev;
  }

  private static byte[] toBytes(final ByteBuf buf) {
    final byte[] b = new byte[buf.readableBytes()];
    buf.getBytes(buf.readerIndex(), b);
    return b;
  }
}
