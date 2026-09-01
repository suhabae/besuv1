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

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import io.netty.buffer.ByteBuf;
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

    final XWingHandshaker initiator = new XWingHandshaker(initXW, book::get);
    final XWingHandshaker responder = new XWingHandshaker(respXW, book::get);

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
    final Map<Bytes, byte[]> respBook = new HashMap<>();

    final XWingHandshaker initiator = new XWingHandshaker(initXW, initBook::get);
    final XWingHandshaker responder = new XWingHandshaker(respXW, respBook::get);

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
}
