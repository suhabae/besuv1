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

import org.hyperledger.besu.ethereum.p2p.rlpx.handshake.xwing.XWing.Encapsulation;
import org.hyperledger.besu.ethereum.p2p.rlpx.handshake.xwing.XWing.KeyPair;
import org.junit.jupiter.api.Test;

/** X-Wing KEM 프리미티브의 정확성/크기/오복호 검증. */
class XWingTest {

  @Test
  void encapsulateThenDecapsulateYieldsSameSecret() {
    // 수신자 키쌍 + 그 공개키(주소록에 배포될 형태)
    final KeyPair recipient = XWing.generateKeyPair();
    final byte[] recipientPub = recipient.encodedPublicKey();

    // 발신자: 수신자 공개키로 캡슐화
    final Encapsulation enc = XWing.encapsulate(recipientPub);
    // 수신자: 자기 개인키로 복호
    final byte[] recovered = XWing.decapsulate(enc.ciphertext(), recipient);

    // 두 공유비밀이 같아야 KEM 왕복이 성립
    assertThat(recovered).isEqualTo(enc.sharedSecret());
  }

  @Test
  void wireSizesMatchSpec() {
    final KeyPair kp = XWing.generateKeyPair();
    final Encapsulation enc = XWing.encapsulate(kp.encodedPublicKey());

    assertThat(kp.encodedPublicKey()).hasSize(XWing.PUBLIC_KEY_BYTES); // 1216
    assertThat(enc.ciphertext()).hasSize(XWing.CIPHERTEXT_BYTES); // 1120
    assertThat(enc.sharedSecret()).hasSize(XWing.SHARED_SECRET_BYTES); // 32
  }

  @Test
  void decapsulateWithWrongKeyDoesNotMatch() {
    final KeyPair recipient = XWing.generateKeyPair();
    final KeyPair attacker = XWing.generateKeyPair();

    final Encapsulation enc = XWing.encapsulate(recipient.encodedPublicKey());
    // 다른 키쌍으로 복호하면(ML-KEM 암묵적 거부 + X25519 불일치) 공유비밀이 달라야 함
    final byte[] wrong = XWing.decapsulate(enc.ciphertext(), attacker);

    assertThat(wrong).isNotEqualTo(enc.sharedSecret());
  }
}
