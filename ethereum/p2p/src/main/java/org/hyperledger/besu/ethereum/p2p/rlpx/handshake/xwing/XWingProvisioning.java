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

import org.hyperledger.besu.crypto.xwing.XWing;
import org.hyperledger.besu.cryptoservices.NodeKey;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.tuweni.bytes.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * [연구용 배선] 시스템 프로퍼티로 X-Wing 핸드셰이크를 켜고, 노드의 X-Wing 정적키/주소록을 파일에서
 * 로드해 {@link XWingHandshaker} 를 만든다. CLI/config 코드를 건드리지 않기 위해 시스템 프로퍼티 사용.
 *
 * <ul>
 *   <li>{@code -Dbesu.rlpx.xwing=true} — X-Wing 핸드셰이크 활성화
 *   <li>{@code -Dbesu.rlpx.xwing.keyFile=<path>} — 이 노드의 X-Wing 정적키 파일(없으면 생성 후 저장,
 *       조립용 자기 항목을 {@code <path>.pub} 로 내보냄)
 *   <li>{@code -Dbesu.rlpx.xwing.addressBook=<path>} — 주소록(각 줄 {@code secpNodeIdHex=xwingPubHex})
 * </ul>
 */
public final class XWingProvisioning {

  private static final Logger LOG = LoggerFactory.getLogger(XWingProvisioning.class);

  /** X-Wing 활성화 플래그. */
  public static final String ENABLED_PROP = "besu.rlpx.xwing";

  /** 이 노드의 X-Wing 정적키 파일 경로. */
  public static final String KEYFILE_PROP = "besu.rlpx.xwing.keyFile";

  /** 주소록 파일 경로(secp nodeId → X-Wing 공개키). */
  public static final String ADDRBOOK_PROP = "besu.rlpx.xwing.addressBook";

  private static XWing.KeyPair localKey;
  private static Map<Bytes, byte[]> addressBook; // nodeId → X-Wing pk (개시자용)
  private static Map<Bytes, Bytes> reverseAddressBook; // X-Wing pk → nodeId (응답자용)

  private XWingProvisioning() {}

  /** {@code -Dbesu.rlpx.xwing=true} 이면 true. */
  public static boolean enabled() {
    return Boolean.getBoolean(ENABLED_PROP);
  }

  /** X-Wing 핸드셰이커 생성(정적키/주소록은 1회 로드 후 캐시). */
  public static synchronized XWingHandshaker newHandshaker(final NodeKey nodeKey) {
    if (localKey == null) {
      localKey = loadOrCreateLocalKey(nodeKey);
      addressBook = loadAddressBook();
      reverseAddressBook = buildReverse(addressBook);
    }
    return new XWingHandshaker(localKey, addressBook::get, reverseAddressBook::get);
  }

  /** 주소록(nodeId→X-Wing pk)에서 역방향 맵(X-Wing pk→nodeId)을 만든다. 응답자 신원 역조회용. */
  private static Map<Bytes, Bytes> buildReverse(final Map<Bytes, byte[]> forward) {
    final Map<Bytes, Bytes> rev = new HashMap<>();
    for (final Map.Entry<Bytes, byte[]> e : forward.entrySet()) {
      rev.put(Bytes.wrap(e.getValue()), e.getKey());
    }
    return rev;
  }

  private static XWing.KeyPair loadOrCreateLocalKey(final NodeKey nodeKey) {
    final String p = System.getProperty(KEYFILE_PROP);
    if (p == null || p.isEmpty()) {
      throw new IllegalStateException(KEYFILE_PROP + " system property is required for X-Wing");
    }
    final Path path = Path.of(p);
    try {
      if (Files.exists(path)) {
        final XWing.KeyPair kp = XWing.keyPairFromPrivateBundle(Files.readAllBytes(path));
        LOG.info("Loaded X-Wing static key from {}", path);
        return kp;
      }
      final XWing.KeyPair kp = XWing.generateKeyPair();
      if (path.getParent() != null) {
        Files.createDirectories(path.getParent());
      }
      Files.write(path, kp.privateKeyBundle());
      // 주소록 조립용 자기 항목: <secp nodeId hex>=<xwing pub hex>
      final Bytes nodeId = nodeKey.getPublicKey().getEncodedBytes();
      final String selfLine =
          nodeId.toUnprefixedHexString()
              + "="
              + Bytes.wrap(kp.encodedPublicKey()).toUnprefixedHexString();
      Files.write(
          Path.of(p + ".pub"),
          (selfLine + System.lineSeparator()).getBytes(StandardCharsets.UTF_8));
      LOG.info(
          "Generated X-Wing static key at {} (address-book entry written to {}.pub)", path, path);
      return kp;
    } catch (final IOException e) {
      throw new UncheckedIOException("failed to load/create X-Wing key at " + path, e);
    }
  }

  private static Map<Bytes, byte[]> loadAddressBook() {
    final Map<Bytes, byte[]> book = new HashMap<>();
    final String p = System.getProperty(ADDRBOOK_PROP);
    if (p == null || p.isEmpty()) {
      LOG.warn("{} not set; X-Wing address book is empty (handshakes will fail)", ADDRBOOK_PROP);
      return book;
    }
    final Path path = Path.of(p);
    if (!Files.exists(path)) {
      LOG.warn("X-Wing address book {} not found; it is empty", path);
      return book;
    }
    try {
      final List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
      for (final String line : lines) {
        final String t = line.trim();
        if (t.isEmpty() || t.startsWith("#")) {
          continue;
        }
        final int eq = t.indexOf('=');
        if (eq <= 0) {
          continue;
        }
        final Bytes nodeId = Bytes.fromHexString(prefix0x(t.substring(0, eq).trim()));
        final byte[] xwPub =
            Bytes.fromHexString(prefix0x(t.substring(eq + 1).trim())).toArrayUnsafe();
        book.put(nodeId, xwPub);
      }
      LOG.info("Loaded {} X-Wing address-book entries from {}", book.size(), path);
    } catch (final IOException e) {
      throw new UncheckedIOException("failed to read X-Wing address book " + path, e);
    }
    return book;
  }

  private static String prefix0x(final String s) {
    return s.startsWith("0x") ? s : "0x" + s;
  }
}
