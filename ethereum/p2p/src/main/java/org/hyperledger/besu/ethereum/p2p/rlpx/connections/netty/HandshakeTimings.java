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
package org.hyperledger.besu.ethereum.p2p.rlpx.connections.netty;

import io.netty.util.AttributeKey;

/**
 * [측정 전용 · 연구용] RLPx 핸드셰이크의 실제 TCP 구간 타임스탬프(T0~T8)를 한 연결(채널) 단위로 모은다.
 *
 * <p>사용법: 개시자(연결 거는 쪽)가 {@code connect()} 시점에 이 객체를 만들어 채널 속성({@link #KEY})에
 * 붙인다. 이후 각 Netty 핸들러가 자기 지점에서 {@code System.nanoTime()} 을 기록하고, 연결 확립 시점
 * (T8)에 {@link #summaryMicros()} 를 로그로 남긴다.
 *
 * <p>응답자(inbound) 채널에는 이 속성을 붙이지 않으므로(속성이 null) 응답자 핸들러의 stamp 는 건너뛴다.
 * 서로 다른 JVM 의 nanoTime 을 직접 빼지 않고, 오직 개시자 JVM 내부의 구간 차이만 계산한다.
 *
 * <p>모든 시각은 {@code System.nanoTime()} (단조 증가, 나노초). production 로직에 영향을 주지 않는다.
 */
final class HandshakeTimings {

  /** 채널에 이 타이밍 객체를 붙이는 키. */
  static final AttributeKey<HandshakeTimings> KEY = AttributeKey.valueOf("besuHandshakeTimings");

  long t0ConnectStart; // connect() 호출 직전
  long t1ChannelActive; // TCP 연결됨(channelActive)
  long t2AuthSent; // Auth 전송 완료
  long t5AckReceived; // Ack 수신(개시자 첫 inbound)
  long t6SecretsReady; // HandshakeSecrets 생성(SUCCESS)
  long t7HelloAuthenticated; // 상대 Hello 복호·nodeId 검증 통과
  long t8PeerEstablished; // peer 확립(connectFuture 완료)

  /** 개시자 JVM 내부 구간 차이(마이크로초). 아직 안 찍힌 구간은 -1. */
  String summaryMicros() {
    return "[RLPx-TCP us]"
        + " TCP(T1-T0)="
        + us(t0ConnectStart, t1ChannelActive)
        + " AuthAckRTT(T5-T2)="
        + us(t2AuthSent, t5AckReceived)
        + " crypto(T6-T1)="
        + us(t1ChannelActive, t6SecretsReady)
        + " helloAuth(T7-T1)="
        + us(t1ChannelActive, t7HelloAuthenticated)
        + " peer(T8-T1)="
        + us(t1ChannelActive, t8PeerEstablished)
        + " peerTotal(T8-T0)="
        + us(t0ConnectStart, t8PeerEstablished);
  }

  private static String us(final long start, final long end) {
    if (start == 0L || end == 0L) {
      return "n/a";
    }
    return String.format("%.1f", (end - start) / 1000.0);
  }
}
