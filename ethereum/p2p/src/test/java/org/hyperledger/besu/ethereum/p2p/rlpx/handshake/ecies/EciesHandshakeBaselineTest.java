package org.hyperledger.besu.ethereum.p2p.rlpx.handshake.ecies;

import io.netty.buffer.ByteBuf;
import java.util.Arrays;
import java.util.Optional;
import org.hyperledger.besu.cryptoservices.NodeKey;
import org.hyperledger.besu.cryptoservices.NodeKeyUtils;
import org.junit.jupiter.api.Test;

@SuppressWarnings("all")
public class EciesHandshakeBaselineTest {

    @Test
    public void measureEciesHandshake() throws Exception {
        NodeKey initiatorKey = NodeKeyUtils.generate();
        NodeKey responderKey = NodeKeyUtils.generate();

        int[] sizes = runHandshake(initiatorKey, responderKey);
        System.out.println("=== ECIES 핸드셰이크 baseline ===");
        System.out.println("Auth 메시지 크기 : " + sizes[0] + " bytes");
        System.out.println("Ack  메시지 크기 : " + sizes[1] + " bytes");
        System.out.println("총 크기          : " + (sizes[0] + sizes[1]) + " bytes (2 메시지, 2 라운드)");

        int warmup = 200, iters = 2000;
        for (int i = 0; i < warmup; i++) {
            runHandshake(initiatorKey, responderKey);
        }
        long[] t = new long[iters];
        for (int i = 0; i < iters; i++) {
            long s = System.nanoTime();
            runHandshake(initiatorKey, responderKey);
            t[i] = System.nanoTime() - s;
        }
        Arrays.sort(t);
        System.out.println("\n[전체 핸드셰이크 시간] 단위: 마이크로초(us)");
        System.out.printf("  중앙값 %.1f | p90 %.1f | 최소 %.1f%n",
                t[iters / 2] / 1000.0, t[(int) (iters * 0.9)] / 1000.0, t[0] / 1000.0);
    }

    private int[] runHandshake(NodeKey initiatorKey, NodeKey responderKey) throws Exception {
        ECIESHandshaker initiator = new ECIESHandshaker();
        ECIESHandshaker responder = new ECIESHandshaker();

        initiator.prepareInitiator(initiatorKey, responderKey.getPublicKey());
        responder.prepareResponder(responderKey);

        ByteBuf auth = initiator.firstMessage();
        int authSize = auth.readableBytes();

        Optional<ByteBuf> ackOpt = responder.handleMessage(auth);
        ByteBuf ack = ackOpt.orElseThrow();
        int ackSize = ack.readableBytes();

        initiator.handleMessage(ack);

        if (!initiator.getStatus().name().equals("SUCCESS")
                || !responder.getStatus().name().equals("SUCCESS")) {
            throw new IllegalStateException(
                    "핸드셰이크 실패: " + initiator.getStatus() + " / " + responder.getStatus());
        }
        return new int[] {authSize, ackSize};
    }
}