package org.hyperledger.besu.ethereum.p2p.rlpx.handshake.ecies;

import org.hyperledger.besu.crypto.SECP256K1;   // Besu의 secp256k1 구현(네이티브/BC 폴백 둘 다 품고 있음)
import org.junit.jupiter.api.Test;

/**
 * [무엇을 하는 파일인가]
 * 이 JVM에서 secp256k1 "네이티브(C 라이브러리, libsecp256k1)"가 실제로 로드됐는지 확인만 하는 프로브.
 *
 * [왜 필요한가 — Tier-2 논거]
 * Besu의 네이티브 secp256k1은 Linux(.so)·macOS(.dylib)만 배포된다(Windows 미지원).
 * 그래서 Windows에서 돌리면 isNative()=false 가 나오고, 이것 자체가 "Windows에선 네이티브 불가"의 실측 증거가 된다.
 * 나중에 집 Linux/Mac에서 같은 테스트를 돌리면 isNative()=true 가 나와 진짜 네이티브 성능 측정으로 넘어갈 수 있다.
 *
 * [작성 언어/도구] Java + JUnit5. Besu crypto 모듈의 SECP256K1 클래스를 직접 호출한다.
 */
@SuppressWarnings("all")
public class NativeStatusProbeTest {

  @Test
  public void probeNativeStatus() {
    SECP256K1 secp = new SECP256K1();               // secp256k1 구현 인스턴스 생성
    boolean enabled = secp.maybeEnableNative();       // 네이티브 로드 "시도" → 성공 여부 반환
    System.out.println("=== secp256k1 네이티브 상태 프로브 ===");
    System.out.println("maybeEnableNative() = " + enabled);       // true면 네이티브 로드 성공
    System.out.println("isNative()          = " + secp.isNative()); // 현재 네이티브 사용 중인지
    System.out.println("OS   : " + System.getProperty("os.name"));
    System.out.println("Arch : " + System.getProperty("os.arch"));
    System.out.println("Java : " + System.getProperty("java.version"));
    System.out.println();
    if (secp.isNative()) {
      System.out.println("→ 네이티브(C) secp256k1 로드됨. 이 환경에서 Tier-2(실무/네이티브) 측정 가능.");
    } else {
      System.out.println("→ 네이티브 미로드 → BouncyCastle 순수자바 폴백. (Windows 예상 결과)");
      System.out.println("  Tier-2 네이티브 측정은 Linux/macOS 환경에서 이 테스트를 다시 돌려야 함.");
    }
  }
}
