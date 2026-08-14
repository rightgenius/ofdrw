package org.ofdrw.sign.signContainer;

import org.junit.jupiter.api.Test;
import org.ofdrw.gm.cert.PKCS12ToolsLight;
import org.ofdrw.reader.OFDReader;
import org.ofdrw.sign.NumberFormatAtomicSignID;
import org.ofdrw.sign.OFDSigner;
import org.ofdrw.sign.verify.OFDValidator;

import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * GBT35275DSContainerLight 集成测试
 * <p>
 * 验证：轻量级 BC API 签的 OFD，能被同样走轻量级 API 的 OFDValidator 验签。
 * <p>
 * 这是 native-image 跑通 sign / verify 的 PoC：
 * <ul>
 *     <li>sign 端：PKCS12ToolsLight（解 .p12）+ GBT35275DSContainerLight（SM3 + SM2 sign）</li>
 *     <li>verify 端：OFDValidator → GBT35275Validate → GmVerifyHelper.sm3WithSm2Verify</li>
 * </ul>
 *
 * @author Mavis
 * @since 2.4.0-openpdf.6
 */
class GBT35275DSContainerLightTest {

    /**
     * 轻量级 sign + 轻量级 verify = VALID
     */
    @Test
    void signAndVerify_lightweightPath() throws Exception {
        Path src = Paths.get("src/test/resources", "helloworld.ofd");
        Path out = Paths.get("target", "lightweight_signed.ofd");
        Path p12 = Paths.get("src/test/resources", "USER.p12");
        char[] pwd = "777777".toCharArray();

        // sign 端：轻量级 PKCS#12 读 + 轻量级 SM2 签
        PKCS12ToolsLight.Result p12Result = PKCS12ToolsLight.read(p12, pwd);
        GBT35275DSContainerLight container =
                new GBT35275DSContainerLight(p12Result.certHolder, p12Result.privateKey);

        try (OFDReader reader = new OFDReader(src);
             OFDSigner signer = new OFDSigner(reader, out, new NumberFormatAtomicSignID())) {
            signer.setSignContainer(container);
            signer.exeSign();
        }
        assertTrue(java.nio.file.Files.exists(out), "签完的 OFD 应已生成");

        // verify 端：OFDValidator 走 GBT35275Validate → GmVerifyHelper 验签
        try (OFDReader reader = new OFDReader(out);
             OFDValidator validator = new OFDValidator(reader)) {
            validator.setValidator(new org.ofdrw.sign.verify.container.GBT35275ValidateContainer());
            assertDoesNotThrow(validator::exeValidate, "轻量级 sign + 轻量级 verify 应通过");
        }
    }

    /**
     * 错误密码：PKCS12ToolsLight 抛 GeneralSecurityException
     */
    @Test
    void wrongPassword_shouldThrow() {
        Path p12 = Paths.get("src/test/resources", "USER.p12");
        org.junit.jupiter.api.Assertions.assertThrows(
                java.security.GeneralSecurityException.class,
                () -> PKCS12ToolsLight.read(p12, "wrong-password".toCharArray()),
                "错误密码应抛 GeneralSecurityException");
    }
}
