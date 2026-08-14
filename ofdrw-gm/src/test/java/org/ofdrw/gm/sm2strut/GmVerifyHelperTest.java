package org.ofdrw.gm.sm2strut;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.*;

/**
 * GmVerifyHelper 单元测试
 * <p>
 * 验证目标：
 * <ol>
 *     <li>SM3withSM2 验签：JCE 签 → 轻量级验 = true（与现有 GBT35275 流程一致）</li>
 *     <li>SM3withSM2 验签：篡改签名 = false</li>
 *     <li>SM3 摘要：与 {@code new SM3.Digest()} JCE 路径结果一致</li>
 *     <li>SHA-256 摘要：与 JDK MessageDigest 一致</li>
 * </ol>
 *
 * @author Mavis
 * @since 2.4.0-openpdf.5
 */
class GmVerifyHelperTest {

    private static final byte[] PLAINTEXT = "Hello, GM world! 验证轻量级验签 API 跟 JCE 兼容."
            .getBytes(StandardCharsets.UTF_8);

    /** test cert (sm2) */
    private static X509CertificateHolder certHolder;
    private static PrivateKey privateKey;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Path certPem = Paths.get("src/test/resources", "sign_cert.pem");
        Path keyPem = Paths.get("src/test/resources", "sign_key.pem");
        try (InputStream certIn = Files.newInputStream(certPem);
             InputStream keyIn = Files.newInputStream(keyPem);
             PEMParser certParser = new PEMParser(new InputStreamReader(certIn));
             PEMParser keyParser = new PEMParser(new InputStreamReader(keyIn))) {
            certHolder = (X509CertificateHolder) certParser.readObject();
            PEMKeyPair keyPair = (PEMKeyPair) keyParser.readObject();
            privateKey = new JcaPEMKeyConverter().setProvider("BC")
                    .getPrivateKey(keyPair.getPrivateKeyInfo());
        }
    }

    /**
     * 用 JCE 签，用轻量级验 → 应该通过
     */
    @Test
    void sm3WithSm2Verify_jceSign_lightweightVerify_shouldPass() throws Exception {
        // 用 JCE 签名（与现有 GBT35275 PKCS9 流程完全一致）
        Signature signer = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), "BC");
        signer.initSign(privateKey);
        signer.update(PLAINTEXT);
        byte[] sig = signer.sign();

        // 用轻量级 API 验签
        assertTrue(GmVerifyHelper.sm3WithSm2Verify(certHolder, PLAINTEXT, sig),
                "SM3withSM2 验签应该通过");
    }

    /**
     * 篡改签名 → 应该失败
     */
    @Test
    void sm3WithSm2Verify_tamperedSignature_shouldFail() throws Exception {
        Signature signer = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), "BC");
        signer.initSign(privateKey);
        signer.update(PLAINTEXT);
        byte[] sig = signer.sign();

        // 篡改一个 byte
        sig[0] ^= 0x01;

        assertFalse(GmVerifyHelper.sm3WithSm2Verify(certHolder, PLAINTEXT, sig),
                "篡改签名后验签应失败");
    }

    /**
     * 篡改原文 → 应该失败
     */
    @Test
    void sm3WithSm2Verify_tamperedPlaintext_shouldFail() throws Exception {
        Signature signer = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), "BC");
        signer.initSign(privateKey);
        signer.update(PLAINTEXT);
        byte[] sig = signer.sign();

        byte[] tampered = PLAINTEXT.clone();
        tampered[0] ^= 0x01;
        assertFalse(GmVerifyHelper.sm3WithSm2Verify(certHolder, tampered, sig),
                "篡改原文后验签应失败");
    }

    /**
     * SM3 摘要：跟 JCE 路径结果一致
     */
    @Test
    void sm3_matchJceResult() {
        SM3Digest d = new SM3Digest();
        d.update(PLAINTEXT, 0, PLAINTEXT.length);
        byte[] expected = new byte[d.getDigestSize()];
        d.doFinal(expected, 0);

        byte[] actual = GmVerifyHelper.sm3(PLAINTEXT);
        assertArrayEquals(expected, actual, "轻量级 SM3 应与 JCE SM3 输出一致");
    }

    /**
     * SM3 已知向量（来自 GM/T 0004-2012）：
     * SM3("abc") = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
     */
    @Test
    void sm3_knownVector() {
        byte[] expected = new byte[]{
                0x66, (byte) 0xc7, (byte) 0xf0, (byte) 0xf4, 0x62, (byte) 0xee, (byte) 0xed, (byte) 0xd9,
                (byte) 0xd1, (byte) 0xf2, (byte) 0xd4, 0x6b, (byte) 0xdc, 0x10, (byte) 0xe4, (byte) 0xe2,
                0x41, 0x67, (byte) 0xc4, (byte) 0x87, 0x5c, (byte) 0xf2, (byte) 0xf7, (byte) 0xa2,
                0x29, 0x7d, (byte) 0xa0, 0x2b, (byte) 0x8f, 0x4b, (byte) 0xa8, (byte) 0xe0
        };
        byte[] actual = GmVerifyHelper.sm3("abc".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(expected, actual, "SM3(\"abc\") 应匹配 GM/T 0004 标准向量");
    }

    /**
     * SHA-256 已知向量
     */
    @Test
    void sha256_knownVector() throws Exception {
        byte[] expected = new byte[]{
                (byte) 0xba, 0x78, 0x16, (byte) 0xbf, (byte) 0x8f, 0x01, (byte) 0xcf, (byte) 0xea,
                0x41, 0x41, 0x40, (byte) 0xde, 0x5d, (byte) 0xae, 0x22, 0x23,
                (byte) 0xb0, 0x03, 0x61, (byte) 0xa3, (byte) 0x96, 0x17, 0x7a, (byte) 0x9c,
                (byte) 0xb4, 0x10, (byte) 0xff, 0x61, (byte) 0xf2, 0x00, 0x15, (byte) 0xad
        };
        byte[] actual = GmVerifyHelper.sha256("abc".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(expected, actual, "SHA-256(\"abc\") 应匹配 NIST FIPS 180-4 标准向量");
    }

    /**
     * 流式 SM3：跟一次性结果一致
     */
    @Test
    void newSm3_streamingShouldMatchOneShot() {
        byte[] oneShot = GmVerifyHelper.sm3(PLAINTEXT);

        SM3Digest d = GmVerifyHelper.newSm3();
        // 切成 7 字节一段，模拟流式
        for (int i = 0; i < PLAINTEXT.length; i += 7) {
            int len = Math.min(7, PLAINTEXT.length - i);
            d.update(PLAINTEXT, i, len);
        }
        byte[] streamed = new byte[d.getDigestSize()];
        d.doFinal(streamed, 0);

        assertArrayEquals(oneShot, streamed, "流式 SM3 应与一次性 SM3 输出一致");
    }
}
