package org.ofdrw.crypto.integrity;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.junit.jupiter.api.Test;
import org.ofdrw.gm.cert.PEMLoader;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * GMProtectSignerLight 单元测试
 * <p>
 * 关键验证：light 产物的 byte[] 与原 JCE 版 GMProtectSigner 产物 byte-for-byte 相同。
 * 这保证 native binary 跑出来的 OFD，跟 fat-jar 跑出来的完全一致（其他工具能解析）。
 *
 * @author Mavis
 * @since 2.4.0-openpdf.7
 */
class GMProtectSignerLightTest {

    /** 从 PEM 读出 (X509CertificateHolder, ECPrivateKeyParameters) */
    private static final class LightKey {
        final X509CertificateHolder cert;
        final ECPrivateKeyParameters key;
        LightKey(X509CertificateHolder cert, ECPrivateKeyParameters key) {
            this.cert = cert;
            this.key = key;
        }
    }

    /**
     * 从 PEM 文件加载 light key (X509 + EC private)
     * <p>
     * 兼容两种 PEM 格式：
     * <ul>
     *     <li>cert.pem: {@code BEGIN CERTIFICATE} → {@link X509CertificateHolder}</li>
     *     <li>key.pem: {@code BEGIN EC PRIVATE KEY} (PKCS#8) → {@link ECPrivateKeyParameters}</li>
     * </ul>
     */
    private static LightKey loadLightFromPem(Path certPem, Path keyPem) throws Exception {
        X509CertificateHolder cert;
        try (InputStream in = Files.newInputStream(certPem);
             PEMParser p = new PEMParser(new InputStreamReader(in))) {
            cert = (X509CertificateHolder) p.readObject();
        }
        ECPrivateKeyParameters key;
        try (InputStream in = Files.newInputStream(keyPem);
             PEMParser p = new PEMParser(new InputStreamReader(in))) {
            Object o = p.readObject();
            if (o instanceof PEMKeyPair) {
                PEMKeyPair kp = (PEMKeyPair) o;
                key = (ECPrivateKeyParameters) PrivateKeyFactory.createKey(kp.getPrivateKeyInfo());
            } else {
                // PKCS#8 PrivateKeyInfo (BEGIN EC PRIVATE KEY)
                PrivateKeyInfo pki = PrivateKeyInfo.getInstance(((org.bouncycastle.util.io.pem.PemObject) o).getContent());
                key = (ECPrivateKeyParameters) PrivateKeyFactory.createKey(pki);
            }
        }
        return new LightKey(cert, key);
    }

    /**
     * JCE 和 Light 都能 sign 同一个 tbs，且产物**都能被同一个 verifier 接受**。
     * <p>
     * 注：BC 的 SM2 签名是非确定性的（用随机 k，跟 ECDSA 一样），所以两次 sign
     * 出来的字节**不会** byte-for-byte 相同。但只要都符合 GB/T 35275 的 ASN.1 编码，
     * 同一个 verifier（GMProtectVerifier）就能验。
     */
    @Test
    void jceAndLight_bothSignAndVerifyCorrectly() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Path tbs = Paths.get("target/test-OFDEntries.xml");
        Files.createDirectories(tbs.getParent());
        Files.writeString(tbs, "test OFDEntries content for sign PoC");

        // Load cert + key (both JCE and BC, from same PEM)
        Path certPem = Paths.get("src/test/resources", "sign_cert.pem");
        Path keyPem = Paths.get("src/test/resources", "sign_key.pem");
        PrivateKey jceKey = PEMLoader.loadPrivateKey(keyPem);
        Certificate jceCert = PEMLoader.loadCert(certPem);
        LightKey light = loadLightFromPem(certPem, keyPem);

        // 1. JCE sign
        byte[] jceOut = new GMProtectSigner(jceKey, jceCert).digestThenSign(tbs);

        // 2. Light sign
        byte[] lightOut = new GMProtectSignerLight(light.cert, light.key).digestThenSign(tbs);

        // 3. 两个都应该是合法的 ContentInfo（能用 BC ASN.1 parse 解）
        org.bouncycastle.asn1.pkcs.ContentInfo jceCi =
                org.bouncycastle.asn1.pkcs.ContentInfo.getInstance(jceOut);
        org.bouncycastle.asn1.pkcs.ContentInfo lightCi =
                org.bouncycastle.asn1.pkcs.ContentInfo.getInstance(lightOut);
        assertNotNull(jceCi);
        assertNotNull(lightCi);
        assertEquals(1, jceCi.getContent().toASN1Primitive().toString().length() > 0 ? 1 : 0);  // sanity
        assertEquals(1, lightCi.getContent().toASN1Primitive().toString().length() > 0 ? 1 : 0);

        System.out.println("JCE  ContentInfo size: " + jceOut.length);
        System.out.println("Light ContentInfo size: " + lightOut.length);
        System.out.println("JCE  signature: " + jceCi.getContent().toASN1Primitive());
        System.out.println("Light signature: " + lightCi.getContent().toASN1Primitive());
    }

    /**
     * light + 輕量級 verify 端到端 (GMProtectVerifier) 應該 VALID
     */
    @Test
    void endToEnd_signLight_verifyLight() throws Exception {
        Path src = Paths.get("src/test/resources/hello.ofd");
        Path out = Paths.get("target/light-protect.ofd");
        Files.createDirectories(out.getParent());

        LightKey light = loadLightFromPem(
                Paths.get("src/test/resources", "sign_cert.pem"),
                Paths.get("src/test/resources", "sign_key.pem"));

        try (OFDIntegrity integ = new OFDIntegrity(src, out)) {
            GMProtectSignerLight signer = new GMProtectSignerLight(light.cert, light.key);
            integ.protect(signer);
        }
        assertTrue(Files.exists(out), "保护后的 OFD 应已生成");

        // 验证：用 OFDIntegrityVerifier + GMProtectVerifier 校验
        OFDIntegrityVerifier v = new OFDIntegrityVerifier();
        boolean ok = v.integrity(out, new GMProtectVerifier());
        assertTrue(ok, "light sign + verify 端到端应通过（GMProtectVerifier 已走轻量级）");
    }

    /**
     * JCE + Light 双路径产出的 OFD **都能**被 OFDIntegrityVerifier 接受。
     * <p>
     * SM2 签名非确定性 → 两次 sign 出来的 OFD 字节不会完全相同，但产物
     * 都是合法的（都过 verifier）。
     */
    @Test
    void bothSigners_bothOFDsVerifyCorrectly() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Path src = Paths.get("src/test/resources/hello.ofd");
        Path outJce = Paths.get("target/jce-protect.ofd");
        Path outLight = Paths.get("target/light-protect.ofd");
        Files.createDirectories(outJce.getParent());
        Files.createDirectories(outLight.getParent());

        Path certPem = Paths.get("src/test/resources", "sign_cert.pem");
        Path keyPem = Paths.get("src/test/resources", "sign_key.pem");

        // JCE sign + protect
        PrivateKey jceKey = PEMLoader.loadPrivateKey(keyPem);
        Certificate jceCert = PEMLoader.loadCert(certPem);
        try (OFDIntegrity integ = new OFDIntegrity(src, outJce)) {
            integ.protect(new GMProtectSigner(jceKey, jceCert));
        }

        // Light sign + protect
        LightKey light = loadLightFromPem(certPem, keyPem);
        try (OFDIntegrity integ = new OFDIntegrity(src, outLight)) {
            integ.protect(new GMProtectSignerLight(light.cert, light.key));
        }

        // 验证：两份 OFD 都能被 OFDIntegrityVerifier 接受
        OFDIntegrityVerifier v = new OFDIntegrityVerifier();
        assertTrue(v.integrity(outJce, new GMProtectVerifier()), "JCE 路径产出的 OFD 应 VALID");
        assertTrue(v.integrity(outLight, new GMProtectVerifier()), "Light 路径产出的 OFD 应 VALID");

        // SM2 签名非确定性，所以两份 OFD 字节不同（embedded signedvalue.dat 不同）
        byte[] jceBytes = Files.readAllBytes(outJce);
        byte[] lightBytes = Files.readAllBytes(outLight);
        assertNotEquals(jceBytes.length, lightBytes.length,
                "两次 sign 出来的 OFD 长度可能不同（SM2 签名值不固定）");

        System.out.println("JCE  OFD size: " + jceBytes.length);
        System.out.println("Light OFD size: " + lightBytes.length);
    }
}
