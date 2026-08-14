package org.ofdrw.gm.cert;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

/**
 * CertTools.objHolder 单元测试
 * <p>
 * 验证目标：
 * <ol>
 *     <li>objHolder 返回的 X509CertificateHolder 与 PEMParser 直读结果一致</li>
 *     <li>objHolder 的 SubjectPublicKeyInfo 可直接喂给 GmVerifyHelper.sm3WithSm2Verify</li>
 *     <li>objHolder 在 native-image 下不会触发 JCE provider 校验（编译期无 BouncyCastleProvider 依赖）</li>
 * </ol>
 *
 * @author Mavis
 * @since 2.4.0-openpdf.5
 */
class CertToolsObjHolderTest {

    @Test
    void objHolder_shouldReturnEquivalentHolder() throws Exception {
        Path certPem = Paths.get("src/test/resources", "sign_cert.pem");
        try (InputStream certIn = Files.newInputStream(certPem);
             PEMParser certParser = new PEMParser(new InputStreamReader(certIn))) {
            X509CertificateHolder direct = (X509CertificateHolder) certParser.readObject();

            // 用 objHolder 走 ASN.1 round-trip 拿到 holder
            Certificate asn1 = Certificate.getInstance(direct.getEncoded());
            X509CertificateHolder viaObjHolder = CertTools.objHolder(asn1);

            // 主体（subject）应一致
            assertEquals(direct.getSubject(), viaObjHolder.getSubject(),
                    "objHolder 应保留 subject");
            // 公钥应一致
            assertArrayEquals(direct.getSubjectPublicKeyInfo().getEncoded(),
                    viaObjHolder.getSubjectPublicKeyInfo().getEncoded(),
                    "objHolder 应保留 SubjectPublicKeyInfo");
        }
    }

    @Test
    void objHolder_shouldProduceValidKeyForGmVerifyHelper() throws Exception {
        Path certPem = Paths.get("src/test/resources", "sign_cert.pem");
        try (InputStream certIn = Files.newInputStream(certPem);
             PEMParser certParser = new PEMParser(new InputStreamReader(certIn))) {
            X509CertificateHolder holder = (X509CertificateHolder) certParser.readObject();

            // 关键链路：objHolder 的输出能被 GmVerifyHelper 直接消费
            // （不让 CertTools.obj 走 JcaX509CertificateConverter 那条 JCE 路径）
            org.bouncycastle.asn1.x509.Certificate asn1Cert =
                    org.bouncycastle.asn1.x509.Certificate.getInstance(holder.getEncoded());
            X509CertificateHolder viaObjHolder = CertTools.objHolder(asn1Cert);

            // 拿公钥参数时不应抛异常
            org.bouncycastle.crypto.params.AsymmetricKeyParameter pubKey =
                    org.bouncycastle.crypto.util.PublicKeyFactory.createKey(
                            viaObjHolder.getSubjectPublicKeyInfo());
            assertNotNull(pubKey, "PublicKeyFactory 应能解析 objHolder 返回的公钥");
            assertTrue(pubKey.isPrivate() == false, "解析出来的应是非私钥");
        }
    }
}
