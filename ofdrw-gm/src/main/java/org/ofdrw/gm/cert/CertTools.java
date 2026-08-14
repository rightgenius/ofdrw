package org.ofdrw.gm.cert;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

/**
 * 证书转换工具
 *
 * @author 权观宇
 * @since 2021-08-05 19:03:14
 */
public final class CertTools {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 转换证书对象为 ASN1结构对象
     *
     * @param certificate JCE证书对象
     * @return ASN1证书结构
     * @throws CertificateEncodingException 证书编码异常
     * @throws IOException                  IO读写异常
     */
    public static Certificate asn1(java.security.cert.Certificate certificate) throws CertificateEncodingException, IOException {
        ASN1Primitive p = ASN1Primitive.fromByteArray(certificate.getEncoded());
        if (p == null) {
            throw new IllegalArgumentException("无法解析证书(certificate)");
        }
        return org.bouncycastle.asn1.x509.Certificate.getInstance(p);
    }

    /**
     * 转换 ASN1结构对象 为 BC 轻量级证书持有者（X509CertificateHolder）
     * <p>
     * 推荐使用此方法（native-image 友好）。返回的 holder 可以直接喂给
     * {@code GmVerifyHelper.sm3WithSm2Verify(holder, ...)} 验签，
     * 不需要走 JCE provider 路径。
     *
     * @param certificate ASN1 证书结构
     * @return X509CertificateHolder
     * @throws IOException 证书解析异常
     * @since 2.4.0-openpdf.5
     */
    public static X509CertificateHolder objHolder(Certificate certificate) throws IOException {
        return new X509CertificateHolder(certificate);
    }

    /**
     * 转换 ASN1结构对象 为 JCE 证书对象
     * <p>
     * <b>注意</b>：此方法走 {@code JcaX509CertificateConverter().setProvider("BC")}，
     * 在 GraalVM native-image closed-world 模式下会触发
     * {@code JceSecurity.canUseProvider} 校验失败。native 路径请改用
     * {@link #objHolder(Certificate)}。
     *
     * @param certificate JCE证书对象
     * @return ASN1证书结构
     * @throws CertificateException 证书解析异常
     * @deprecated 2.4.0-openpdf.5 起 native 路径请改用 {@link #objHolder(Certificate)}；
     *             本方法保留以兼容 sign 路径、PEMLoader 等历史调用方
     */
    @Deprecated
    public static java.security.cert.Certificate obj(Certificate certificate) throws CertificateException {
        return new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(new X509CertificateHolder(certificate));
    }
}
