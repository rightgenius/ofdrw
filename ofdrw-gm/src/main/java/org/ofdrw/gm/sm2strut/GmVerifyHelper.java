package org.ofdrw.gm.sm2strut;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * GM 算法轻量级 API 验签/摘要工具
 * <p>
 * 目的：让 {@code ofd-cli} native binary（GraalVM closed-world）下，
 * 不需要注册 {@link org.bouncycastle.jce.provider.BouncyCastleProvider}，
 * 也能完成 SM2 验签和 SM3 摘要运算。
 * <p>
 * 与 {@code org.bouncycastle.jcajce.provider.digest.SM3} /
 * {@code java.security.Signature.getInstance(alg, "BC")} 行为一致，
 * 但走 {@code org.bouncycastle.crypto.*} 轻量级入口，绕开 JCE provider 校验。
 *
 * <p>设计要点：
 * <ul>
 *     <li>{@link #sm3WithSm2Verify} 用 {@link SM2Signer} 验签（GB/T 35275 唯一标准，
 *         算法字段差异不影响验签结果，公钥决定了是 SM2 curve 还是别的 EC curve）</li>
 *     <li>{@link #sm3(byte[])} / {@link #newSm3()} 用 {@link SM3Digest} 计算 SM3 摘要</li>
 *     <li>{@link #sha256(byte[])} 直接走 JDK 自带 provider（SHA-256 在 JDK 8+ 都内置）</li>
 * </ul>
 *
 * @author Mavis
 * @since 2.4.0-openpdf.5
 */
public final class GmVerifyHelper {

    private GmVerifyHelper() {
    }

    /**
     * SM3withSM2 验签（GB/T 35275 标准）
     * <p>
     * 输入：
     * <ul>
     *     <li>{@code holder} — 签名者证书（BC ASN.1 结构）</li>
     *     <li>{@code plaintext} — 待签原文（GB/T 35275 是 authenticated-attributes 的 DER 编码）</li>
     *     <li>{@code signature} — 签名值（密文摘要）</li>
     * </ul>
     *
     * @param holder    证书持有者
     * @param plaintext 待签原文
     * @param signature 签名值
     * @return true - 验签通过；false - 验签失败
     * @throws IOException              公钥解析失败
     * @throws GeneralSecurityException 公钥非 EC 类型等其他安全异常
     */
    public static boolean sm3WithSm2Verify(X509CertificateHolder holder, byte[] plaintext, byte[] signature)
            throws IOException, GeneralSecurityException {
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)
                PublicKeyFactory.createKey(holder.getSubjectPublicKeyInfo());
        SM2Signer signer = new SM2Signer();
        signer.init(false, pubKey);
        signer.update(plaintext, 0, plaintext.length);
        return signer.verifySignature(signature);
    }

    /**
     * SM3 摘要（一次性）
     *
     * @param data 输入数据
     * @return SM3 摘要值（32 字节）
     */
    public static byte[] sm3(byte[] data) {
        SM3Digest d = new SM3Digest();
        d.update(data, 0, data.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    /**
     * 流式 SM3 摘要（OFDValidator 校验文件完整性用）
     * <p>
     * 调用方负责：
     * <pre>
     *     SM3Digest d = GmVerifyHelper.newSm3();
     *     d.update(buf, 0, n);
     *     // ...循环
     *     byte[] out = new byte[d.getDigestSize()];
     *     d.doFinal(out, 0);
     * </pre>
     *
     * @return 新的 SM3 摘要器
     */
    public static SM3Digest newSm3() {
        return new SM3Digest();
    }

    /**
     * SHA-256 摘要（一次性）。走 JDK 内置 provider，不需要 BouncyCastleProvider。
     *
     * @param data 输入数据
     * @return SHA-256 摘要值（32 字节）
     * @throws NoSuchAlgorithmException JDK 缺少 SHA-256（理论不可能）
     */
    public static byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }
}
