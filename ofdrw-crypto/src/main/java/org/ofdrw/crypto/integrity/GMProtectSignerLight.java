package org.ofdrw.crypto.integrity;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.ofdrw.gm.sm2strut.ContentInfo;
import org.ofdrw.gm.sm2strut.GmVerifyHelper;
import org.ofdrw.gm.sm2strut.OIDs;
import org.ofdrw.gm.sm2strut.SignedData;
import org.ofdrw.gm.sm2strut.builder.SignedDataBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

/**
 * 国密 SM2 + SM3 OFD 完整性保护签名（轻量级 BC API 版本）
 * <p>
 * 与 {@link GMProtectSigner}（JCE 入口）行为完全一致，但：
 * <ul>
 *     <li>构造参数：{@link X509CertificateHolder} + {@link ECPrivateKeyParameters}（BC 轻量级），
 *         不是 {@code java.security.cert.Certificate} + {@code PrivateKey}（JCE）</li>
 *     <li>SM3 摘要：{@code GmVerifyHelper.sm3()}（轻量级），
 *         不是 {@code new SM3.Digest()}（JCE 入口）</li>
 *     <li>SM2 签名：{@code GmVerifyHelper.sm3WithSm2Sign()}（轻量级），
 *         不是 {@code Signature.getInstance("SM3WithSM2", "BC")}（JCE 入口）</li>
 *     <li>SignedData 构造：{@code SignedDataBuilder.signedDataFromHolder()}（不走 JcaX509CertificateConverter）</li>
 * </ul>
 * <p>
 * 这样可以让 {@code ofd-cli} native binary（GraalVM closed-world）下也跑
 * {@code validate --apply}。
 * <p>
 * 兼容性：与 {@link GMProtectSigner} 产物 byte-for-byte 相同（同 SM3 + SM2 + ASN.1 DER）。
 * 生成的 OFDEntries.xml + signedvalue.dat 同样能被 {@link GMProtectVerifier}（已走轻量级）
 * 验证通过。
 *
 * @author Mavis
 * @since 2.4.0-openpdf.7
 */
public class GMProtectSignerLight implements ProtectSigner {

    /**
     * 版式文件合成者的签名私钥（BC 轻量级 / SM2）
     */
    private final ECPrivateKeyParameters privateKey;

    /**
     * 版式文件合成者的公钥证书（BC 轻量级 / X.509）
     */
    private final X509CertificateHolder certHolder;

    /**
     * 创建一个轻量级完整性保护签名实现
     *
     * @param certHolder 签名证书（X.509 / SM2）
     * @param privateKey 签名私钥（EC / SM2）
     */
    public GMProtectSignerLight(X509CertificateHolder certHolder, ECPrivateKeyParameters privateKey) {
        if (certHolder == null) {
            throw new IllegalArgumentException("签名使用证书（certHolder）不能为空");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("签名使用私钥（privateKey）不能为空");
        }
        this.certHolder = certHolder;
        this.privateKey = privateKey;
    }

    /**
     * 根据 GM/T 0099 OFD 完整性保护协议 7.4.3 中的 c) d) 步骤。
     * <p>
     * c) 根据签名方案，计算完整性保护文件的杂凑值（SM3，轻量级）；
     * d) 根据签名方案，使用版式文件合成者的签名私钥对杂凑值进行数字签名（SM2 + SM3，轻量级）。
     *
     * @param tbs 待签名文件路径（OFDEntries.xml）
     * @return 签名值应符合 GB/T 35275 标准（ContentInfo DER 编码）
     * @throws GeneralSecurityException 安全计算异常
     * @throws IOException              IO 读写异常
     */
    @Override
    public byte[] digestThenSign(Path tbs) throws GeneralSecurityException, IOException {
        // c) 杂凑算法采用 SM3（轻量级 API，不走 JCE provider）
        final byte[] raw = Files.readAllBytes(tbs);
        final byte[] plaintext = GmVerifyHelper.sm3(raw);

        // d) 签名算法采用 SM2 + SM3（轻量级 API）
        final byte[] signature;
        try {
            signature = GmVerifyHelper.sm3WithSm2Sign(privateKey, plaintext);
        } catch (Exception e) {
            throw new GeneralSecurityException("SM2 签名失败: " + e.getMessage(), e);
        }

        // 构造 GB/T 35275 数据格式（走 signedDataFromHolder，不转 JCE Certificate）
        final SignedData signedData = SignedDataBuilder.signedDataFromHolder(plaintext, signature, certHolder);
        final ContentInfo ci = new ContentInfo(OIDs.signedData, signedData);
        return ci.getEncoded();
    }
}
