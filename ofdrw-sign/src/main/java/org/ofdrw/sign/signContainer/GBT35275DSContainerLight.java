package org.ofdrw.sign.signContainer;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.util.encoders.Base64;
import org.ofdrw.core.signatures.SigType;
import org.ofdrw.gm.sm2strut.ContentInfo;
import org.ofdrw.gm.sm2strut.GmVerifyHelper;
import org.ofdrw.gm.sm2strut.OIDs;
import org.ofdrw.gm.sm2strut.SignedData;
import org.ofdrw.gm.sm2strut.builder.SignedDataBuilder;
import org.ofdrw.sign.ExtendSignatureContainer;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

/**
 * GB/T 35275 数字签名容器（轻量级 BC API 版本）
 * <p>
 * 与 {@link GBT35275DSContainer}（JCE 入口）行为完全一致，但：
 * <ul>
 *     <li>构造参数：{@link X509CertificateHolder} + {@link ECPrivateKeyParameters}（BC 轻量级），
 *         不是 {@code java.security.cert.Certificate} + {@code PrivateKey}（JCE）</li>
 *     <li>SM3 摘要：{@code GmVerifyHelper.sm3()}（轻量级），
 *         不是 {@code new SM3.Digest()}（JCE 入口）</li>
 *     <li>SM2 签名：{@code GmVerifyHelper.sm3WithSm2Sign()}（轻量级），
 *         不是 {@code Signature.getInstance(alg, "BC")}（JCE 入口）</li>
 * </ul>
 * <p>
 * 这样可以让 {@code ofd-cli} native binary（GraalVM closed-world）下也跑 sign。
 * <p>
 * 对应 verify：{@code GBT35275Validate} 已经走轻量级 API，可以直接验 {@link GBT35275DSContainerLight} 的产物。
 *
 * @author Mavis
 * @since 2.4.0-openpdf.6
 */
public class GBT35275DSContainerLight implements ExtendSignatureContainer {

    private final ECPrivateKeyParameters prvKey;
    private final X509CertificateHolder certHolder;
    private boolean enableFileHashBase64;

    /**
     * 创建一个轻量级数字签名容器
     *
     * @param certHolder 签名者证书（X.509 / SM2）
     * @param prvKey     私钥（EC / SM2）
     */
    public GBT35275DSContainerLight(X509CertificateHolder certHolder, ECPrivateKeyParameters prvKey) {
        if (certHolder == null) {
            throw new IllegalArgumentException("签名使用证书（certHolder）不能为空");
        }
        if (prvKey == null) {
            throw new IllegalArgumentException("签名使用私钥（prvKey）不能为空");
        }
        this.certHolder = certHolder;
        this.prvKey = prvKey;
        this.enableFileHashBase64 = false;
    }

    @Override
    public java.security.MessageDigest getDigestFnc() {
        // OFDSigner 用这个 MessageDigest 算 OFD 内每个被保护文件的 SM3 hash（写 Signature.xml 的 References）。
        // 这里用 JCE 的 SM3.Digest 是 OK 的：MessageDigest.getInstance(...) 的常规 digest() 调用
        // 不走 JceSecurity.canUseProvider 校验，只有 Signature.getInstance(..., "BC") 这种
        // "显式要求 BC provider" 的调用才被 closed-world 拦截。
        return new org.bouncycastle.jcajce.provider.digest.SM3.Digest();
    }

    @Override
    public ASN1ObjectIdentifier getSignAlgOID() {
        return GMObjectIdentifiers.sm2sign_with_sm3;
    }

    @Override
    public byte[] sign(InputStream inData, String propertyInfo) throws GeneralSecurityException, IOException {
        // d) 计算 SM3 摘要（轻量级 API）
        byte[] plaintext = GmVerifyHelper.sm3(IOUtils.toByteArray(inData));
        if (this.enableFileHashBase64) {
            plaintext = Base64.encode(plaintext);
        }

        // e) SM2 私钥签名（轻量级 API）
        final byte[] signature;
        try {
            signature = GmVerifyHelper.sm3WithSm2Sign(prvKey, plaintext);
        } catch (Exception e) {
            throw new GeneralSecurityException("SM2 签名失败: " + e.getMessage(), e);
        }

        // f) 组装 SignedData
        // 现有 SignedDataBuilder.signedData 接受 java.security.cert.Certificate，
        // 我们在 native 路径下没法走 JCA conversion。这里直接构造 ContentInfo + SignedData：
        // 因为 certHolder 是 X509CertificateHolder，SignedDataBuilder 也可以接 BC 对象。
        // ——但 SignedDataBuilder 强类型是 Certificate（JCE）——我们用 builder 内部走 ASN.1 round-trip
        // 走不通 native 路径，所以这里手动构造：
        final SignedData signedData = SignedDataBuilder.signedDataFromHolder(plaintext, signature, certHolder);
        ContentInfo contentInfo = new ContentInfo(OIDs.signedData, signedData);
        return contentInfo.getEncoded();
    }

    @Override
    public byte[] getSeal() {
        return null;
    }

    @Override
    public SigType getSignType() {
        return SigType.Sign;
    }

    public void setEnableFileHashBase64(boolean state) {
        this.enableFileHashBase64 = state;
    }
}
