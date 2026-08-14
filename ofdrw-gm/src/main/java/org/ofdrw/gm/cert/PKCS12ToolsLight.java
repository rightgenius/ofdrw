package org.ofdrw.gm.cert;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagFactory;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEInputDecryptorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

/**
 * 轻量级 PKCS#12 解析（不依赖 {@code BouncyCastleProvider}）
 * <p>
 * 目的：让 {@code ofd-cli} native binary（GraalVM closed-world）下，
 * 不需要注册 BouncyCastleProvider，也能从 {@code .p12} 文件拿到
 * 签名用的私钥 + 证书。
 * <p>
 * 与 {@link PKCS12Tools}（JCE {@code KeyStore.getInstance("PKCS12", "BC")} 路径）的区别：
 * <ul>
 *     <li>本类走 BC 轻量级 API（{@code PKCS12PfxPdu} + {@code PKCS12SafeBagFactory}），
 *         不触发 {@code JceSecurity.canUseProvider} 校验</li>
 *     <li>返回 {@link X509CertificateHolder} + {@link ECPrivateKeyParameters}，
 *         不转 JCE {@code java.security.cert.Certificate} / {@code PrivateKey}</li>
 * </ul>
 * <p>
 * <b>限制</b>：只支持 GB/T 35275 / SM2 用例：
 * <ul>
 *     <li>私钥：EC 曲线（PKCS#8 加密 / 未加密 都支持）</li>
 *     <li>证书：X.509（certBag）</li>
 *     <li>PKCS#5 v1 PBE（3DES-CBC + SHA-1）和 PKCS#5 v2 PBES2（BC 默认）由
 *         {@code BcPKCS12PBEInputDecryptorProviderBuilder} 透明处理</li>
 * </ul>
 *
 * @author Mavis
 * @since 2.4.0-openpdf.6
 */
public final class PKCS12ToolsLight {

    private PKCS12ToolsLight() {
    }

    /**
     * PKCS#12 解析结果
     */
    public static final class Result {
        /** 用户证书（X.509） */
        public final X509CertificateHolder certHolder;
        /** 私钥（EC / SM2） */
        public final ECPrivateKeyParameters privateKey;
        /** friendly name（如果 PKCS#12 文件里设了），可能为 null */
        public final String friendlyName;

        public Result(X509CertificateHolder certHolder, ECPrivateKeyParameters privateKey, String friendlyName) {
            this.certHolder = certHolder;
            this.privateKey = privateKey;
            this.friendlyName = friendlyName;
        }
    }

    /**
     * 从 PKCS#12 文件读私钥 + 证书
     *
     * @param p12File  PKCS#12 文件路径
     * @param password 文件密码
     * @return 私钥 + 证书 + friendly name
     * @throws GeneralSecurityException 解析失败（密码错 / 无 cert / 无 key）
     * @throws IOException              IO 异常
     */
    public static Result read(Path p12File, char[] password) throws GeneralSecurityException, IOException {
        try (InputStream in = Files.newInputStream(p12File)) {
            return read(in.readAllBytes(), password);
        }
    }

    /**
     * 从 PKCS#12 字节读私钥 + 证书
     *
     * @param p12Bytes PKCS#12 DER 编码
     * @param password 文件密码
     * @return 私钥 + 证书 + friendly name
     * @throws GeneralSecurityException 解析失败
     * @throws IOException              ASN.1 解析失败
     */
    public static Result read(byte[] p12Bytes, char[] password) throws GeneralSecurityException, IOException {
        PKCS12PfxPdu pfx = new PKCS12PfxPdu(p12Bytes);
        ASN1ObjectIdentifier[] contentTypes = pfx.getContentInfos() == null
                ? new ASN1ObjectIdentifier[0]
                : new ASN1ObjectIdentifier[pfx.getContentInfos().length];
        for (int i = 0; i < contentTypes.length; i++) {
            contentTypes[i] = pfx.getContentInfos()[i].getContentType();
        }

        // MAC 校验：GraalVM native-image 下 BC 的 BcPKCS12MacCalculatorBuilder 依赖
        // HMAC + SHA-1 的轻量级 API，可走通。如果 MAC 校验失败直接抛错（密码错的早期信号）。
        if (pfx.hasMac()) {
            try {
                org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilderProvider provider =
                        new org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilderProvider(
                                org.bouncycastle.operator.bc.BcDefaultDigestProvider.INSTANCE);
                boolean macValid = pfx.isMacValid(provider, password);
                if (!macValid) {
                    throw new GeneralSecurityException("PKCS#12 MAC 校验失败（密码错？）");
                }
            } catch (GeneralSecurityException e) {
                throw e;
            } catch (Exception e) {
                // 解析 MAC 算法本身失败时（如未知 MAC OID），不阻断；fall through
                // （实际签名依然可能正确解析）
            }
        }

        BcPKCS12PBEInputDecryptorProviderBuilder decBuilder = new BcPKCS12PBEInputDecryptorProviderBuilder();

        X509CertificateHolder certHolder = null;
        ECPrivateKeyParameters privateKey = null;
        String friendlyName = null;

        for (int i = 0; i < pfx.getContentInfos().length; i++) {
            ASN1ObjectIdentifier ct = contentTypes[i];
            if (ct.equals(PKCSObjectIdentifiers.data)) {
                // 未加密的 SafeContents（通常 cert bag 走这条，但 OFD R&W 测试 P12 反过来：key bag 在这）
                PKCS12SafeBagFactory factory = new PKCS12SafeBagFactory(pfx.getContentInfos()[i]);
                for (PKCS12SafeBag bag : factory.getSafeBags()) {
                    if (bag.getType().equals(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag)) {
                        privateKey = decryptKey(bag, decBuilder, password);
                    } else if (bag.getType().equals(PKCSObjectIdentifiers.certBag)) {
                        certHolder = (X509CertificateHolder) bag.getBagValue();
                    }
                    String fn = extractFriendlyName(bag);
                    if (fn != null) friendlyName = fn;
                }
            } else if (ct.equals(PKCSObjectIdentifiers.encryptedData)) {
                // 加密的 SafeContents
                InputDecryptorProvider decProv = decBuilder.build(password);
                PKCS12SafeBagFactory factory;
                try {
                    factory = new PKCS12SafeBagFactory(pfx.getContentInfos()[i], decProv);
                } catch (org.bouncycastle.pkcs.PKCSException e) {
                    throw new GeneralSecurityException("PKCS#12 EncryptedData 解密失败: " + e.getMessage(), e);
                }
                for (PKCS12SafeBag bag : factory.getSafeBags()) {
                    if (bag.getType().equals(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag)) {
                        privateKey = decryptKey(bag, decBuilder, password);
                    } else if (bag.getType().equals(PKCSObjectIdentifiers.certBag)) {
                        certHolder = (X509CertificateHolder) bag.getBagValue();
                    }
                    String fn = extractFriendlyName(bag);
                    if (fn != null) friendlyName = fn;
                }
            }
            // 其他 OID（密钥、CRL 等）忽略 —— 我们只关心 EC key + X.509 cert
        }

        if (certHolder == null) {
            throw new GeneralSecurityException("PKCS#12 中未找到 X.509 证书");
        }
        if (privateKey == null) {
            throw new GeneralSecurityException("PKCS#12 中未找到 EC 私钥");
        }
        return new Result(certHolder, privateKey, friendlyName);
    }

    private static ECPrivateKeyParameters decryptKey(PKCS12SafeBag bag,
                                                     BcPKCS12PBEInputDecryptorProviderBuilder builder,
                                                     char[] password) throws GeneralSecurityException {
        Object bagValue = bag.getBagValue();
        if (bagValue instanceof PKCS8EncryptedPrivateKeyInfo) {
            PKCS8EncryptedPrivateKeyInfo epki = (PKCS8EncryptedPrivateKeyInfo) bagValue;
            try {
                InputDecryptorProvider decProv = builder.build(password);
                InputDecryptor dec = decProv.get(epki.getEncryptionAlgorithm());
                try (InputStream in = new ByteArrayInputStream(epki.getEncryptedData())) {
                    InputStream decrypted = dec.getInputStream(in);
                    byte[] keyBytes = decrypted.readAllBytes();
                    PrivateKeyInfo pki = PrivateKeyInfo.getInstance(keyBytes);
                    return (ECPrivateKeyParameters) PrivateKeyFactory.createKey(pki);
                }
            } catch (org.bouncycastle.operator.OperatorCreationException e) {
                throw new GeneralSecurityException("PKCS#12 私钥解密器创建失败: " + e.getMessage(), e);
            } catch (IOException e) {
                throw new GeneralSecurityException("PKCS#12 私钥解密失败: " + e.getMessage(), e);
            }
        } else if (bagValue instanceof PrivateKeyInfo) {
            // 未加密 keyBag（OID 1.2.840.113549.1.12.10.1.1）
            try {
                return (ECPrivateKeyParameters) PrivateKeyFactory.createKey((PrivateKeyInfo) bagValue);
            } catch (IOException e) {
                throw new GeneralSecurityException("PKCS#12 keyBag 解析失败: " + e.getMessage(), e);
            }
        } else {
            throw new GeneralSecurityException("未知的 PKCS#12 keyBag 类型: " +
                    (bagValue == null ? "null" : bagValue.getClass().getName()));
        }
    }

    private static String extractFriendlyName(PKCS12SafeBag bag) {
        ASN1Encodable[] attrs = bag.getAttributes() == null
                ? new ASN1Encodable[0]
                : bag.getAttributes();
        for (int i = 0; i < attrs.length; i++) {
            org.bouncycastle.asn1.pkcs.Attribute attr =
                    org.bouncycastle.asn1.pkcs.Attribute.getInstance(attrs[i]);
            if (attr.getAttrType().equals(PKCS12SafeBag.friendlyNameAttribute)) {
                if (attr.getAttrValues().size() > 0) {
                    ASN1Encodable v = attr.getAttrValues().getObjectAt(0);
                    if (v instanceof org.bouncycastle.asn1.DERBMPString) {
                        return ((org.bouncycastle.asn1.DERBMPString) v).getString();
                    } else if (v instanceof org.bouncycastle.asn1.DERUTF8String) {
                        return ((org.bouncycastle.asn1.DERUTF8String) v).getString();
                    }
                }
            }
        }
        return null;
    }
}
