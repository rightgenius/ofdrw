package org.ofdrw.sign.verify;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.dom4j.DocumentException;
import org.ofdrw.core.basicType.ST_Loc;
import org.ofdrw.core.signatures.SigType;
import org.ofdrw.core.signatures.Signatures;
import org.ofdrw.core.signatures.appearance.Seal;
import org.ofdrw.core.signatures.range.Reference;
import org.ofdrw.core.signatures.range.References;
import org.ofdrw.core.signatures.sig.Signature;
import org.ofdrw.core.signatures.sig.SignedInfo;
import org.ofdrw.gm.ses.parse.SESVersion;
import org.ofdrw.gm.ses.parse.SESVersionHolder;
import org.ofdrw.gm.ses.parse.VersionParser;
import org.ofdrw.gm.ses.v4.SES_Signature;
import org.ofdrw.gm.ses.v4.SESeal;
import org.ofdrw.gm.sm2strut.GmVerifyHelper;
import org.ofdrw.pkg.container.OFDDir;
import org.ofdrw.reader.BadOFDException;
import org.ofdrw.reader.OFDReader;
import org.ofdrw.reader.ResourceLocator;
import org.ofdrw.sign.verify.exceptions.DocNotSignException;
import org.ofdrw.sign.verify.exceptions.FileIntegrityException;
import org.ofdrw.sign.verify.exceptions.OFDVerifyException;
import org.ofdrw.sign.verify.exceptions.InvalidSignedValueException;

import java.io.Closeable;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;
import java.util.List;

/**
 * OFD 电子签名验证引擎
 *
 * @author 权观宇
 * @since 2020-04-22 10:33:26
 */
public class OFDValidator implements Closeable {

    /**
     * OFD虚拟容器
     */
    private OFDDir ofdDir;
    /**
     * OFD解析器
     */
    private final OFDReader reader;

    /**
     * 资源定位器
     * <p>
     * 用于根据路径获取资源
     */
    private final ResourceLocator rl;

    /**
     * 电子印章
     */
    private SignedDataValidateContainer validator;

    /**
     * 创建一个OFD验证引擎
     *
     * @param reader OFD解析器
     */
    public OFDValidator(OFDReader reader) {
        this.reader = reader;
        ofdDir = reader.getOFDDir();
        rl = reader.getResourceLocator();
    }


    /**
     * 执行OFD电子签名验证
     *
     * @throws OFDVerifyException       验证异常，电子签名失效
     * @throws DocNotSignException      文件未进行电子签名
     * @throws IOException              文件读写过程中IO异常
     * @throws NoSuchAlgorithmException 未知的杂凑算法
     */
    public void exeValidate() throws OFDVerifyException, IOException, GeneralSecurityException {
        rl.save();
        try {
            rl.cd("/");
            // 获取电子签名列表文件路径
            final ST_Loc signsListLoc = reader.getDefaultDocSignaturesPath();
            if (signsListLoc == null) {
                throw new DocNotSignException("文件未进行电子签名");
            }

            // 获取签名列表
            Signatures sigList = rl.get(signsListLoc, Signatures::new);

            // 切换目录到 签名列表文件所处目录 “/Doc_0/Signs”
            rl.cd(signsListLoc.parent());
            // 获取签名记录列表
            List<org.ofdrw.core.signatures.Signature> signatures = sigList.getSignatures();
            if (signatures == null || signatures.size() == 0) {
                throw new DocNotSignException("文件未进行电子签名");
            }
            for (org.ofdrw.core.signatures.Signature sigRecord : signatures) {
                // 获取签章类型
                SigType type = sigRecord.getType();
                // 获取 Signature.xml 文件路径
                ST_Loc signFileLoc = sigRecord.getBaseLoc();
                Path signatureFilePath = rl.getFile(signFileLoc);
                Signature sig = rl.get(signFileLoc, Signature::new);
                rl.save();
                try {
                    rl.cd(signFileLoc.parent());
                    // 1. 检查文件完整性
                    checkFileIntegrity(sig);

                    // 获取 SignedValue.dat 文件路径
                    Path signedValueFilePath = rl.getFile(sig.getSignedValue());
                    if (type == null || type == SigType.Seal) {
                        Seal seal = sig.getSignedInfo().getSeal();
                        /*
                         * 由于 Seal节点在OFD中是可选节点，即便是电子签章也为可选，
                         * 所以这里只有在该元素存在的情况在进行匹配检查。
                         */
                        if (seal != null) {
                            // 获取电子印章 Seal.esl 文件路径
                            Path sealFilePath = rl.getFile(seal.getBaseLoc());
                            // 2. 检查印章匹配
                            boolean sealMatch = checkSealMatch(sealFilePath, signedValueFilePath);
                            if (!sealMatch) {
                                throw new GeneralSecurityException("印章(Seal.esl)与电子签章数据(SignedValue.dat)中的印章不匹配");
                            }
                        }
                    }
                    // 签名算法名称
                    String alg = sig.getSignedInfo().getSignatureMethod();
                    // 3. 验证电子签名或签章数据
                    checkSignedValue(type, alg, signatureFilePath, signedValueFilePath);
                } finally {
                    rl.restore();
                }
            }
        } catch (DocumentException | FileNotFoundException e) {
            throw new BadOFDException("OFD文件内部结构错误，无法解析。", e);
        } finally {
            rl.restore();
        }
    }

    /**
     * 设置用于电子签章数据验证的容器
     *
     * @param validator 验证容器
     * @return this
     */
    public OFDValidator setValidator(SignedDataValidateContainer validator) {
        if (validator == null) {
            throw new IllegalArgumentException("电子签章数据验证容器（validator）为空");
        }
        this.validator = validator;
        return this;
    }

    /**
     * 检查电子签章数据
     *
     * @param type              验证类型 数字签名/电子签章
     * @param alg               算法名称
     * @param signatureFilePath 签名文件（Signature.xml）路径
     * @param signedValuePath   签名值文件（SignedValue.dat）路径
     * @throws InvalidSignedValueException 电子签章数据失效
     * @throws IOException                 IO异常
     */
    public void checkSignedValue(SigType type, String alg, Path signatureFilePath, Path signedValuePath) throws IOException, GeneralSecurityException {
        if (validator == null) {
            throw new IllegalArgumentException("电子签章数据验证容器（validator）为空,Call #setValidator");
        }
        if (type == null) {
            type = SigType.Seal;
        }
        validator.validate(type,
                alg,
                Files.readAllBytes(signatureFilePath),
                Files.readAllBytes(signedValuePath));
    }

    /**
     * 检查被保护文件的完整性（是否被篡改）
     * <p>
     * 2.4.0-openpdf.5 起改用 BC 轻量级 API（GmVerifyHelper.newSm3），
     * 不再持有 {@code BouncyCastleProvider} 字段，
     * 让 {@code ofd-cli} native binary（GraalVM closed-world）下也能跑
     * {@code OFDValidator}。SHA-1 / SHA-256 / MD5 等仍走 JDK 内置 provider。
     *
     * @param sig 签名描述文件的根节点对象
     * @throws FileIntegrityException 文件被篡改
     * @throws IOException            文件读写IO异常 / 杂凑算法不支持
     */
    private void checkFileIntegrity(Signature sig)
            throws FileIntegrityException, IOException {

        final SignedInfo signedInfo = sig.getSignedInfo();
        final References references = signedInfo.getReferences();
        final String checkMethod = references.getCheckMethod();
        for (Reference ref : references.getReferences()) {
            ST_Loc fileRef = ref.getFileRef();
            Path file = rl.getFile(fileRef);
            // 获取预期的文件杂凑值
            byte[] expectDataHash = ref.getCheckValue();
            byte[] actualDataHash = hashFile(file, checkMethod);
            // 比对杂凑值是否一致
            if (!Arrays.equals(expectDataHash, actualDataHash)) {
                throw new FileIntegrityException(fileRef, expectDataHash, actualDataHash);
            }
        }
    }

    /**
     * 计算文件摘要。SM3 走 {@link GmVerifyHelper#newSm3()}（BC 轻量级 API），
     * 其他算法走 JDK 内置 provider（不再注册 BC provider）。
     * <p>
     * 摘要算法名支持：字符串名（"SM3" / "SHA-256" / "SHA-1" / "MD5"）和
     * OID（"1.2.156.10197.1.401" 是 SM3，"2.16.840.1.101.3.4.2.1" 是 SHA-256）。
     *
     * @param file   待计算文件
     * @param method 摘要算法名或 OID
     * @return 摘要值
     * @throws IOException 算法不支持或文件读写异常
     */
    private static byte[] hashFile(Path file, String method) throws IOException {
        // 兼容字符串名和 OID 两种写法
        if ("SM3".equalsIgnoreCase(method) || GMObjectIdentifiers.sm3.getId().equals(method)) {
            SM3Digest d = GmVerifyHelper.newSm3();
            try (InputStream in = Files.newInputStream(file)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) {
                    d.update(buf, 0, n);
                }
            }
            byte[] out = new byte[d.getDigestSize()];
            d.doFinal(out, 0);
            return out;
        }
        try {
            // OID 形式（"1.2.156.10197.1.401" 等）转成可读算法名
            String algorithmName = method;
            if (method != null && method.matches("^[0-9.]+$")) {
                // 是 OID，转算法名
                java.security.MessageDigest tmp;
                try {
                    tmp = MessageDigest.getInstance(method);
                    algorithmName = tmp.getAlgorithm();
                } catch (NoSuchAlgorithmException ignore) {
                    // fall through，下面会再抛
                }
            }
            MessageDigest md = MessageDigest.getInstance(algorithmName);
            try (InputStream in = Files.newInputStream(file)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) {
                    md.update(buf, 0, n);
                }
            }
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("不支持的杂凑算法: " + method, e);
        }
    }


    /**
     * 电子印章与电子签章数据的匹配性检查
     *
     * @param sealPath        电子印章文件路径
     * @param signedValuePath 电子签章数据路径
     * @return true - 匹配；false - 不匹配
     * @throws IOException        文件流操作异常
     * @throws OFDVerifyException 未知的电子签章数据版本，无法解析
     */
    private boolean checkSealMatch(Path sealPath, Path signedValuePath) throws IOException, OFDVerifyException {
        final byte[] sesSignatureBin = Files.readAllBytes(signedValuePath);
        byte[] expect = null;
        // 解析电子印章版本
        SESVersionHolder v = VersionParser.parseSES_SignatureVersion(sesSignatureBin);
        if (v.getVersion() == SESVersion.v4) {
            SES_Signature sesSignature = SES_Signature.getInstance(v.getObjSeq());
            SESeal eseal = sesSignature.getToSign().getEseal();
            expect = eseal.getEncoded("DER");
        } else if (v.getVersion() == SESVersion.v5) {
            org.ofdrw.gm.ses.v5.SES_Signature sesSignature
                    = org.ofdrw.gm.ses.v5.SES_Signature.getInstance(v.getObjSeq());
            org.ofdrw.gm.ses.v5.SESeal eseal = sesSignature.getToSign().getEseal();
            expect = eseal.getEncoded("DER");
        } else if (v.getVersion() == SESVersion.v1) {
            org.ofdrw.gm.ses.v1.SES_Signature sesSignature
                    = org.ofdrw.gm.ses.v1.SES_Signature.getInstance(v.getObjSeq());
            org.ofdrw.gm.ses.v1.SESeal eseal = sesSignature.getToSign().getEseal();
            expect = eseal.getEncoded("DER");
        } else {
            throw new OFDVerifyException("未知的电子签章数据版本，无法解析");
        }
        byte[] sealBin = Files.readAllBytes(sealPath);
        return Arrays.equals(expect, sealBin);
    }


    @Override
    public void close() throws IOException {
        reader.close();
    }
}
