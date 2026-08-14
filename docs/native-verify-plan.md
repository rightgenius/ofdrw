# Native Verify 设计计划：让 ofd-cli 的 `verify` / `validate` 在 GraalVM native-image 跑通

> **作者**：Mavis (ofd-cli 维护者)
> **目标分支**：`feature/native-verify`（基于 `feature/openpdf-replacement` HEAD `b5b2bc61`）
> **关联项目**：[rightgenius/ofd-cli](https://github.com/rightgenius/ofd-cli)
> **状态**：草案 v1

---

## 1. 背景

`ofd-cli` v0.1.6 的 native binary **故意不注册** 5 个子命令，其中 3 个 (`sign` / `verify` / `validate`) 是因为走的 JCE provider API 在 GraalVM 25.0.4 的 closed-world `JceSecurity.getVerificationResult` 校验里失败。

但 `ofd-cli` v0.1.6 的 `encrypt` / `decrypt` 同样在 native binary 跑通了 —— 因为 ofdrw-crypto 的 `UserPasswordEncryptor` 走的是 BouncyCastle 的**轻量级 crypto API**（`org.bouncycastle.crypto.*`），根本不碰 `java.security.Security`。

**核心想法**：把 `verify` / `validate` 也迁到 BC 轻量级 API，绕过 closed-world provider 校验，让这 3 个子命令从 native binary 也能跑。

---

## 2. 现状盘点

### 2.1 `ofd-cli` native binary 限制（v0.1.6）

| 子命令 | native | fat-jar | 根因 |
|---|:---:|:---:|---|
| `version` / `info` / `to-png` / `to-pdf` / `extract` / `merge` / `encrypt` / `decrypt` | ✅ | ✅ | 无 JCE 依赖或走轻量级 API |
| `sign` / `verify` / `validate` | ❌ 不注册 | ✅ | JCE `Signature.getInstance(alg, "BC")` + `JceSecurity.canUseProvider` 校验失败 |
| `to-html` / `to-svg` | ❌ 不注册 | ✅ | AWTMaker 父类触发 `sun/font/CFontManager` JNI（AWT 限制，**不在本文档范围**）|

### 2.2 `verify` 路径的 JCE 依赖

跟了一下 `ofd-cli verify <file>` 的完整调用链，JCE provider 依赖有 **3 处**：

| # | 文件:行 | 代码 | 影响范围 |
|---|---|---|---|
| ① | `ofdrw-gm/.../sm2strut/GBT35275Validate.java:113` | `Signature.getInstance(alg, new BouncyCastleProvider())`<br>`sg.initVerify(cert.getPublicKey())`<br>`sg.update(plaintext)`<br>`sg.verify(signature)` | **核心**：直接调 JCE `Signature` API |
| ② | `ofdrw-gm/.../cert/CertTools.java:48` | `new JcaX509CertificateConverter().setProvider("BC")`<br>`.getCertificate(new X509CertificateHolder(certificate))` | **间接**：把 BC 的 ASN.1 cert 转成 JCA `java.security.cert.Certificate` 给 ① 用 |
| ③ | `ofdrw-sign/.../verify/OFDValidator.java:207` | `MessageDigest.getInstance(checkMethod, provider)` | **间接**：从 OFD 拿 `References/CheckMethod`（通常是 `SM3` 或 `SHA-256`），通过 BC provider 解析 |

### 2.3 `verify` 路径的 BC 轻量级 API 替代方案

| JCE 调用 | 轻量級 API 替代 | BC 类 |
|---|---|---|
| ① `Signature.getInstance("SM3withSM2", "BC")` + `.initVerify(pubKey)` | `new SM2Signer()` + `.init(false, pubKeyParams)` | `org.bouncycastle.crypto.signers.SM2Signer` |
| ① `.update(plaintext)` | `.update(plaintext, 0, len)` | 同上 |
| ① `.verify(signature)` | `.verifySignature(signature)` | 同上 |
| ② `JcaX509CertificateConverter` | `X509CertificateHolder` + `PublicKeyFactory.createKey(spki)` | `org.bouncycastle.cert.X509CertificateHolder` + `org.bouncycastle.crypto.util.PublicKeyFactory` |
| ③ `MessageDigest.getInstance("SM3", "BC")` | `new SM3.Digest()` | `org.bouncycastle.crypto.digests.SM3Digest` |
| ③ `MessageDigest.getInstance("SHA-256", "BC")` | `MessageDigest.getInstance("SHA-256")`（JDK 内置） | JDK 自带 |

**关键观察**：② 的 BC 替代方案里 `X509CertificateHolder` **已经存在**于 verify 调用路径（`CertTools.java:6` import 了），只是被 `JcaX509CertificateConverter` 包了一层。把这层包装去掉就行，**不需要重新实现 X.509 解析**。

---

## 3. 目标

让 `ofd-cli` v0.2.0 的 native binary **注册并跑通** `verify` / `validate` 子命令。

- `verify <file>` → 输出 `VALID` / `UNSIGNED` / `INVALID`，exit code 0/0/1
- `validate <file>` → 输出 GM/T 0099 完整性检查结果，exit code 0
- 与 fat-jar 在同一份测试 OFD 上**输出一致**

`sign` 不在本文档范围（需要 PKCS#12 私钥 + `JcaX509CertificateConverter` 写证书，JCE 依赖更重，且 fat-jar 路径用得少）。

---

## 4. 设计

### 4.1 新增 `GmVerifyHelper`（在 `ofdrw-gm`）

在 `org.ofdrw.gm.sm2strut` 包下加一个工具类，集中封装"轻量级 API 验签 + 摘要"：

```java
package org.ofdrw.gm.sm2strut;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class GmVerifyHelper {
    private GmVerifyHelper() {}

    /** SM3withSM2 验签。plaintext 是 authenticated-attributes DER 编码；signature 是密文摘要。 */
    public static boolean sm3WithSm2Verify(X509CertificateHolder holder, byte[] plaintext, byte[] signature) throws Exception {
        ECPublicKeyParameters pubKey = (ECPublicKeyParameters)
                PublicKeyFactory.createKey(holder.getSubjectPublicKeyInfo());
        SM2Signer signer = new SM2Signer();
        signer.init(false, pubKey);
        signer.update(plaintext, 0, plaintext.length);
        return signer.verifySignature(signature);
    }

    /** SM3 摘要。替代 MessageDigest.getInstance("SM3", provider) */
    public static byte[] sm3(byte[] data) {
        SM3Digest d = new SM3Digest();
        d.update(data, 0, data.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    /** 流式 SM3（OFDValidator.checkFileIntegrity 用） */
    public static SM3Digest newSm3() {
        return new SM3Digest();
    }

    /** SHA-256 摘要。替代 MessageDigest.getInstance("SHA-256", provider) */
    public static byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }
}
```

**设计要点**：
- 不动 `org.bouncycastle.jcajce.provider.digest.SM3`（这是 JCE 入口）— 直接用 `org.bouncycastle.crypto.digests.SM3Digest`（轻量级入口）
- `PublicKeyFactory.createKey(spki)` 拿到 `ECPublicKeyParameters`，**完全绕开 JCA 的 `java.security.PublicKey`**
- `SM2Signer` 接受 `ECPublicKeyParameters`，**不需要 `initVerify(cert.getPublicKey())`**

### 4.2 改 `CertTools.obj` 移除 JCE 依赖

**改前**（line 48）：
```java
public static java.security.cert.Certificate obj(Certificate certificate) throws CertificateException {
    return new JcaX509CertificateConverter().setProvider("BC")
            .getCertificate(new X509CertificateHolder(certificate));
}
```

**改后**（返回类型改为 `X509CertificateHolder`，让调用方直接拿 SubjectPublicKeyInfo）：
```java
public static X509CertificateHolder objHolder(Certificate certificate) throws IOException {
    return new X509CertificateHolder(certificate);
}

/** @deprecated 仍保留 JCA 入口以兼容其他模块（sign 路径、PEMLoader 等） */
@Deprecated
public static java.security.cert.Certificate obj(Certificate certificate) throws CertificateException {
    return new JcaX509CertificateConverter().setProvider("BC")
            .getCertificate(new X509CertificateHolder(certificate));
}
```

**风险**：`CertTools.obj` 是 public API，外部代码可能依赖。**保留旧方法 + 加 `@Deprecated`**，新加 `objHolder` 返回轻量级 `X509CertificateHolder`。JCA 入口在 native-image 仍会触发 `JceSecurity.canUseProvider`，但只对**用 `obj()` 的 caller**有影响（sign / PEMLoader / PKCGenerate 都不在 native 注册路径里，所以安全）。

### 4.3 改 `GBT35275Validate.validate` 走轻量级 API

**改前**（line 109-122）：
```java
final java.security.cert.Certificate cert = CertTools.obj(c);
Signature sg = Signature.getInstance(alg, new BouncyCastleProvider());
sg.initVerify(cert.getPublicKey());
sg.update(plaintext);
byte[] signature = signerInfo.getEncryptedDigest().getOctets();
if (!sg.verify(signature)) {
    return VerifyInfo.Err("签名值不一致");
}
```

**改后**：
```java
final X509CertificateHolder holder = CertTools.objHolder(c);
byte[] signature = signerInfo.getEncryptedDigest().getOctets();
if (!GmVerifyHelper.sm3WithSm2Verify(holder, plaintext, signature)) {
    return VerifyInfo.Err("签名值不一致");
}
```

`alg` 字段不再使用（GB/T 35275 写死 SM2+SM3，helper 内部就是 `SM2Signer`）。如果 OFD 里 alg 字段跟实际签名算法不一致，我们 follow `Signature.getInstance(alg, "BC")` 的语义在 helper 里再加 alg 分流（先 PoC 验证 OFD 样本 alg 字段是不是统一 `SM3withSM2`）。

### 4.4 改 `OFDValidator` 摘掉 `BouncyCastleProvider` 字段

**改前**（line 75-77）：
```java
private Provider provider;

public OFDValidator(OFDReader reader) {
    this.reader = reader;
    ofdDir = reader.getOFDDir();
    rl = reader.getResourceLocator();
    provider = new BouncyCastleProvider();
}
```

**改前**（line 207）：
```java
MessageDigest md = MessageDigest.getInstance(checkMethod, provider);
```

**改后**（helper 分流）：
```java
// checkMethod 通常是 "SM3" / "SHA-256" / "SHA-1"
MessageDigest md;
if ("SM3".equalsIgnoreCase(checkMethod)) {
    md = new MessageDigestAdapter(GmVerifyHelper.newSm3());
} else {
    md = MessageDigest.getInstance(checkMethod);  // 走 JDK 自带 provider
}
```

其中 `MessageDigestAdapter` 是把 BC 的 `SM3Digest` 包装成 JDK `MessageDigest` 接口（只实现 `update(byte[], int, int)` + `digest()` 两个方法），这样 `DigestInputStream` 还能用。**或者**更激进：`checkFileIntegrity` 改成不用 `DigestInputStream`，自己手写循环：

```java
for (Reference ref : references.getReferences()) {
    Path file = rl.getFile(fileRef);
    byte[] expectDataHash = ref.getCheckValue();
    SM3Digest d = GmVerifyHelper.newSm3();
    try (InputStream in = Files.newInputStream(file)) {
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            d.update(buf, 0, n);
        }
    }
    byte[] actual = new byte[d.getDigestSize()];
    d.doFinal(actual, 0);
    if (!Arrays.equals(expectDataHash, actual)) {
        throw new FileIntegrityException("...");
    }
}
```

**更倾向后者** —— 不引入新 wrapper 类，控制面更小。

### 4.5 native-image 反射元数据

`ofd-cli` 当前 `src/main/resources/META-INF/native-image/agent-capture/reachability-metadata.json` 是 fat-jar 跑 agent 抓的（1586 行）。`verify` / `validate` 子命令在 fat-jar 不走 native 分支，所以**没抓到**轻量级 API 的反射点。

迁完轻量级 API 后，新增 reflection 元数据需求：

| BC 内部类 | 用途 | 反射方式 |
|---|---|---|
| `org.bouncycastle.crypto.signers.SM2Signer` | 验签 | 直接 `new`，不反射（`new SM2Signer()` 在 `GBT35275Validate` 里）|
| `org.bouncycastle.crypto.signers.SM2Signer$State` | 内部 enum | BC 内部访问，需要反射 |
| `org.bouncycastle.crypto.params.ECPublicKeyParameters` | 验签 | `ECPublicKeyParameters` 构造 / 字段访问 |
| `org.bouncycastle.crypto.digests.SM3Digest` | SM3 摘要 | `new SM3Digest()`，但 `update/doFinal` 调用不反射 |
| `org.bouncycastle.crypto.util.PublicKeyFactory` | 拿 EC 公钥 | `PublicKeyFactory.createKey(spki)` 内部要反射 ASN.1 tag 表 |
| `org.bouncycastle.asn1.x509.SubjectPublicKeyInfo` | 公钥容器 | ASN.1 parser 大量反射 |
| `org.bouncycastle.asn1.ASN1Primitive` 子类 | 证书 DER 解析 | 大量反射 |

**两种走法**：

A. **重新跑 agent 抓**（推荐）：

```bash
# 用 fat-jar 跑 verify 路径，让 agent 抓所有反射
java -agentlib:native-image-agent=config-output-dir=/tmp/agent-new -jar ofd-cli.jar verify /path/to/signed.ofd
java -agentlib:native-image-agent=config-output-dir=/tmp/agent-new -jar ofd-cli.jar validate /path/to/signed.ofd
```

B. **手写 reflect-config.json**：约 30-50 个 entry，工作量大但精确。

**先走 A**，再 diff 现有 `agent-capture/reachability-metadata.json` 跟新抓的，merge 增量的 reflection 条目。

### 4.6 ofd-cli 注册 verify / validate

改 `Main.java`：

```diff
 private static final Class<?>[] NATIVE_SUBCOMMANDS = {
         VersionCommand.class,
         InfoCommand.class,
         ToPngCommand.class,
         ToPdfCommand.class,
         ExtractCommand.class,
         MergeCommand.class,
         EncryptCommand.class,
-        DecryptCommand.class,
+        DecryptCommand.class,
+        VerifyCommand.class,
+        ValidateCommand.class,
 };
```

`SignCommand` 仍不注册（PKCS#12 私钥 + 写证书用 JCE，路径更长）。

---

## 5. 测试

### 5.1 测试资源

- `src/test/resources/helloworld-sign.ofd`（仓库内已有，但要先确认它的签名是 GB/T 35275 数字签名，不是电子印章）
- 如缺，从 ofdrw 上游 / 真实电子发票样本里捞一份 GB/T 35275 数字签名的 OFD

### 5.2 单元测试（在 fork 仓库）

```java
// ofdrw-sign/src/test/java/org/ofdrw/sign/verify/NativeCompatibilityTest.java
@Test
void verifyOnFatJarAndOnLightweight_shouldProduceSameResult() throws Exception {
    Path signed = Paths.get("src/test/resources/helloworld-sign.ofd");
    try (OFDReader reader = new OFDReader(signed)) {
        OFDValidator validator = new OFDValidator(reader);
        validator.setValidator(new GBT35275ValidateContainer());
        // 不抛异常 = VALID
        assertDoesNotThrow(() -> validator.exeValidate());
    }
}
```

### 5.3 ofd-cli 集成测试

```bash
# 1. fat-jar 跑 verify (baseline)
java -jar ofd-cli.jar verify src/test/resources/helloworld-sign.ofd
# → VALID, exit 0

# 2. native binary 跑 verify (target)
./target/ofd verify src/test/resources/helloworld-sign.ofd
# → VALID, exit 0
```

两个输出一致才算通过。

### 5.4 边界 case

- 篡改过的签名 OFD → `INVALID`, exit 1（fat-jar + native 行为一致）
- 没签名的 OFD → `UNSIGNED`, exit 0
- 损坏的 SignedData XML → 抛 `InvalidSignedValueException`, exit 3
- 用电子印章 (SesSignature) 签的 OFD → 当前是 `DocNotSignException`（GBT35275ValidateContainer 只支持 SigType.Sign），保持 fat-jar 行为

---

## 6. 里程碑

| # | commit | 内容 | 预计行数 |
|---|---|---|---|
| M1 | `feat(gm): add GmVerifyHelper lightweight API wrapper` | 新增 `GmVerifyHelper.java` + 单元测试 | +120 / -0 |
| M2 | `refactor(gm): add CertTools.objHolder return X509CertificateHolder` | 新加 `objHolder`，原 `obj` 标 `@Deprecated` | +20 / -0 |
| M3 | `refactor(sign): GBT35275Validate use GmVerifyHelper, drop BCEcdsaSignature` | 改 4 行 | +5 / -8 |
| M4 | `refactor(sign): OFDValidator drop BouncyCastleProvider field, use GmVerifyHelper for SM3` | 改 `checkFileIntegrity` + 构造器 | +30 / -15 |
| M5 | `chore(release): bump version to 2.4.0-openpdf.5` | pom.xml 改 4 个 module | +4 / -4 |
| M6 | `test(sign): add NativeCompatibilityTest verifying fat-jar/native consistency` | 单元测试 | +60 / -0 |
| M7 | (ofd-cli) `chore(deps): bump rightgenius/ofdrw to 2.4.0-openpdf.5` | pom.xml 改 dependency | +1 / -1 |
| M8 | (ofd-cli) `feat(native): register VerifyCommand/ValidateCommand in native binary` | Main.java | +2 / -0 |
| M9 | (ofd-cli) `chore(reflect): add BC lightweight API reflection entries` | reflect-config.json | +50 / -0 |
| M10 | (ofd-cli) `chore(release): v0.2.0` | pom.xml + release notes | +10 / -0 |

预估总工作量：~10 commits, ~300 行 Java 改 fork + ~100 行改 ofd-cli。

---

## 7. 风险与回退

| 风险 | 缓解 | 回退 |
|---|---|---|
| `X509CertificateHolder` 拿公钥在某些边缘 cert 上失败（罕见 non-EC 算法） | PoC 阶段先用真实 GB/T 35275 OFD 跑通；不通过就在 helper 里加 `KeyFactory.getInstance("EC")` 兜底（但 EC KeyFactory 走 JDK 不走 BC，应该 OK） | 改回 `JcaX509CertificateConverter`，把 verify 仍放 fat-jar |
| `alg` 字段在 OFD 里不一定是 `SM3withSM2`，可能 `SM3WithSM2` / `1.2.156.10197.1.501` 等变体 | helper 内部写死 `SM2Signer`（GB/T 35275 唯一标准），如果 OFD 里 alg 不符则报错 | 在 helper 加 alg 字符串分流（用 BC `SM2Signer` 还是 RSA Signer 等） |
| native-image 反射元数据漏抓导致 `ClassNotFoundException` / `NoSuchFieldError` | M9 之前先跑 fat-jar + agent 抓一遍新 reflection 需求；`native-test.sh` 跑通 | 把 M8 撤回，verify / validate 仍不注册 |
| `SM2Signer` 在 native-image 下访问内部 `State` enum 触发 illegal reflective access | GraalVM 25.0.4 的 `--allow-incomplete-classpath` 兜底 | 升级 BC 版本（1.84 → 1.85 试一下）|
| 测试样本 `helloworld-sign.ofd` 不是 GB/T 35275 数字签名 | M6 跑测试前先 `info` + `extract` 确认；缺样本从公开来源补一份 | 跳过 M6，先做 M1-M5 跑通单元测试 |

---

## 8. 不在范围

- **`sign` 子命令**：写 PKCS#12 + 私钥 + 签发证书，JCE 依赖更深（`JcaContentSignerBuilder` / `JcaX509v3CertificateBuilder`），工作量是 verify 的 2-3 倍。先做 verify，sign 留后续。
- **`to-html` / `to-svg` 在 native 跑**：AWTMaker 父类触发 `sun/font/CFontManager` JNI 失败，跟 BC 无关，路线不同。
- **GraalVM BC closed-world 根本性解决**：等 oracle/graal#13412 上游合并 `BouncyCastleSubstitutions`，或自己写 `Feature` 类在 build time `Security.addProvider`（已试过不工作）。本计划是**绕开**这个限制，不是**解决**它。

---

## 9. 参考资料

- [oracle/graal#13412](https://github.com/oracle/graal/issues/13412) — GraalVM native-image BouncyCastleProvider 注册失败
- [GB/T 35275-2017](http://www.gb688.cn/bzgk/gb/newGbInfo?hcno=7FA63E9BBA56E3FE01BF0D4B1AA0C71C) — 信息安全技术 SM2 密码算法使用规范
- [GM/T 0099-2020](https://github.com/ofdrw/ofdrw/blob/master/GBT_33190-2016_电子文件存储与交换格式版式文档.pdf) — OFD 数字签名格式
- [BouncyCastle `SM2Signer` 文档](https://www.bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/crypto/signers/SM2Signer.html)
- [BouncyCastle `PublicKeyFactory` 文档](https://www.bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/crypto/util/PublicKeyFactory.html)
- [Quarkus BC 集成](https://quarkus.io/guides/security-bouncycastle) — 同思路参考

---

## 10. 决策记录

- 2026-08-14 v1 草案：Mavis 起稿。等用户 review 后再开 `feature/native-verify` 分支落地。
