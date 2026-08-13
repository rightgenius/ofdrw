package org.ofdrw.gm;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * 统一获取 BouncyCastle Provider 的入口。
 *
 * <p>ofdrw 代码库历史上在多处直接调用 {@code new BouncyCastleProvider()}。
 * 该写法在常规 JVM 下没有问题,但在 GraalVM native-image 25.0.4 下会被
 * 闭世界假设拦截,抛出:
 *
 * <pre>
 *   SecurityException: Attempted to verify a provider that was not
 *   registered at build time
 * </pre>
 *
 * <p>本类提供一个统一的获取入口:优先返回 {@link Security} 中已注册的
 * BC 实例(JVM 端可避免重复创建,native-image 端在 GraalVM 工具链修复
 * 后可命中 build time 注册的 Provider);若尚未注册,再 fallback 到
 * {@code org.ofdrw.gm.GmProviders.bouncyCastle()} 并将其注册到 {@link Security}。
 *
 * <p>{@link #bouncyCastle()} 永远返回一个非空的 {@link BouncyCastleProvider}:
 * <ul>
 *   <li>JVM 端:命中 Security 中已注册的 BC(由本类或外部代码注册),或
 *       fallback 创建并注册。</li>
 *   <li>native-image 端:要求 build time 通过 {@code GmProvidersFeature}
 *       (或其它等价机制)将 BC 预先注册到 Security;若未注册,本方法
 *       会触发 native-image 的 "registered at build time" 检查而失败,
 *       这与原有 {@code org.ofdrw.gm.GmProviders.bouncyCastle()} 行为一致。</li>
 * </ul>
 */
public final class GmProviders {

    private GmProviders() {
    }

    /**
     * @return 一个 BouncyCastle Provider 实例,永不为 null。
     */
    public static Provider bouncyCastle() {
        Provider existing = Security.getProvider("BC");
        if (existing != null) {
            return existing;
        }
        // 尚未注册,fallback 创建并注册一个。
        // 在 JVM 端正常工作;native-image 端要求 build time 已注册 BC。
        BouncyCastleProvider fresh = new BouncyCastleProvider();
        Security.addProvider(fresh);
        return fresh;
    }
}
