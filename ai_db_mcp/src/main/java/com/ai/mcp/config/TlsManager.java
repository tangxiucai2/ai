package com.ai.mcp.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.Service;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.coyote.AbstractProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.jsse.PEMFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.embedded.tomcat.TomcatWebServer;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.context.ServletWebServerInitializedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * 网关 TLS / mTLS: 验签控制台下发的 authConf → 解密私钥落盘 data/tls/v&lt;version&gt;/ → 运行时替换 Tomcat connector
 * <p>
 * 启动时按 state.json 的 authType 配置初始 connector; 落盘与 connector 操作都在单线程执行器里串行
 */
@Component
public class TlsManager implements WebServerFactoryCustomizer<TomcatServletWebServerFactory>, Ordered {

    private static final Logger log = LoggerFactory.getLogger(TlsManager.class);
    static final String BEARER = "BEARER";
    static final String TLS_TOKEN = "TLS_TOKEN";
    static final String MTLS = "MTLS";
    private static final long RETRY_S = 30;
    private static final int ERROR_MAX = 200;
    private static final ObjectMapper JSON = new ObjectMapper();

    /** 验签通过的下发配置 (私钥仍是密文); BEARER 时证书三项为 null */
    public record AuthConf(String authType, String authToken, long authVersion,
                           String serverCert, String serverKeyEnc, String clientCaCert) {
    }

    /** state.json: 当前生效的 connector 目标态; BEARER 时 dir/trustPass 为 null */
    record State(String authType, long authVersion, String dir, String trustPass) {
    }

    private record Pending(AuthConf conf, String nodeId, String secret) {
    }

    private final Path dir;
    private final Path stateFile;
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "tls-manager");
        t.setDaemon(true);
        return t;
    });

    private volatile Tomcat tomcat;
    // 以下三项只在执行器线程读写 (构造时的初值除外)
    private State current;
    private int port;
    private InetAddress address;
    private volatile String applied;
    private volatile String lastError;
    // 本地曾有过签名配置: 之后不再信任无 authConf 的旧式响应 (防剥离降级)
    private volatile boolean signedSeen;
    // 版本下限 / 已应用版本 / 待应用配置: accept 与执行器共用, 用 this 锁
    private long floor;
    private long appliedVersion = -1;
    // 新 connector 起不来且已回滚的版本: 材料本身有问题, 不随心跳反复重建断流, 等控制台下发新版本
    private long rejectedVersion = -1;
    private Pending latest;

    /** 新 connector 启动失败但已回滚到旧态 */
    private static class RolledBack extends IllegalStateException {
        RolledBack(String msg) {
            super(msg);
        }
    }

    public TlsManager(@Value("${console.secret-file:./data/gateway.secret}") Path secretFile) {
        this.dir = secretFile.toAbsolutePath().getParent().resolve("tls");
        this.stateFile = dir.resolve("state.json");
        if (!Files.exists(stateFile)) {
            return;
        }
        signedSeen = true;
        try {
            State s = JSON.readValue(stateFile.toFile(), State.class);
            checkState(s);
            current = s;
            applied = key(s);
            floor = s.authVersion();
            appliedVersion = s.authVersion();
        } catch (Exception e) {
            lastError = trim("本地 TLS 状态不可用, 以 HTTP 启动: " + e.getMessage());
            log.warn("TlsManager {}", lastError);
        }
    }

    @Override
    public int getOrder() {
        // 晚于 Spring 自己的 ServletWebServerFactoryCustomizer, 才能覆盖 server.ssl.*
        return Ordered.LOWEST_PRECEDENCE;
    }

    /** 启动: 有本地状态则按其 authType 配置初始 connector, 并压过 server.ssl.*; 无状态保持 Spring 默认 */
    @Override
    public void customize(TomcatServletWebServerFactory factory) {
        State s = current;
        if (s == null) {
            return;
        }
        factory.setSsl(null);
        factory.addConnectorCustomizers(c -> configure(c, s));
        log.info("TlsManager 按本地状态启动 {}", key(s));
    }

    @EventListener
    public void onWebServer(ServletWebServerInitializedEvent e) {
        if (e.getWebServer() instanceof TomcatWebServer w) {
            attach(w.getTomcat());
        }
    }

    /** 容器就绪: 记下端口与监听地址, 补应用就绪前收到的配置 */
    void attach(Tomcat t) {
        executor.execute(() -> {
            Connector[] cs = t.getService().findConnectors();
            if (cs.length > 0) {
                port = cs[0].getLocalPort() > 0 ? cs[0].getLocalPort() : cs[0].getPort();
                address = ((AbstractProtocol<?>) cs[0].getProtocolHandler()).getAddress();
            }
            tomcat = t;
            applyLatest();
        });
    }

    @PreDestroy
    void stop() {
        executor.shutdownNow();
    }

    /** 当前生效态 authType:authVersion, 未应用为 null */
    public String appliedState() {
        return applied;
    }

    public String lastError() {
        return lastError;
    }

    public boolean signedSeen() {
        return signedSeen;
    }

    /** 新注册拿到新密钥: 旧版本号不再有意义 (节点删除重建后控制台版本从 1 重新计) */
    public synchronized void rebase() {
        floor = 0;
        appliedVersion = -1;
        rejectedVersion = -1;
    }

    /**
     * 验签 + 版本检查, 通过则异步应用
     *
     * @return 验签通过的配置 (鉴权态以它为准, 与 connector 是否切换成功无关); 验签失败/版本回退返回 null
     */
    public AuthConf accept(String nodeId, String secret, Map<?, ?> raw, Object sign) {
        AuthConf c;
        try {
            c = parse(raw);
        } catch (RuntimeException e) {
            lastError = "认证配置格式非法";
            return null;
        }
        if (secret == null || !(sign instanceof String s) || !verify(secret, nodeId, c, s)) {
            lastError = "认证配置验签失败";
            return null;
        }
        synchronized (this) {
            if (c.authVersion() < floor) {
                lastError = "认证配置版本回退 " + c.authVersion() + " < " + floor;
                return null;
            }
            floor = c.authVersion();
            signedSeen = true;
            if (c.authVersion() == appliedVersion) {
                lastError = null;
                return c;
            }
            if (c.authVersion() == rejectedVersion) {
                return c;
            }
            if (latest == null || latest.conf().authVersion() != c.authVersion()) {
                // 新版本待应用: 上一版本的失败原因不再代表当前期望态
                lastError = null;
            }
            latest = new Pending(c, nodeId, secret);
        }
        executor.execute(this::applyLatest);
        return c;
    }

    private void applyLatest() {
        Pending p;
        synchronized (this) {
            p = latest;
            if (p == null || p.conf().authVersion() == appliedVersion) {
                return;
            }
        }
        Tomcat t = tomcat;
        if (t == null) {
            // 容器未就绪, attach 时补
            return;
        }
        AuthConf c = p.conf();
        try {
            State target = writeFiles(p);
            switchConnector(t, target);
            current = target;
            writeState(target);
            synchronized (this) {
                appliedVersion = c.authVersion();
                if (latest == p) {
                    latest = null;
                }
            }
            applied = key(target);
            lastError = null;
            cleanup(target);
            log.info("TlsManager 已生效 {}", applied);
        } catch (Exception e) {
            if (e instanceof RolledBack) {
                synchronized (this) {
                    rejectedVersion = c.authVersion();
                }
            }
            // 自己抛的原因已是中文; 其余 (如 data/tls 被普通文件占用的 FileAlreadyExistsException) 带上异常类型
            String why = e instanceof IllegalStateException || e instanceof IllegalArgumentException ? e.getMessage() : e.toString();
            lastError = trim("应用 " + c.authType() + ":" + c.authVersion() + " 失败: " + why);
            log.warn("TlsManager {}", lastError);
        }
    }

    // -------------------- 落盘 --------------------

    private State writeFiles(Pending p) throws Exception {
        AuthConf c = p.conf();
        String type = c.authType();
        if (BEARER.equals(type)) {
            return new State(BEARER, c.authVersion(), null, null);
        }
        if (!TLS_TOKEN.equals(type) && !MTLS.equals(type)) {
            throw new IllegalArgumentException("未知认证方式 " + type);
        }
        if (c.serverCert() == null || c.serverKeyEnc() == null || (MTLS.equals(type) && c.clientCaCert() == null)) {
            throw new IllegalArgumentException("证书材料不全");
        }
        String keyPem = decryptKey(p.secret(), p.nodeId(), c.authVersion(), c.serverKeyEnc());
        ensureDir();
        Path vdir = dir.resolve("v" + c.authVersion());
        // 新密钥重注册后版本号可能与正在用的目录重名, 换个名字, 不覆盖正在用的文件
        if (current != null && vdir.toString().equals(current.dir())) {
            vdir = dir.resolve("v" + c.authVersion() + "-" + System.currentTimeMillis());
        }
        deleteTree(vdir);
        createPrivate(vdir, true);
        writePrivate(vdir.resolve("server.crt"), c.serverCert().getBytes(StandardCharsets.UTF_8));
        writePrivate(vdir.resolve("server.key"), keyPem.getBytes(StandardCharsets.UTF_8));
        String pass = null;
        if (MTLS.equals(type)) {
            byte[] rnd = new byte[16];
            new SecureRandom().nextBytes(rnd);
            pass = HexFormat.of().formatHex(rnd);
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            int i = 0;
            for (Certificate ca : CertificateFactory.getInstance("X.509").generateCertificates(
                    new ByteArrayInputStream(c.clientCaCert().getBytes(StandardCharsets.UTF_8)))) {
                ks.setCertificateEntry("ca" + i++, ca);
            }
            if (i == 0) {
                throw new IllegalArgumentException("客户端 CA 证书为空");
            }
            Path p12 = vdir.resolve("client-ca.p12");
            createPrivate(p12, false);
            try (OutputStream out = Files.newOutputStream(p12)) {
                ks.store(out, pass.toCharArray());
            }
        }
        return new State(type, c.authVersion(), vdir.toAbsolutePath().toString(), pass);
    }

    private void writeState(State s) throws Exception {
        ensureDir();
        Path tmp = stateFile.resolveSibling("state.json.tmp");
        Files.deleteIfExists(tmp);
        writePrivate(tmp, JSON.writeValueAsBytes(s));
        Files.move(tmp, stateFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    /** 清掉当前目录以外的版本目录 (旧私钥不留盘) */
    private void cleanup(State s) {
        try (Stream<Path> list = Files.list(dir)) {
            for (Path d : list.toList()) {
                if (Files.isDirectory(d) && d.getFileName().toString().startsWith("v")
                        && !d.toAbsolutePath().toString().equals(s.dir())) {
                    deleteTree(d);
                }
            }
        } catch (Exception e) {
            log.warn("TlsManager 清理旧版本目录失败: {}", e.toString());
        }
    }

    private void ensureDir() throws Exception {
        if (!Files.isDirectory(dir)) {
            // data/tls 被同名普通文件占用时这里抛 FileAlreadyExistsException
            Files.createDirectories(dir.getParent());
            createPrivate(dir, true);
        }
    }

    /** 建文件/目录时即 0600/0700, 不留 umask 可读窗口 */
    private static void createPrivate(Path p, boolean directory) throws Exception {
        try {
            var attr = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------"));
            if (directory) {
                Files.createDirectory(p, attr);
            } else {
                Files.createFile(p, attr);
            }
        } catch (UnsupportedOperationException e) {
            if (directory) {
                Files.createDirectory(p);
            } else {
                Files.createFile(p);
            }
        }
    }

    private static void writePrivate(Path p, byte[] data) throws Exception {
        createPrivate(p, false);
        Files.write(p, data);
    }

    private static void deleteTree(Path p) throws Exception {
        if (!Files.exists(p)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(p)) {
            for (Path x : walk.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(x);
            }
        }
    }

    // -------------------- connector --------------------

    /** 设计 §3.4 步骤 1-4: remove → destroy → add, 未 STARTED 则回滚到旧目标态 */
    private void switchConnector(Tomcat t, State target) {
        Service svc = t.getService();
        Connector[] cs = svc.findConnectors();
        Connector old = cs.length > 0 ? cs[0] : null;
        if (old != null) {
            // 目标与当前同为 HTTP 没有可换的, 不重建 (免得无谓断流)
            if (!isHttps(target) && !isHttps(old)) {
                return;
            }
            svc.removeConnector(old);
            destroyQuietly(old);
        }
        String err = start(svc, build(target));
        if (err == null) {
            return;
        }
        String back = start(svc, build(current));
        if (back != null) {
            // 端口无人监听: 30s 后重试待应用配置 (心跳到来也会重试)
            executor.schedule(this::applyLatest, RETRY_S, TimeUnit.SECONDS);
            throw new IllegalStateException("新 connector 启动失败(" + err + "), 回滚也失败(" + back + ")");
        }
        throw new RolledBack("新 connector 启动失败, 已回滚: " + err);
    }

    /** @return null=已 STARTED; 否则失败原因 (失败的 connector 已移除销毁) */
    private static String start(Service svc, Connector c) {
        String err = null;
        try {
            svc.addConnector(c);
        } catch (Exception e) {
            Throwable r = e;
            while (r.getCause() != null) {
                r = r.getCause();
            }
            err = r.toString();
        }
        if (err == null && c.getState() == LifecycleState.STARTED) {
            return null;
        }
        try {
            svc.removeConnector(c);
        } catch (Exception ignore) {
            // 已失败, 尽力清理
        }
        destroyQuietly(c);
        return err == null ? "state=" + c.getState() : err;
    }

    private static void destroyQuietly(Connector c) {
        try {
            c.destroy();
        } catch (Exception e) {
            log.warn("TlsManager 销毁 connector 失败: {}", e.toString());
        }
    }

    private Connector build(State s) {
        Connector c = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        c.setPort(port);
        if (address != null) {
            ((AbstractProtocol<?>) c.getProtocolHandler()).setAddress(address);
        }
        c.setThrowOnFailure(true);
        // 同 Spring 自建 connector: stop 即释放端口 (TomcatWebServer.stop 只摘 connector 不 destroy)
        c.setProperty("bindOnInit", "false");
        configure(c, s);
        return c;
    }

    /** 按目标态配置 connector (启动与运行时替换共用); s 为 null 视同 BEARER */
    static void configure(Connector c, State s) {
        if (!isHttps(s)) {
            c.setProperty("SSLEnabled", "false");
            c.setScheme("http");
            c.setSecure(false);
            return;
        }
        c.setProperty("SSLEnabled", "true");
        c.setProperty("sslImplementationName", "org.apache.tomcat.util.net.jsse.JSSEImplementation");
        c.setScheme("https");
        c.setSecure(true);
        SSLHostConfig host = new SSLHostConfig();
        // UNDEFINED: 单证书, RSA/EC 皆可
        SSLHostConfigCertificate cert = new SSLHostConfigCertificate(host, SSLHostConfigCertificate.Type.UNDEFINED);
        cert.setCertificateFile(Path.of(s.dir(), "server.crt").toString());
        cert.setCertificateKeyFile(Path.of(s.dir(), "server.key").toString());
        host.addCertificate(cert);
        if (MTLS.equals(s.authType())) {
            // JSSE 不认 caCertificateFile, 客户端 CA 走 PKCS12 truststore
            host.setCertificateVerification("required");
            host.setTruststoreFile(Path.of(s.dir(), "client-ca.p12").toString());
            host.setTruststorePassword(s.trustPass());
            host.setTruststoreType("PKCS12");
        }
        c.addSslHostConfig(host);
    }

    private static boolean isHttps(State s) {
        return s != null && (TLS_TOKEN.equals(s.authType()) || MTLS.equals(s.authType()));
    }

    private static boolean isHttps(Connector c) {
        return c.getSecure() || "true".equals(String.valueOf(c.getProperty("SSLEnabled")));
    }

    /** 启动前校验本地状态: 文件不全/损坏直接抛, 以免 Tomcat 起不来整个进程挂掉 */
    private static void checkState(State s) throws Exception {
        if (s == null || s.authVersion() <= 0) {
            throw new IllegalArgumentException("state.json 内容非法");
        }
        if (BEARER.equals(s.authType())) {
            return;
        }
        if (!isHttps(s) || s.dir() == null) {
            throw new IllegalArgumentException("state.json 内容非法");
        }
        if (new PEMFile(Path.of(s.dir(), "server.crt").toString()).getCertificates().isEmpty()
                || new PEMFile(Path.of(s.dir(), "server.key").toString()).getPrivateKey() == null) {
            throw new IllegalArgumentException("服务器证书或私钥不可用");
        }
        if (MTLS.equals(s.authType())) {
            try (InputStream in = Files.newInputStream(Path.of(s.dir(), "client-ca.p12"))) {
                KeyStore.getInstance("PKCS12").load(in, s.trustPass() == null ? null : s.trustPass().toCharArray());
            }
        }
    }

    // -------------------- 协议 (与控制台逐字一致) --------------------

    static AuthConf parse(Map<?, ?> m) {
        Object v = m.get("authVersion");
        String type = str(m, "authType");
        if (!(v instanceof Integer || v instanceof Long) || type == null) {
            throw new IllegalArgumentException("authConf 字段非法");
        }
        return new AuthConf(type, str(m, "authToken"), ((Number) v).longValue(),
                str(m, "serverCert"), str(m, "serverKeyEnc"), str(m, "clientCaCert"));
    }

    private static String str(Map<?, ?> m, String k) {
        Object o = m.get(k);
        if (o == null || o instanceof String) {
            return (String) o;
        }
        throw new IllegalArgumentException(k);
    }

    static String payload(String nodeId, AuthConf c) {
        return "authconf\n" + nodeId + "\n" + c.authVersion() + "\n" + c.authType() + "\n" + h(c.authToken())
                + "\n" + h(c.serverCert()) + "\n" + h(c.serverKeyEnc()) + "\n" + h(c.clientCaCert());
    }

    static boolean verify(String secret, String nodeId, AuthConf c, String sign) {
        try {
            byte[] expect = HexFormat.of().formatHex(hmac(secret, payload(nodeId, c))).getBytes(StandardCharsets.UTF_8);
            return MessageDigest.isEqual(expect, sign.trim().toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    /** AES-256-GCM, key = HMAC(secret, "agent-gateway-tls-key"), AAD = nodeId\nversion, 密文 = Base64(iv12 ‖ ct ‖ tag) */
    static String decryptKey(String secret, String nodeId, long version, String enc) throws GeneralSecurityException {
        byte[] all = Base64.getDecoder().decode(enc);
        if (all.length < 12 + 16) {
            throw new GeneralSecurityException("serverKeyEnc 长度非法");
        }
        Cipher ci = Cipher.getInstance("AES/GCM/NoPadding");
        ci.init(Cipher.DECRYPT_MODE, new SecretKeySpec(tlsKey(secret), "AES"), new GCMParameterSpec(128, all, 0, 12));
        ci.updateAAD((nodeId + "\n" + version).getBytes(StandardCharsets.UTF_8));
        return new String(ci.doFinal(all, 12, all.length - 12), StandardCharsets.UTF_8);
    }

    static byte[] tlsKey(String secret) throws GeneralSecurityException {
        return hmac(secret, "agent-gateway-tls-key");
    }

    private static String h(String x) {
        if (x == null) {
            return "-";
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(x.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] hmac(String secret, String data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String key(State s) {
        return s.authType() + ":" + s.authVersion();
    }

    private static String trim(String s) {
        return s.length() > ERROR_MAX ? s.substring(0, ERROR_MAX) : s;
    }
}
