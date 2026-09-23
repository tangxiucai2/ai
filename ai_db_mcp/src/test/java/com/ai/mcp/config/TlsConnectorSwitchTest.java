package com.ai.mcp.config;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.embedded.tomcat.TomcatWebServer;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 运行中的 Tomcat 上真实握手: HTTP → TLS_TOKEN → MTLS → 同模式换证书 → 坏私钥回滚 → BEARER → data/tls 被占用失败 → 恢复 → 重启按 state 起
 */
class TlsConnectorSwitchTest {

    private static final String SECRET = "s3cr3t";
    private static final String NODE = "gw-it";

    @TempDir
    Path tmp;

    private TomcatWebServer server;
    private TlsManager tls;

    @AfterEach
    void tearDown() {
        stopServer();
    }

    @Test
    void switchModesOnLiveTomcat() throws Exception {
        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        Path secretFile = tmp.resolve("gateway.secret");
        Path tlsDir = tmp.resolve("tls");

        KeyPair caKey1 = TlsTestSupport.rsa();
        X509Certificate ca1 = TlsTestSupport.cert("ca1", caKey1.getPublic(), "ca1", caKey1.getPrivate(), true);
        KeyPair caKey2 = TlsTestSupport.rsa();
        X509Certificate ca2 = TlsTestSupport.cert("ca2", caKey2.getPublic(), "ca2", caKey2.getPrivate(), true);
        KeyPair cliKey1 = TlsTestSupport.rsa();
        KeyManager[] client1 = keyManagers(cliKey1, TlsTestSupport.cert("client1", cliKey1.getPublic(), "ca1", caKey1.getPrivate(), false));
        KeyPair cliKey2 = TlsTestSupport.rsa();
        KeyManager[] client2 = keyManagers(cliKey2, TlsTestSupport.cert("client2", cliKey2.getPublic(), "ca2", caKey2.getPrivate(), false));

        // 0. 无本地状态: HTTP
        startServer(secretFile, port);
        assertNull(tls.appliedState());
        assertNull(tls.lastError());
        assertTrue(http(port).contains("secure=false"));
        assertRejected(() -> https(port, null, null));

        // 1. TLS_TOKEN (RSA)
        KeyPair srvA = TlsTestSupport.rsa();
        X509Certificate certA = TlsTestSupport.cert("127.0.0.1", srvA.getPublic(), "127.0.0.1", srvA.getPrivate(), false);
        apply("TLS_TOKEN", 1, certA, srvA, null);
        X509Certificate[] seen = new X509Certificate[1];
        assertTrue(https(port, null, seen).contains("secure=true"));
        assertEquals(fp(certA), fp(seen[0]));
        assertRejected(() -> http(port));
        assertEquals("rwx------", perm(tlsDir));
        assertEquals("rw-------", perm(tlsDir.resolve("v1/server.key")));
        assertEquals("rw-------", perm(tlsDir.resolve("state.json")));

        // 2. MTLS (EC 服务器证书, 客户端 CA=ca1)
        KeyPair srvB = TlsTestSupport.ec();
        X509Certificate certB = TlsTestSupport.cert("127.0.0.1", srvB.getPublic(), "127.0.0.1", srvB.getPrivate(), false);
        apply("MTLS", 2, certB, srvB, ca1);
        assertTrue(https(port, client1, seen).contains("secure=true"));
        assertEquals(fp(certB), fp(seen[0]));
        assertRejected(() -> https(port, null, null));
        assertRejected(() -> https(port, client2, null));
        assertFalse(Files.exists(tlsDir.resolve("v1")), "旧版本目录应清理");

        // 3. 同模式换证书
        KeyPair srvC = TlsTestSupport.rsa();
        X509Certificate certC = TlsTestSupport.cert("127.0.0.1", srvC.getPublic(), "127.0.0.1", srvC.getPrivate(), false);
        apply("MTLS", 3, certC, srvC, ca1);
        https(port, client1, seen);
        assertEquals(fp(certC), fp(seen[0]));
        assertRejected(() -> https(port, client2, null));

        // 4. 私钥坏掉: 新 connector 起不来 → 回滚到 MTLS:3
        String badKey = "-----BEGIN PRIVATE KEY-----\nAAAAAAAA\n-----END PRIVATE KEY-----\n";
        Map<String, Object> v4 = TlsTestSupport.issue(SECRET, NODE, "TLS_TOKEN", "tok", 4, TlsTestSupport.pem(certA), badKey, null);
        assertNotNull(tls.accept(NODE, SECRET, conf(v4), sign(v4)));
        await(() -> tls.lastError() != null);
        assertTrue(tls.lastError().contains("回滚"), tls.lastError());
        assertEquals("MTLS:3", tls.appliedState());
        https(port, client1, seen);
        assertEquals(fp(certC), fp(seen[0]));
        assertRejected(() -> https(port, null, null));

        // 5. 切回 BEARER: HTTP, 版本目录全清
        apply("BEARER", 5, null, null, null);
        assertTrue(http(port).contains("secure=false"));
        assertRejected(() -> https(port, null, null));
        try (Stream<Path> list = Files.list(tlsDir)) {
            assertEquals(0, list.filter(Files::isDirectory).count());
        }

        // 6. data/tls 被同名普通文件占用: 落盘失败, 旧 HTTP connector 仍在
        Path bak = tmp.resolve("tls.bak");
        Files.move(tlsDir, bak);
        Files.createFile(tlsDir);
        KeyPair srvD = TlsTestSupport.rsa();
        X509Certificate certD = TlsTestSupport.cert("127.0.0.1", srvD.getPublic(), "127.0.0.1", srvD.getPrivate(), false);
        Map<String, Object> v6 = TlsTestSupport.issue(SECRET, NODE, "MTLS", null, 6,
                TlsTestSupport.pem(certD), TlsTestSupport.pem(srvD.getPrivate()), TlsTestSupport.pem(ca1));
        assertNotNull(tls.accept(NODE, SECRET, conf(v6), sign(v6)));
        await(() -> tls.lastError() != null);
        assertEquals("BEARER:5", tls.appliedState());
        assertTrue(http(port).contains("secure=false"));

        // 恢复目录后, 下一次心跳 (同一份配置) 自动生效
        Files.delete(tlsDir);
        Files.move(bak, tlsDir);
        assertNotNull(tls.accept(NODE, SECRET, conf(v6), sign(v6)));
        await(() -> "MTLS:6".equals(tls.appliedState()));
        assertNull(tls.lastError());
        https(port, client1, seen);
        assertEquals(fp(certD), fp(seen[0]));

        // 7. 版本回退拒绝
        Map<String, Object> old = TlsTestSupport.issue(SECRET, NODE, "BEARER", "tok", 5, null, null, null);
        assertNull(tls.accept(NODE, SECRET, conf(old), sign(old)));

        // 8. 重启: 注册前即按 state.json 以 MTLS 起
        stopServer();
        startServer(secretFile, port);
        assertEquals("MTLS:6", tls.appliedState());
        assertNull(tls.lastError());
        assertRejected(() -> https(port, null, null));
        assertRejected(() -> http(port));
        https(port, client1, seen);
        assertEquals(fp(certD), fp(seen[0]));

        // 9. state 指向的文件缺失: 以 HTTP 起并记 lastError
        stopServer();
        Files.delete(tlsDir.resolve("v6/server.key"));
        startServer(secretFile, port);
        assertNull(tls.appliedState());
        assertNotNull(tls.lastError());
        assertTrue(http(port).contains("secure=false"));
    }

    private void apply(String type, long version, X509Certificate cert, KeyPair key, X509Certificate ca) throws Exception {
        Map<String, Object> d = TlsTestSupport.issue(SECRET, NODE, type, "tok", version,
                cert == null ? null : TlsTestSupport.pem(cert), key == null ? null : TlsTestSupport.pem(key.getPrivate()),
                ca == null ? null : TlsTestSupport.pem(ca));
        assertNotNull(tls.accept(NODE, SECRET, conf(d), sign(d)));
        String expect = type + ":" + version;
        await(() -> expect.equals(tls.appliedState()) || tls.lastError() != null);
        assertEquals(expect, tls.appliedState(), tls.lastError());
    }

    private void startServer(Path secretFile, int port) {
        tls = new TlsManager(secretFile);
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory(port);
        tls.customize(factory);
        server = (TomcatWebServer) factory.getWebServer(sc -> sc.addServlet("probe", new HttpServlet() {
            @Override
            protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
                resp.getWriter().write("secure=" + req.isSecure());
            }
        }).addMapping("/"));
        server.start();
        tls.attach(server.getTomcat());
    }

    private void stopServer() {
        if (server != null) {
            server.stop();
            server.destroy();
            server = null;
        }
        if (tls != null) {
            tls.stop();
        }
    }

    // -------------------- 客户端 --------------------

    private static String http(int port) throws IOException {
        try (Socket s = new Socket("127.0.0.1", port)) {
            return exchange(s);
        }
    }

    /** 信任任意服务器证书 (记下来比指纹), 可选客户端证书 */
    private static String https(int port, KeyManager[] km, X509Certificate[] seen) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(km, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {
            }

            public void checkServerTrusted(X509Certificate[] c, String a) {
            }

            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }}, null);
        try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket("127.0.0.1", port)) {
            s.setSoTimeout(5000);
            s.startHandshake();
            if (seen != null) {
                seen[0] = (X509Certificate) s.getSession().getPeerCertificates()[0];
            }
            return exchange(s);
        }
    }

    /** 发 GET 读完整响应; 非 200 抛异常 */
    private static String exchange(Socket s) throws IOException {
        s.setSoTimeout(5000);
        s.getOutputStream().write("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        s.getOutputStream().flush();
        InputStream in = s.getInputStream();
        String resp = new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
        if (!resp.startsWith("HTTP/1.1 200")) {
            throw new IOException("非 200: " + resp.lines().findFirst().orElse("<空>"));
        }
        return resp;
    }

    private interface Call {
        String run() throws Exception;
    }

    private static void assertRejected(Call c) {
        try {
            String r = c.run();
            fail("应被拒绝, 实际: " + r);
        } catch (Exception expected) {
            // 握手失败 / 连接被断 / 非 200
        }
    }

    private static KeyManager[] keyManagers(KeyPair key, X509Certificate cert) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("client", key.getPrivate(), "p".toCharArray(), new Certificate[]{cert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "p".toCharArray());
        return kmf.getKeyManagers();
    }

    private static String fp(X509Certificate c) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(c.getEncoded()));
    }

    private static String perm(Path p) throws IOException {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(p));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> conf(Map<String, Object> d) {
        return (Map<String, Object>) d.get("authConf");
    }

    private static Object sign(Map<String, Object> d) {
        return d.get("authSign");
    }

    private static void await(BooleanSupplier cond) throws InterruptedException {
        long end = System.currentTimeMillis() + 15_000;
        while (!cond.getAsBoolean() && System.currentTimeMillis() < end) {
            Thread.sleep(50);
        }
        assertTrue(cond.getAsBoolean(), "等待超时");
    }
}
