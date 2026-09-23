package com.ai.mcp.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.AEADBadTagException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** 签名/加密协议向量 (与控制台单测同一组) + 验签/版本/鉴权口径 */
class TlsManagerTest {

    private static final String SECRET = "s3cr3t";
    private static final String NODE = "gw-test";
    private static final String SIGN = "0cd275dbd0b850980142e927788c495d7241cfaecd5317ddbe1b47736ae30bb6";
    private static final String KEY_PEM = "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n";
    private static final String KEY_ENC = "AAECAwQFBgcICQoLvIKoiHbqT/r9vDKh2LZMBKyBqZdUhBT0LcFkcLIQNYrp6z8qkuF8EAQrEQV8fHSJAKBvh4N/hs/SK4qZYceiEeqY0gonnAubEUg=";
    private static final TlsManager.AuthConf VECTOR = new TlsManager.AuthConf("TLS_TOKEN", "tok", 7, "CERT", "KEY", null);

    @TempDir
    Path tmp;

    @Test
    void signVector() throws Exception {
        assertEquals(SIGN, TlsTestSupport.sign(SECRET, NODE, VECTOR));
        assertTrue(TlsManager.verify(SECRET, NODE, VECTOR, SIGN));
        assertTrue(TlsManager.verify(SECRET, NODE, VECTOR, SIGN.toUpperCase()));
    }

    @Test
    void encryptVector() throws Exception {
        byte[] iv = new byte[12];
        for (int i = 0; i < iv.length; i++) {
            iv[i] = (byte) i;
        }
        assertEquals(KEY_ENC, TlsTestSupport.encrypt(SECRET, NODE, 7, iv, KEY_PEM));
        assertEquals(KEY_PEM, TlsManager.decryptKey(SECRET, NODE, 7, KEY_ENC));
    }

    @Test
    void tamperAnyFieldFailsVerify() {
        TlsManager.AuthConf[] tampered = {
                new TlsManager.AuthConf("TLS_TOKEN", "tok", 8, "CERT", "KEY", null),
                new TlsManager.AuthConf("BEARER", "tok", 7, "CERT", "KEY", null),
                new TlsManager.AuthConf("TLS_TOKEN", "tok2", 7, "CERT", "KEY", null),
                new TlsManager.AuthConf("TLS_TOKEN", null, 7, "CERT", "KEY", null),
                new TlsManager.AuthConf("TLS_TOKEN", "tok", 7, "CERT2", "KEY", null),
                new TlsManager.AuthConf("TLS_TOKEN", "tok", 7, "CERT", "KEY2", null),
                new TlsManager.AuthConf("TLS_TOKEN", "tok", 7, "CERT", "KEY", "CA"),
        };
        for (TlsManager.AuthConf c : tampered) {
            assertFalse(TlsManager.verify(SECRET, NODE, c, SIGN), c.toString());
        }
        assertFalse(TlsManager.verify(SECRET, "gw-other", VECTOR, SIGN));
        assertFalse(TlsManager.verify("other", NODE, VECTOR, SIGN));
        assertFalse(TlsManager.verify(SECRET, NODE, VECTOR, SIGN.substring(1) + "0"));
    }

    @Test
    void aadMismatchFailsDecrypt() {
        assertThrows(AEADBadTagException.class, () -> TlsManager.decryptKey(SECRET, NODE, 8, KEY_ENC));
        assertThrows(AEADBadTagException.class, () -> TlsManager.decryptKey(SECRET, "gw-other", 7, KEY_ENC));
        assertThrows(AEADBadTagException.class, () -> TlsManager.decryptKey("other", NODE, 7, KEY_ENC));
    }

    @Test
    void versionRollbackRejected() throws Exception {
        TlsManager tls = new TlsManager(tmp.resolve("gateway.secret"));
        try {
            assertNotNull(accept(tls, bearer(5)));
            assertNull(accept(tls, bearer(4)));
            assertTrue(tls.lastError().contains("回退"));
            assertNotNull(accept(tls, bearer(5)));
            assertNotNull(accept(tls, bearer(6)));
            // 篡改签名
            Map<String, Object> bad = bearer(7);
            bad.put("authSign", "00" + ((String) bad.get("authSign")).substring(2));
            assertNull(accept(tls, bad));
            assertEquals("认证配置验签失败", tls.lastError());
            // 新密钥重注册后版本号重新计
            tls.rebase();
            assertNotNull(accept(tls, bearer(1)));
        } finally {
            tls.stop();
        }
    }

    @Test
    void tlsTokenRequiresSecure() throws Exception {
        TlsManager tls = new TlsManager(tmp.resolve("gateway.secret"));
        ConsoleClient console = console(tls);
        try {
            console.applyAuth(TlsTestSupport.issue(SECRET, NODE, "TLS_TOKEN", "tok", 1, "CERT", "KEY", null));
            assertFalse(console.checkToken("Bearer tok", false, false));
            assertTrue(console.checkToken("Bearer tok", false, true));
            assertFalse(console.checkToken("Bearer bad", false, true));

            console.applyAuth(bearer(2));
            assertTrue(console.checkToken("Bearer tok", false, false));

            console.applyAuth(TlsTestSupport.issue(SECRET, NODE, "MTLS", null, 3, "CERT", "KEY", "CA"));
            assertFalse(console.checkToken("Bearer tok", false, true));
            assertTrue(console.checkToken(null, true, true));
        } finally {
            tls.stop();
        }
    }

    @Test
    void unsignedOrForgedConfKeepsCurrentAuth() throws Exception {
        TlsManager tls = new TlsManager(tmp.resolve("gateway.secret"));
        ConsoleClient console = console(tls);
        try {
            // 旧控制台 (无 authConf): 沿用顶层字段
            console.applyAuth(new HashMap<>(Map.of("authType", "BEARER", "authToken", "old")));
            assertTrue(console.checkToken("Bearer old", false, false));

            console.applyAuth(TlsTestSupport.issue(SECRET, NODE, "TLS_TOKEN", "tok", 1, "CERT", "KEY", null));
            assertTrue(console.checkToken("Bearer tok", false, true));

            // 伪造签名 → 保持 TLS_TOKEN
            Map<String, Object> forged = TlsTestSupport.issue("wrong", NODE, "BEARER", "evil", 2, null, null, null);
            console.applyAuth(forged);
            assertFalse(console.checkToken("Bearer evil", false, false));
            assertTrue(console.checkToken("Bearer tok", false, true));

            // 剥离 authConf 只留顶层字段 → 见过签名配置后不再采信
            console.applyAuth(new HashMap<>(Map.of("authType", "BEARER", "authToken", "evil")));
            assertFalse(console.checkToken("Bearer evil", false, false));
            assertTrue(console.checkToken("Bearer tok", false, true));
        } finally {
            tls.stop();
        }
    }

    private static ConsoleClient console(TlsManager tls) {
        ConsoleClient c = new ConsoleClient();
        ReflectionTestUtils.setField(c, "nodeId", NODE);
        ReflectionTestUtils.setField(c, "secret", SECRET);
        ReflectionTestUtils.setField(c, "tls", tls);
        return c;
    }

    private static Map<String, Object> bearer(long version) throws Exception {
        return TlsTestSupport.issue(SECRET, NODE, "BEARER", "tok", version, null, null, null);
    }

    @SuppressWarnings("unchecked")
    private static TlsManager.AuthConf accept(TlsManager tls, Map<String, Object> data) {
        return tls.accept(NODE, SECRET, (Map<String, Object>) data.get("authConf"), data.get("authSign"));
    }
}
