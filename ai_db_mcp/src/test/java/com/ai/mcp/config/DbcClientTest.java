package com.ai.mcp.config;

import com.ai.mcp.tool.FakeDbcServer;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DbcClient 的请求签名与响应映射: 签名按 DBC 的 TestTicketIssuer.sign 口径独立复算
 */
class DbcClientTest {

    private static final byte[] KEY = new byte[32];

    static {
        for (int i = 0; i < KEY.length; i++) {
            KEY[i] = (byte) (i * 7 + 1);
        }
    }

    private static final ConsoleClient.DbcTicket TICKET = new ConsoleClient.DbcTicket("payload.sig",
            System.currentTimeMillis() + 300_000, Base64.getUrlEncoder().withoutPadding().encodeToString(KEY));

    private FakeDbcServer dbc;

    @AfterEach
    void tearDown() {
        if (dbc != null) {
            dbc.close();
        }
    }

    /** 参考实现: 与 DBC 测试侧 TestTicketIssuer.sign 同算法 */
    private static String referenceSign(String method, String path, String ts, String nonce, byte[] body) throws Exception {
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
        byte[] sig = mac.doFinal((method + "\n" + path + "\n" + ts + "\n" + nonce + "\n" + hash).getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
    }

    @Test
    void signedHeadersMatchContract() throws Exception {
        dbc = new FakeDbcServer();
        dbc.reply("parse", "{\"ok\":true,\"data\":{\"op\":\"SELECT\"}}");
        DbcClient client = new DbcClient(dbc.baseUrl() + "/", new ObjectMapper());
        long before = System.currentTimeMillis();
        DbcClient.Result r = client.parse(TICKET, "agent_9_" + "a".repeat(32), "select 1");
        client.close(TICKET, "agent_9_" + "a".repeat(32));

        assertTrue(r.ok());
        assertEquals("SELECT", r.data().get("op"));
        FakeDbcServer.Req req = dbc.requests.get(0);
        // path 含 context-path, 与 DBC 的 request.getRequestURI() 一致; 尾斜杠不产生双斜杠
        assertEquals("/dbc/api/agent/parse", req.path());
        assertEquals("POST", req.method());
        assertEquals("payload.sig", req.headers().get("X-Dbc-Ticket"));
        String nonce = req.headers().get("X-Nonce");
        assertTrue(nonce.matches("[0-9a-f]{32}"));
        long ts = Long.parseLong(req.headers().get("X-Ts"));
        assertTrue(ts >= before && ts <= System.currentTimeMillis());
        assertEquals(referenceSign("POST", req.path(), req.headers().get("X-Ts"), nonce, req.body()), req.headers().get("X-Sign"));
        assertFalse(req.headers().get("X-Sign").contains("="));
        // 固定 HTTP/1.1: 不发 h2c Upgrade 头 (DBC 前面的过滤器/容器不必处理协议升级)
        assertFalse(req.headers().containsKey("Upgrade"));
        // nonce 一次一用
        assertNotEquals(nonce, dbc.requests.get(1).headers().get("X-Nonce"));
        assertEquals("/dbc/api/agent/close", dbc.requests.get(1).path());
    }

    @Test
    void executeBodyCarriesParseResult() throws Exception {
        dbc = new FakeDbcServer();
        DbcClient client = new DbcClient(dbc.baseUrl(), new ObjectMapper());
        client.execute(TICKET, "c", "select * from t", "abc", "SELECT", List.of("db.t"), 5);
        client.execute(TICKET, "c", "select * from t", "abc", "SELECT", List.of("db.t"), null);
        var first = dbc.requests.get(0).json();
        assertEquals("abc", first.get("sqlDigest"));
        assertEquals("SELECT", first.get("op"));
        assertEquals(List.of("db.t"), first.get("tables"));
        assertEquals(5, first.get("maxRows"));
        assertFalse(dbc.requests.get(1).json().containsKey("maxRows"));
    }

    @Test
    void errorTypePassedThrough() throws Exception {
        dbc = new FakeDbcServer();
        dbc.reply("parse", "{\"ok\":false,\"error\":{\"type\":\"MULTI_STATEMENT\",\"message\":\"只允许单条语句\"}}");
        DbcClient.Result r = new DbcClient(dbc.baseUrl(), new ObjectMapper()).parse(TICKET, "c", "a;b");
        assertFalse(r.ok());
        assertEquals("MULTI_STATEMENT", r.errorType());
        assertEquals("只允许单条语句", r.message());
    }

    @Test
    void unreachableAndUnconfigured() {
        DbcClient.Result down = new DbcClient("http://127.0.0.1:1/dbc/api", new ObjectMapper()).parse(TICKET, "c", "select 1");
        assertEquals(DbcClient.UNREACHABLE, down.errorType());
        assertTrue(down.message().startsWith("DBC 不可达"));
        assertFalse(down.message().contains("payload.sig"));

        DbcClient none = new DbcClient("  ", new ObjectMapper());
        assertFalse(none.configured());
        assertEquals("未配置 dbc.base-url, 数据库工具不可用", none.parse(TICKET, "c", "select 1").message());
    }

    /** close 用独立的 10s 读超时: DBC 卡住时很快失败返回, 不会让空闲回收/撤权关连接挂几分钟 */
    @Test
    void closeTimesOutAfterTenSeconds() throws Exception {
        dbc = new FakeDbcServer();
        dbc.delay("close", 60_000);
        DbcClient client = new DbcClient(dbc.baseUrl(), new ObjectMapper());
        long t0 = System.nanoTime();
        DbcClient.Result r = client.close(TICKET, "c");
        long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
        assertEquals(DbcClient.UNREACHABLE, r.errorType());
        assertTrue(r.message().contains("HttpTimeoutException"), r.message());
        assertTrue(elapsedMs >= 9_000 && elapsedMs < 15_000, "elapsed=" + elapsedMs);
    }
}
