package com.ai.mcp.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 固定资源模式带 X-User-Token 的 resolve: 不走缓存、身份只取响应、缺身份即拒、拒绝不触发撤权广播
 */
class ConsoleClientFixedUserTokenTest {

    private final List<Map<String, Object>> bodies = new ArrayList<>();
    private Supplier<Map<String, Object>> reply;
    private ConsoleClient client;
    private final List<Long> revoked = new ArrayList<>();

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() throws Exception {
        client = new ConsoleClient() {
            @Override
            Map<String, Object> send(String path, String ts, String sign, Object body) {
                bodies.add((Map<String, Object>) body);
                return reply.get();
            }
        };
        var f = ConsoleClient.class.getDeclaredField("secret");
        f.setAccessible(true);
        f.set(client, "s");
        client.credentialRevoked((agentId, credentialId) -> revoked.add(credentialId));
    }

    private static Map<String, Object> ok(Long userId, String userName) {
        Map<String, Object> d = new HashMap<>();
        d.put("agentId", 7);
        d.put("credentialId", 9);
        d.put("category", "HOST");
        d.put("dbType", "SSH");
        d.put("address", "10.0.0.1");
        d.put("port", 22);
        // 数据库账号 username 与调用者 userName 只差大小写, 必须按 key 精确区分
        d.put("username", "dbuser");
        d.put("ttlSeconds", 600);
        if (userId != null) {
            d.put("userId", userId);
        }
        if (userName != null) {
            d.put("userName", userName);
        }
        return Map.of("code", 200, "data", d);
    }

    @Test
    void tokenPathBypassesCacheAndTakesIdentityFromResponse() throws Exception {
        reply = () -> ok(5L, "bob");
        ConsoleClient.Resolved r = client.resolve("a", "tok", "ut", "1.1.1.1");
        client.resolve("a", "tok", "ut", "1.1.1.1");
        assertEquals(2, bodies.size());
        assertEquals(5L, r.userId());
        assertEquals("bob", r.userName());
        assertEquals("dbuser", r.username());
        assertEquals("ut", bodies.get(0).get("userToken"));
        assertFalse(bodies.get(0).containsKey("userName"));
    }

    /** 匿名缓存不会被 Token 请求命中, Token 请求也不写缓存 */
    @Test
    void tokenPathDoesNotReadOrWriteAnonymousCache() throws Exception {
        reply = () -> ok(null, null);
        client.resolve("a", "tok", null, "1.1.1.1");
        reply = () -> ok(5L, "bob");
        assertEquals(5L, client.resolve("a", "tok", "ut", "1.1.1.1").userId());
        reply = () -> ok(null, null);
        ConsoleClient.Resolved anon = client.resolve("a", "tok", null, "1.1.1.1");
        assertEquals(2, bodies.size());
        assertNull(anon.userId());
        assertNull(anon.userName());
        assertFalse(bodies.get(0).containsKey("userToken"));
    }

    /** 新网关 + 旧后端: 旧后端不认 userToken 照常放行但不回身份, 必须拒而不是降级成匿名 */
    @Test
    void tokenPathMissingIdentityRejected() {
        reply = () -> ok(null, "bob");
        assertThrows(ConsoleClient.Rejected.class, () -> client.resolve("a", "tok", "ut", "1.1.1.1"));
        reply = () -> ok(5L, null);
        assertThrows(ConsoleClient.Rejected.class, () -> client.resolve("a", "tok", "ut", "1.1.1.1"));
        reply = () -> ok(5L, " ");
        assertThrows(ConsoleClient.Rejected.class, () -> client.resolve("a", "tok", "ut", "1.1.1.1"));
    }

    /** 匿名路径即使响应带了身份也置空: 无 Token 不留用户身份 */
    @Test
    void anonymousPathIgnoresIdentityInResponse() throws Exception {
        reply = () -> ok(5L, "bob");
        ConsoleClient.Resolved r = client.resolve("a", "tok", null, "1.1.1.1");
        assertNull(r.userId());
        assertNull(r.userName());
    }

    /** Token 路径的拒绝不会触发凭据级撤权广播 (哪怕同凭据有匿名缓存), 不误关他人连接 */
    @Test
    void tokenPathRejectionDoesNotBroadcast() throws Exception {
        reply = () -> ok(null, null);
        client.resolve("a", "tok", null, "1.1.1.1");
        reply = () -> Map.of("code", 403, "msg", "用户身份已停用");
        ConsoleClient.Rejected e = assertThrows(ConsoleClient.Rejected.class,
                () -> client.resolve("a", "tok", "ut", "1.1.1.1"));
        assertEquals("用户身份已停用", e.getMessage());
        assertTrue(revoked.isEmpty());
        // 匿名缓存仍在: 匿名请求不回控制台
        reply = () -> ok(null, null);
        client.resolve("a", "tok", null, "1.1.1.1");
        assertEquals(2, bodies.size());
    }
}
