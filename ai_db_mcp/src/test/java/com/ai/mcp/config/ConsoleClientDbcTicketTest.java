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

/**
 * resolve 解析 DBC 票据、票据快到期绕过缓存续签、续签被拒通知撤权; HOST 缓存行为不变
 */
class ConsoleClientDbcTicketTest {

    private final List<String> paths = new ArrayList<>();
    private Supplier<Map<String, Object>> reply;
    private ConsoleClient client;

    @BeforeEach
    void setUp() throws Exception {
        client = new ConsoleClient() {
            @Override
            Map<String, Object> send(String path, String ts, String sign, Object body) {
                paths.add(path);
                return reply.get();
            }
        };
        var f = ConsoleClient.class.getDeclaredField("secret");
        f.setAccessible(true);
        f.set(client, "s");
    }

    private static Map<String, Object> ok(String category, Long ticketExpireAt) {
        Map<String, Object> d = new HashMap<>();
        d.put("agentId", 7);
        d.put("credentialId", 9);
        d.put("category", category);
        d.put("dbType", "DATABASE".equals(category) ? "MYSQL" : "SSH");
        d.put("address", "10.0.0.1");
        d.put("port", 3306);
        d.put("hostId", 1);
        d.put("ttlSeconds", 600);
        if (ticketExpireAt != null) {
            d.put("dbcTicket", "t-" + ticketExpireAt);
            d.put("dbcTicketExpireAt", ticketExpireAt);
            d.put("dbcSessionKey", "k");
        }
        return Map.of("code", 200, "data", d);
    }

    @Test
    void ticketParsedAndHiddenFromToString() throws Exception {
        long exp = System.currentTimeMillis() + 300_000;
        reply = () -> ok("DATABASE", exp);
        ConsoleClient.Resolved r = client.resolve("a", "tok", null, "1.1.1.1");
        assertEquals("t-" + exp, r.dbc().ticket());
        assertEquals(exp, r.dbc().expireAt());
        assertEquals("k", r.dbc().sessionKey());
        assertFalse(r.toString().contains("t-" + exp));
    }

    @Test
    void cacheHitWhileTicketFresh() throws Exception {
        reply = () -> ok("DATABASE", System.currentTimeMillis() + 300_000);
        client.resolve("a", "tok", null, "1.1.1.1");
        client.resolve("a", "tok", null, "1.1.1.1");
        assertEquals(1, paths.size());
    }

    @Test
    void expiringTicketBypassesCache() throws Exception {
        reply = () -> ok("DATABASE", System.currentTimeMillis() + 30_000);
        client.resolve("a", "tok", null, "1.1.1.1");
        long fresh = System.currentTimeMillis() + 300_000;
        reply = () -> ok("DATABASE", fresh);
        ConsoleClient.Resolved r = client.resolve("a", "tok", null, "1.1.1.1");
        assertEquals(2, paths.size());
        assertEquals(fresh, r.dbc().expireAt());
    }

    @Test
    void hostCacheUnchanged() throws Exception {
        reply = () -> ok("HOST", null);
        ConsoleClient.Resolved r = client.resolve("a", "tok", null, "1.1.1.1");
        client.resolve("a", "tok", null, "1.1.1.1");
        assertEquals(1, paths.size());
        assertNull(r.dbc());
    }

    @Test
    void missingTicketFieldsYieldNull() throws Exception {
        Map<String, Object> resp = ok("DATABASE", System.currentTimeMillis() + 300_000);
        @SuppressWarnings("unchecked")
        Map<String, Object> d = (Map<String, Object>) resp.get("data");
        d.remove("dbcSessionKey");
        reply = () -> resp;
        assertNull(client.resolve("a", "tok", null, "1.1.1.1").dbc());
    }

    @Test
    void renewalRejectedNotifiesRevocation() throws Exception {
        List<long[]> revoked = new ArrayList<>();
        client.credentialRevoked((agentId, credentialId) -> revoked.add(new long[]{agentId, credentialId}));
        reply = () -> ok("DATABASE", System.currentTimeMillis() + 30_000);
        client.resolve("a", "tok", null, "1.1.1.1");
        reply = () -> Map.of("code", 403, "msg", "凭据已被撤销");
        assertThrows(ConsoleClient.Rejected.class, () -> client.resolve("a", "tok", null, "1.1.1.1"));
        assertEquals(1, revoked.size());
        assertEquals(7, revoked.get(0)[0]);
        assertEquals(9, revoked.get(0)[1]);
        // 从未放行过的 key 被拒不算撤权
        assertThrows(ConsoleClient.Rejected.class, () -> client.resolve("a", "other", null, "1.1.1.1"));
        assertEquals(1, revoked.size());
    }

    /** 多个监听者都收到撤权通知, 后注册的不会顶掉先注册的 */
    @Test
    void revocationNotifiesAllListeners() throws Exception {
        List<String> got = new ArrayList<>();
        client.credentialRevoked((agentId, credentialId) -> got.add("first-" + credentialId));
        client.credentialRevoked((agentId, credentialId) -> got.add("second-" + credentialId));
        reply = () -> ok("DATABASE", System.currentTimeMillis() + 30_000);
        client.resolve("a", "tok", null, "1.1.1.1");
        reply = () -> Map.of("code", 403, "msg", "凭据已被撤销");
        assertThrows(ConsoleClient.Rejected.class, () -> client.resolve("a", "tok", null, "1.1.1.1"));
        assertEquals(List.of("first-9", "second-9"), got);
    }
}
