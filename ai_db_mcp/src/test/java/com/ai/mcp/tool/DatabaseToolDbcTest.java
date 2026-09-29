package com.ai.mcp.tool;

import com.ai.mcp.audit.AuditLog;
import com.ai.mcp.audit.AuditSpool;
import com.ai.mcp.config.ConsoleClient;
import com.ai.mcp.config.DbcClient;
import com.ai.mcp.config.McpRequestFilter;
import com.ai.mcp.policy.PolicyDecider;
import com.ai.mcp.policy.PolicyGate;
import com.ai.mcp.policy.PolicyStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.common.McpTransportContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DatabaseTool 走 DBC 的全流程: parse → 策略闸门 → execute, 审计字段, DBC 错误映射, 票据续签与撤权关闭
 */
class DatabaseToolDbcTest {

    private static final String SESSION_KEY = Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);

    /** 控制台替身: 策略快照 + 续签 (resolve / resolve-credential) */
    private static class FakeConsole extends ConsoleClient {
        Map<String, Object> data;
        PolicyHeartbeat hb;
        ConsoleClient.Resolved renewed;
        boolean reject;
        int renewCalls;

        @Override
        public Map<String, Object> policySnapshot() {
            return data;
        }

        @Override
        public void policyHeartbeat(PolicyHeartbeat h) {
            this.hb = h;
        }

        @Override
        public Resolved resolve(String agentCode, String token, String userName, String peerIp) {
            renewCalls++;
            if (reject) {
                throw new Rejected("凭据已被撤销");
            }
            return renewed;
        }

        @Override
        public Resolved resolveCredential(String agentCode, String userToken, long credentialId, String userName, String peerIp) {
            renewCalls++;
            if (reject) {
                throw new Rejected("凭据已被撤销");
            }
            return renewed;
        }
    }

    private final FakeConsole console = new FakeConsole();
    private final List<Map<String, Object>> events = new ArrayList<>();
    private FakeDbcServer dbc;
    private DatabaseTool tool;

    @BeforeEach
    void setUp() throws Exception {
        dbc = new FakeDbcServer();
        ObjectMapper om = new ObjectMapper();
        AuditSpool spool = new AuditSpool(console, Files.createTempDirectory("spool")) {
            @Override
            @SuppressWarnings("unchecked")
            public void offer(String json) {
                try {
                    events.add(om.readValue(json, Map.class));
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }
        };
        PolicyStore store = new PolicyStore(console, om);
        // register() 是包级可见的 @PostConstruct, 跨包只能反射调用
        var register = PolicyStore.class.getDeclaredMethod("register");
        register.setAccessible(true);
        register.invoke(store);
        policies();
        tool = new DatabaseTool(new AuditLog(spool, om, console), new PolicyGate(new PolicyDecider(store), console),
                new DbcClient(dbc.baseUrl(), om), console);
        new ToolAuth().setConsole(console);
    }

    @AfterEach
    void tearDown() {
        dbc.close();
    }

    private void policies(Object... policies) {
        String v = "v" + System.nanoTime();
        console.data = Map.of("version", v, "policies", List.of(policies));
        console.hb.onReport(v);
    }

    private static Map<String, Object> policy(long id, String type, String mode, String op) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", id);
        p.put("name", "p-" + id);
        p.put("type", type);
        p.put("hostType", "MYSQL");
        p.put("hostIds", List.of(0));
        p.put("agentIds", List.of(0));
        p.put("approvalMode", mode);
        p.put("rulesInvalid", false);
        p.put("ops", op == null ? List.of() : List.of(Map.of("value", op, "matchType", "EXACT")));
        return p;
    }

    private static ConsoleClient.DbcTicket ticket(String name, long ttlMs) {
        return new ConsoleClient.DbcTicket(name, System.currentTimeMillis() + ttlMs, SESSION_KEY);
    }

    private static ConsoleClient.Resolved cred(ConsoleClient.DbcTicket t) {
        return new ConsoleClient.Resolved(7, 9, "DATABASE", "MYSQL", "10.0.0.1", 3306, "appdb", "u", null,
                "agent-7", "alice", 1L, t);
    }

    /** 固定资源模式的请求上下文 */
    private static McpTransportContext fixedCtx(ConsoleClient.DbcTicket t) {
        Map<String, Object> m = new HashMap<>();
        m.put(McpRequestFilter.CREDENTIAL, cred(t));
        m.put(McpRequestFilter.VIRTUAL_TOKEN, "vt");
        m.put(McpRequestFilter.PEER_IP, "1.1.1.1");
        m.put(McpRequestFilter.REQUEST_ID, new AtomicReference<String>());
        return McpTransportContext.create(m);
    }

    /** 用户自选模式的请求上下文 (与 Filter 预置的 attribute 一致) */
    private static McpTransportContext userCtx() {
        Map<String, Object> m = new HashMap<>();
        m.put(McpRequestFilter.USER_IDENTITY, new ConsoleClient.ResolvedUser(7, 3, "alice", "agent-7"));
        m.put(McpRequestFilter.USER_TOKEN, "ut");
        m.put(McpRequestFilter.IN_FLIGHT, ConcurrentHashMap.<Long>newKeySet());
        m.put(McpRequestFilter.RESOLVED, new AtomicReference<ConsoleClient.Resolved>());
        m.put(McpRequestFilter.DENY_REASON, new AtomicReference<String>());
        m.put(McpRequestFilter.PEER_IP, "1.1.1.1");
        m.put(McpRequestFilter.REQUEST_ID, new AtomicReference<String>());
        return McpTransportContext.create(m);
    }

    private String connect(McpTransportContext ctx) {
        Map<String, Object> r = tool.db_create_connection(null, ctx);
        assertEquals(true, r.get("success"), String.valueOf(r));
        return (String) r.get("connectionId");
    }

    private static String parseOk(String op, String tables) {
        return "{\"ok\":true,\"data\":{\"sqlDigest\":\"d1\",\"parserVersion\":\"gsp-1\",\"statementCount\":1,\"op\":\"" + op
                + "\",\"tables\":" + tables + ",\"defaultNamespace\":\"appdb\"}}";
    }

    private static String error(String type, String msg) {
        return "{\"ok\":false,\"error\":{\"type\":\"" + type + "\",\"message\":\"" + msg + "\"}}";
    }

    private Map<String, Object> lastEvent() {
        return events.get(events.size() - 1);
    }

    @Test
    void createRegistersLocallyWithoutCallingDbc() {
        String id = connect(fixedCtx(ticket("t1", 300_000)));
        assertTrue(id.startsWith("9:"));
        assertTrue(dbc.requests.isEmpty());
    }

    @Test
    void selectHappyPath() {
        McpTransportContext ctx = fixedCtx(ticket("t1", 300_000));
        String id = connect(ctx);
        dbc.reply("parse", parseOk("SELECT", "[\"appdb.t\"]"));
        dbc.reply("execute", "{\"ok\":true,\"data\":{\"headers\":[\"a\"],\"types\":[\"INT\"],\"rows\":[[1],[2]],"
                + "\"rowCount\":2,\"truncated\":true,\"affectedRows\":-1,\"operation\":0,\"durationMs\":3}}");

        Map<String, Object> r = tool.db_execute(id, "select a from t", 2, ctx, null);

        assertEquals(true, r.get("success"));
        assertEquals("query", r.get("type"));
        assertEquals(List.of("a"), r.get("columns"));
        assertEquals(2, r.get("rowCount"));
        assertEquals(true, r.get("truncated"));
        assertFalse(r.containsKey(AuditLog.AUDIT_OP));
        assertFalse(r.containsKey(AuditLog.AUDIT_TABLES));

        FakeDbcServer.Req exec = dbc.of("execute").get(0);
        String connectId = (String) exec.json().get("connectId");
        assertTrue(connectId.matches("agent_9_[0-9a-f]{32}"), connectId);
        assertEquals(dbc.of("parse").get(0).json().get("connectId"), connectId);
        assertEquals("d1", exec.json().get("sqlDigest"));
        assertEquals("SELECT", exec.json().get("op"));
        assertEquals(List.of("appdb.t"), exec.json().get("tables"));
        assertEquals(2, exec.json().get("maxRows"));
        assertEquals("t1", exec.headers().get("X-Dbc-Ticket"));

        Map<String, Object> e = lastEvent();
        assertEquals("SUCCESS", e.get("status"));
        assertEquals("select a from t", e.get("summary"));
        assertEquals(2, e.get("lines"));
        assertEquals("SELECT", e.get("op"));
        assertEquals("SELECT", e.get("type"));
        assertEquals(List.of("appdb.t"), e.get("tables"));
        assertEquals(true, e.get("truncated"));
        // 票据与会话密钥不进审计
        assertFalse(e.toString().contains("t1") || e.toString().contains(SESSION_KEY));
    }

    @Test
    void ddlAffectedRowsRecordedAsZero() {
        McpTransportContext ctx = fixedCtx(ticket("t1", 300_000));
        String id = connect(ctx);
        dbc.reply("parse", parseOk("CREATE", "[\"appdb.x\"]"));
        dbc.reply("execute", "{\"ok\":true,\"data\":{\"headers\":[],\"types\":[],\"rows\":[],\"rowCount\":0,"
                + "\"truncated\":false,\"affectedRows\":-1,\"operation\":1,\"durationMs\":3}}");

        Map<String, Object> r = tool.db_execute(id, "create table x(a int)", null, ctx, null);

        assertEquals("update", r.get("type"));
        assertEquals(0L, r.get("affectedRows"));
        assertEquals(false, r.get("truncated"));
        assertFalse(dbc.of("execute").get(0).json().containsKey("maxRows"));
        assertEquals(0, lastEvent().get("lines"));
    }

    @Test
    void policyDenyDoesNotExecute() {
        policies(policy(1, PolicyStore.TYPE_BLACKLIST, "NONE", "DELETE"));
        McpTransportContext ctx = fixedCtx(ticket("t1", 300_000));
        String id = connect(ctx);
        dbc.reply("parse", parseOk("DELETE", "[\"appdb.t\"]"));

        Map<String, Object> r = tool.db_execute(id, "delete from t", null, ctx, null);

        assertEquals(false, r.get("success"));
        assertFalse(r.containsKey("denySource"));
        assertTrue(dbc.of("execute").isEmpty());
        Map<String, Object> e = lastEvent();
        assertEquals("DENIED", e.get("status"));
        assertEquals("POLICY", e.get("denySource"));
        assertEquals(0, e.get("lines"));
        assertEquals("DELETE", e.get("op"));
        assertEquals(List.of("appdb.t"), e.get("tables"));
        assertNull(e.get("truncated"));
    }

    @Test
    void dbcParseRejectionMapsToDbcSource() {
        McpTransportContext ctx = fixedCtx(ticket("t1", 300_000));
        String id = connect(ctx);
        dbc.reply("parse", error("MULTI_STATEMENT", "只允许单条语句"));

        Map<String, Object> r = tool.db_execute(id, "select 1; select 2", null, ctx, null);

        assertEquals(false, r.get("success"));
        assertTrue(((String) r.get("error")).contains("只允许单条语句"));
        assertTrue(dbc.of("execute").isEmpty());
        Map<String, Object> e = lastEvent();
        assertEquals("DENIED", e.get("status"));
        assertEquals("DBC", e.get("denySource"));
        assertEquals(0, e.get("lines"));
        assertNull(e.get("op"));
        assertNull(e.get("tables"));
    }

    @Test
    void execErrorIsFailedAndConsumesRateButDbcDenyDoesNot() {
        Map<String, Object> rate = policy(1, PolicyStore.TYPE_RATE_LIMIT, "NONE", null);
        rate.put("limit", 1);
        rate.put("windowSeconds", 60);
        policies(rate);
        McpTransportContext ctx = fixedCtx(ticket("t1", 300_000));
        String id = connect(ctx);

        // DBC 拒绝不占配额
        dbc.reply("parse", error("PARSE", "语法错误"));
        tool.db_execute(id, "selec", null, ctx, null);
        // 数据库返回 SQL 错误: FAILED, 但算执行过
        dbc.reply("parse", parseOk("SELECT", "[\"appdb.nope\"]"));
        dbc.reply("execute", error("EXEC", "Table 'appdb.nope' doesn't exist"));
        Map<String, Object> r = tool.db_execute(id, "select * from nope", null, ctx, null);
        assertEquals("SQL execution error: Table 'appdb.nope' doesn't exist", r.get("error"));
        Map<String, Object> e = lastEvent();
        assertEquals("FAILED", e.get("status"));
        assertNull(e.get("denySource"));
        assertEquals("SELECT", e.get("op"));

        dbc.reply("parse", parseOk("SELECT", "[\"appdb.t\"]"));
        r = tool.db_execute(id, "select * from t", null, ctx, null);
        assertEquals("超出频率限制, 已拒绝执行", r.get("error"));
        assertEquals(1, dbc.of("execute").size());
    }

    @Test
    void internalAndUnreachableAreFailed() {
        McpTransportContext ctx = fixedCtx(ticket("t1", 300_000));
        String id = connect(ctx);
        dbc.reply("parse", error("INTERNAL", "NullPointerException at com.x.Y"));
        Map<String, Object> r = tool.db_execute(id, "select 1", null, ctx, null);
        // 对外固定文案, 详情只进审计, 内部字段不外传
        assertEquals("DBC 内部错误, 请联系管理员", r.get("error"));
        assertNull(r.get("auditError"));
        assertEquals("FAILED", lastEvent().get("status"));
        assertNull(lastEvent().get("denySource"));
        assertEquals("DBC 内部错误: NullPointerException at com.x.Y", lastEvent().get("error"));

        dbc.close();
        r = tool.db_execute(id, "select 1", null, ctx, null);
        assertEquals("DBC 内部错误, 请联系管理员", r.get("error"));
        assertNull(r.get("auditError"));
        assertEquals("FAILED", lastEvent().get("status"));
        assertTrue(((String) lastEvent().get("error")).startsWith("DBC 不可达"), String.valueOf(lastEvent()));
    }

    @Test
    void connClosedDropsLocalConnection() {
        McpTransportContext ctx = fixedCtx(ticket("t1", 300_000));
        String id = connect(ctx);
        dbc.reply("parse", parseOk("SELECT", "[\"appdb.t\"]"));
        dbc.reply("execute", error("CONN_CLOSED", "连接已关闭"));

        Map<String, Object> r = tool.db_execute(id, "select * from t", null, ctx, null);

        assertTrue(((String) r.get("error")).contains("db_create_connection"));
        assertEquals("DENIED", lastEvent().get("status"));
        assertEquals("DBC", lastEvent().get("denySource"));
        assertEquals(List.of(), tool.db_list_connections(ctx).get("connections"));
    }

    @Test
    void expiringTicketRenewedBeforeCallingDbc() {
        McpTransportContext ctx = fixedCtx(ticket("old", 10_000));
        String id = connect(ctx);
        console.renewed = cred(ticket("new", 300_000));
        dbc.reply("parse", parseOk("SELECT", "[\"appdb.t\"]"));
        dbc.reply("execute", "{\"ok\":true,\"data\":{\"headers\":[\"a\"],\"rows\":[],\"truncated\":false}}");

        Map<String, Object> r = tool.db_execute(id, "select a from t", null, ctx, null);

        assertEquals(true, r.get("success"), String.valueOf(r));
        assertEquals(1, console.renewCalls);
        assertEquals("new", dbc.of("parse").get(0).headers().get("X-Dbc-Ticket"));
        assertEquals("new", dbc.of("execute").get(0).headers().get("X-Dbc-Ticket"));
    }

    @Test
    void renewalRejectedClosesConnection() throws Exception {
        McpTransportContext ctx = fixedCtx(ticket("old", 10_000));
        String id = connect(ctx);
        console.reject = true;

        Map<String, Object> r = tool.db_execute(id, "select 1", null, ctx, null);

        assertEquals("凭据已被撤销", r.get("error"));
        assertEquals("DENIED", lastEvent().get("status"));
        assertEquals("AUTH", lastEvent().get("denySource"));
        assertTrue(dbc.of("parse").isEmpty());
        awaitClose();
        assertEquals("old", dbc.of("close").get(0).headers().get("X-Dbc-Ticket"));
        assertEquals(List.of(), tool.db_list_connections(ctx).get("connections"));
    }

    @Test
    void userModeRevokedClosesConnection() throws Exception {
        console.renewed = cred(ticket("u1", 300_000));
        McpTransportContext create = userCtx();
        Map<String, Object> c = tool.db_create_connection(9L, create);
        assertEquals(true, c.get("success"), String.valueOf(c));
        console.reject = true;

        Map<String, Object> r = tool.db_execute((String) c.get("connectionId"), "select 1", null, userCtx(), null);

        assertEquals(false, r.get("success"));
        assertEquals("AUTH", lastEvent().get("denySource"));
        awaitClose();
        assertTrue(dbc.of("parse").isEmpty());
    }

    @Test
    void closeConnectionCallsDbc() {
        McpTransportContext ctx = fixedCtx(ticket("t1", 300_000));
        String id = connect(ctx);
        Map<String, Object> r = tool.db_close_connection(id, ctx);
        assertEquals(true, r.get("success"));
        assertFalse(r.containsKey("warning"));
        assertEquals(1, dbc.of("close").size());
        assertTrue(((String) dbc.of("close").get(0).json().get("connectId")).startsWith("agent_9_"));
        assertEquals(List.of(), tool.db_list_connections(ctx).get("connections"));
    }

    @Test
    void createRejectsMissingTicketOrConfig() throws Exception {
        Map<String, Object> r = tool.db_create_connection(null, fixedCtx(null));
        assertEquals(false, r.get("success"));
        assertTrue(((String) r.get("error")).startsWith("控制台版本不匹配"));

        ObjectMapper om = new ObjectMapper();
        DatabaseTool unconfigured = new DatabaseTool(new AuditLog(new AuditSpool(console, Files.createTempDirectory("s")) {
            @Override
            public void offer(String json) {
            }
        }, om, console), null, new DbcClient("", om), console);
        r = unconfigured.db_create_connection(null, fixedCtx(ticket("t1", 300_000)));
        assertEquals("未配置 dbc.base-url, 数据库工具不可用", r.get("error"));
    }

    /** 撤权关闭是异步通知 DBC 的 */
    private void awaitClose() throws InterruptedException {
        for (int i = 0; i < 100 && dbc.of("close").isEmpty(); i++) {
            Thread.sleep(20);
        }
        assertEquals(1, dbc.of("close").size());
    }
}
