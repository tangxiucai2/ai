package com.ai.mcp.policy;

import com.ai.mcp.config.ConsoleClient;
import com.ai.mcp.config.McpRequestFilter;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.common.McpTransportContext;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PolicyGate 的 DATABASE 路径: 审批闸门 operation 填 SQL 原文, 审批放行前用同一组输入 fresh decide,
 * 以 policyRevision 相等为准 (设计文档 §5 P4 / P8); HOST 路径文案与请求体不变
 */
class PolicyGateDatabaseTest {

    private static class FakeConsoleClient extends ConsoleClient {
        Map<String, Object> data;
        PolicyHeartbeat captured;
        final List<Map<String, Object>> gateBodies = new ArrayList<>();
        ApprovalGateResult result;
        /** /gate 调用期间要执行的动作 (模拟审批中管理员改策略) */
        Runnable duringGate = () -> { };

        @Override
        public int confirmTimeoutSeconds() {
            return 1;
        }

        @Override
        public Map<String, Object> policySnapshot() {
            return data;
        }

        @Override
        public void policyHeartbeat(PolicyHeartbeat h) {
            this.captured = h;
        }

        @Override
        public ApprovalGateResult approvalGate(Map<String, Object> body) {
            gateBodies.add(body);
            duringGate.run();
            return result;
        }
    }

    private static final String SQL = "UPDATE order_a SET x = 1";

    private final FakeConsoleClient console = new FakeConsoleClient();
    private PolicyGate gate;

    private void load(String version, Object... policies) {
        console.data = Map.of("version", version, "policies", List.of(policies));
        console.captured.onReport(version);
    }

    private void setUp(Object... policies) {
        PolicyStore store = new PolicyStore(console, new ObjectMapper());
        store.register();
        load("v1", policies);
        assertFalse(store.unavailable());
        gate = new PolicyGate(new PolicyDecider(store), console);
    }

    private static Map<String, Object> policy(long id, String type, String hostType, String mode, String op) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", id);
        p.put("name", "p-" + id);
        p.put("type", type);
        p.put("hostType", hostType);
        p.put("hostIds", List.of(0));
        p.put("agentIds", List.of(0));
        p.put("approvalMode", mode);
        p.put("rulesInvalid", false);
        p.put("ops", List.of(Map.of("value", op, "matchType", "EXACT")));
        return p;
    }

    private static McpTransportContext ctx(String dbType) {
        ConsoleClient.Resolved cred = new ConsoleClient.Resolved(7, 9, "SSH".equals(dbType) ? "HOST" : "DATABASE",
                dbType, "10.0.0.1", 3306, "appdb", "u", null, "agent-7", "alice", 1L);
        return McpTransportContext.create(Map.of(McpRequestFilter.CREDENTIAL, cred));
    }

    private PolicyDecider.Decision checkDb() {
        return gate.checkDatabase(ctx("MYSQL"), null, SQL, "UPDATE", List.of("appdb.order_a"), "appdb", "db_execute");
    }

    /** P4 前半: 需审批 → 建单, 请求体 operation 是 SQL 原文, 未放行 */
    @Test
    void approvalPendingCarriesSql() {
        setUp(policy(1, PolicyStore.TYPE_WHITELIST, "MYSQL", "APPROVAL", "UPDATE"));
        console.result = new ConsoleClient.ApprovalGateResult("PENDING", 1L, "AP-1", 1L, null, null);
        PolicyDecider.Decision r = checkDb();
        assertEquals(PolicyDecider.Kind.DENY, r.kind());
        assertEquals("PENDING", r.approvalStatus());
        assertEquals("AP-1", r.approvalNo());
        assertTrue(r.reason().startsWith("该SQL需管理员审批"));
        assertEquals(SQL, console.gateBodies.get(0).get("operation"));
        assertEquals("db_execute", console.gateBodies.get(0).get("tool"));
    }

    /** 固定资源审批带 Token 反查的可信 userId/userName (审批指纹按用户隔离); 匿名不带 userId */
    @Test
    void approvalCarriesFixedResourceTrustedUser() {
        setUp(policy(1, PolicyStore.TYPE_WHITELIST, "MYSQL", "APPROVAL", "UPDATE"));
        console.result = new ConsoleClient.ApprovalGateResult("PENDING", 1L, "AP-1", 1L, null, null);
        ConsoleClient.Resolved named = new ConsoleClient.Resolved(7, 9, "DATABASE", "MYSQL", "10.0.0.1", 3306,
                "appdb", "u", null, "agent-7", "bob", 1L, null, 6L);
        gate.checkDatabase(McpTransportContext.create(Map.of(McpRequestFilter.CREDENTIAL, named)),
                null, SQL, "UPDATE", List.of("appdb.order_a"), "appdb", "db_execute");
        assertEquals(6L, console.gateBodies.get(0).get("userId"));
        assertEquals("bob", console.gateBodies.get(0).get("userName"));

        ConsoleClient.Resolved anon = new ConsoleClient.Resolved(7, 9, "DATABASE", "MYSQL", "10.0.0.1", 3306,
                "appdb", "u", null, "agent-7", null, 1L);
        gate.checkDatabase(McpTransportContext.create(Map.of(McpRequestFilter.CREDENTIAL, anon)),
                null, SQL, "UPDATE", List.of("appdb.order_a"), "appdb", "db_execute");
        assertFalse(console.gateBodies.get(1).containsKey("userId"));
    }

    /** P4 后半: 审批通过, 策略未变 → fresh decide 的 policyRevision 相等 → 放行 */
    @Test
    void approvalAllowWhenRevisionUnchanged() {
        setUp(policy(1, PolicyStore.TYPE_WHITELIST, "MYSQL", "APPROVAL", "UPDATE"));
        console.result = new ConsoleClient.ApprovalGateResult("ALLOW", 1L, "AP-1", null, null, null);
        PolicyDecider.Decision r = checkDb();
        assertEquals(PolicyDecider.Kind.ALLOW, r.kind());
        assertTrue(r.confirmWaited());
    }

    /** P8: 审批单消费时管理员已改了命中策略 → policyRevision 不同 → 拒绝, 不能直接执行 */
    @Test
    void approvalRejectedWhenPolicyChanged() {
        setUp(policy(1, PolicyStore.TYPE_WHITELIST, "MYSQL", "APPROVAL", "UPDATE"));
        Map<String, Object> edited = policy(1, PolicyStore.TYPE_WHITELIST, "MYSQL", "APPROVAL", "UPDATE");
        edited.put("priority", 20);
        console.duringGate = () -> load("v2", edited);
        console.result = new ConsoleClient.ApprovalGateResult("ALLOW", 1L, "AP-1", null, null, null);
        PolicyDecider.Decision r = checkDb();
        assertEquals(PolicyDecider.Kind.DENY, r.kind());
        assertEquals("凭证已消费但策略已变更, 已拒绝执行", r.reason());
    }

    /** 审批期间数据范围被收窄: fresh decide 变成 DENY → 拒绝, 来源保留为策略判定 */
    @Test
    void approvalRejectedWhenScopeNarrowed() {
        setUp(policy(1, PolicyStore.TYPE_WHITELIST, "MYSQL", "APPROVAL", "UPDATE"));
        Map<String, Object> scope = new LinkedHashMap<>(policy(2, PolicyStore.TYPE_DATA_SCOPE, "MYSQL", "NONE", "X"));
        scope.put("ops", List.of());
        scope.put("tables", List.of(Map.of("tableName", "user", "matchType", "EXACT")));
        console.duringGate = () -> load("v2", policy(1, PolicyStore.TYPE_WHITELIST, "MYSQL", "APPROVAL", "UPDATE"), scope);
        console.result = new ConsoleClient.ApprovalGateResult("ALLOW", 1L, "AP-1", null, null, null);
        PolicyDecider.Decision r = checkDb();
        assertEquals(PolicyDecider.Kind.DENY, r.kind());
        assertEquals(PolicyDecider.Source.POLICY, r.source());
    }

    /** CONFIRM 档在不支持 elicitation 的客户端上拒绝 (与 HOST 同) */
    @Test
    void confirmWithoutElicitationDenied() {
        setUp(policy(1, PolicyStore.TYPE_BLACKLIST, "MYSQL", "CONFIRM", "UPDATE"));
        PolicyDecider.Decision r = checkDb();
        assertEquals(PolicyDecider.Kind.DENY, r.kind());
        assertEquals(PolicyDecider.Source.CONFIRM, r.source());
    }

    /** 拿不到目标资源 → 拒绝 (与 HOST 同口径) */
    @Test
    void missingHostIdDenied() {
        setUp();
        ConsoleClient.Resolved cred = new ConsoleClient.Resolved(7, 9, "DATABASE", "MYSQL", "10.0.0.1", 3306,
                "appdb", "u", null, "agent-7", "alice", null);
        PolicyDecider.Decision r = gate.checkDatabase(McpTransportContext.create(Map.of(McpRequestFilter.CREDENTIAL, cred)),
                null, SQL, "UPDATE", List.of("appdb.order_a"), "appdb", "db_execute");
        assertEquals(PolicyDecider.Kind.DENY, r.kind());
    }

    /** 非数据库类凭据 (SSH) 走 checkDatabase → 拒绝, 不能按"无 DATABASE 策略"放行 */
    @Test
    void nonDatabaseCredentialDenied() {
        setUp();
        PolicyDecider.Decision r = gate.checkDatabase(ctx("SSH"), null, SQL, "UPDATE", List.of("appdb.order_a"), "appdb", "db_execute");
        assertEquals(PolicyDecider.Kind.DENY, r.kind());
        assertEquals(PolicyDecider.Source.POLICY, r.source());
        assertEquals("该凭据不是数据库类资源, 不能执行 SQL", r.reason());
    }

    /** 限流记账按类别: recordDatabaseRate 只占 DATABASE 配额 */
    @Test
    void recordDatabaseRate() {
        Map<String, Object> rate = policy(1, PolicyStore.TYPE_RATE_LIMIT, "MYSQL", "NONE", "X");
        rate.put("ops", List.of());
        rate.put("limit", 1);
        rate.put("windowSeconds", 60);
        setUp(rate);
        assertEquals(PolicyDecider.Kind.ALLOW, checkDb().kind());
        gate.recordRate(ctx("SSH"));
        assertEquals(PolicyDecider.Kind.ALLOW, checkDb().kind());
        gate.recordDatabaseRate(ctx("MYSQL"));
        assertEquals(PolicyDecider.Kind.DENY, checkDb().kind());
    }

    /** HOST 路径不变: operation 仍是命令原文, 文案仍是"命令" */
    @Test
    void hostPathUnchanged() {
        setUp(policy(1, PolicyStore.TYPE_WHITELIST, "SSH", "APPROVAL", "ls"));
        console.result = new ConsoleClient.ApprovalGateResult("PENDING", 1L, "AP-2", 1L, null, null);
        PolicyDecider.Decision r = gate.check(ctx("SSH"), null, "ls", "ssh_execute");
        assertEquals("该命令需管理员审批, 已提交审批单 AP-2。请勿修改命令内容——修改后需重新审批。审批通过后原样重试本命令即可执行。",
                r.reason());
        assertEquals("ls", console.gateBodies.get(0).get("operation"));
    }

    /** 支持 elicitation 但永不作答的客户端: 用来走到确认超时分支 */
    private static McpSyncServerExchange silentExchange() {
        return new McpSyncServerExchange(null) {
            @Override
            public McpSchema.ClientCapabilities getClientCapabilities() {
                return McpSchema.ClientCapabilities.builder().elicitation().build();
            }

            @Override
            public McpSchema.ElicitResult createElicitation(McpSchema.ElicitRequest request) {
                try {
                    Thread.sleep(10_000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return null;
            }
        };
    }

    /** 抓 PolicyGate 的 "二次确认超时" INFO 日志 */
    private static List<String> timeoutLogs(Runnable action) {
        Logger logger = (Logger) LoggerFactory.getLogger(PolicyGate.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            action.run();
        } finally {
            logger.detachAppender(appender);
        }
        return appender.list.stream().map(ILoggingEvent::getFormattedMessage)
                .filter(m -> m.startsWith("二次确认超时")).toList();
    }

    /** 确认超时日志: DATABASE 只打 sha256 前缀 + 长度, 不出现 SQL 原文 */
    @Test
    void confirmTimeoutLogOmitsSql() {
        setUp(policy(1, PolicyStore.TYPE_BLACKLIST, "MYSQL", "CONFIRM", "UPDATE"));
        String secretSql = "UPDATE order_a SET card_no = '6222020000001234'";
        List<PolicyDecider.Decision> out = new ArrayList<>();
        List<String> logs = timeoutLogs(() -> out.add(gate.checkDatabase(ctx("MYSQL"), silentExchange(), secretSql,
                "UPDATE", List.of("appdb.order_a"), "appdb", "db_execute")));
        assertEquals(PolicyDecider.Kind.DENY, out.get(0).kind());
        assertEquals(1, logs.size());
        assertFalse(logs.get(0).contains(secretSql));
        assertFalse(logs.get(0).contains("6222020000001234"));
        assertEquals("二次确认超时 policy=p-1 sql=" + PolicyGate.sqlLogDigest(secretSql), logs.get(0));
        assertTrue(PolicyGate.sqlLogDigest(secretSql).matches("sha256:[0-9a-f]{12},len=" + secretSql.length()));
    }

    /** 确认超时日志: HOST 仍打命令原文, 格式不变 */
    @Test
    void confirmTimeoutLogHostUnchanged() {
        setUp(policy(1, PolicyStore.TYPE_BLACKLIST, "SSH", "CONFIRM", "ls"));
        List<String> logs = timeoutLogs(() -> gate.check(ctx("SSH"), silentExchange(), "ls -la", "ssh_execute"));
        assertEquals(List.of("二次确认超时 policy=p-1 command=ls -la"), logs);
    }
}
