package com.ai.mcp.policy;

import com.ai.mcp.config.ConsoleClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PolicyStore 接收 DATABASE 类策略 (字段口径以 SOAG AgentGatewayPolicySnapshotVO / getPolicySnapshot 为准):
 * DATA_SCOPE 的 tables:[{tableName, matchType}]、DATABASE 操作项只许 EXACT 十项
 */
class PolicyStoreDatabaseTest {

    private static class FakeConsoleClient extends ConsoleClient {
        Map<String, Object> data;

        @Override
        public Map<String, Object> policySnapshot() {
            return data;
        }
    }

    private static PolicyStore.Snapshot fetch(Map<String, Object> policy) throws Exception {
        FakeConsoleClient console = new FakeConsoleClient();
        console.data = Map.of("version", "v1", "policies", List.of(policy));
        return new PolicyStore(console, new ObjectMapper()).fetch("v1");
    }

    private static Map<String, Object> base(String type, String hostType) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", 1L);
        p.put("name", "p");
        p.put("type", type);
        p.put("hostType", hostType);
        p.put("hostIds", List.of(0));
        p.put("agentIds", List.of(0));
        p.put("approvalMode", "NONE");
        p.put("rulesInvalid", false);
        p.put("ops", List.of());
        return p;
    }

    private static Map<String, Object> dataScope(List<?> tables) {
        Map<String, Object> p = base(PolicyStore.TYPE_DATA_SCOPE, "MYSQL");
        p.put("tables", tables);
        return p;
    }

    @Test
    void dataScopeTablesParsed() throws Exception {
        PolicyStore.Policy p = fetch(dataScope(List.of(
                Map.of("tableName", "order_", "matchType", "PREFIX"),
                Map.of("tableName", "sales.订单", "matchType", "EXACT"),
                Map.of("tableName", "_log", "matchType", "SUFFIX")))).policies().get(0);
        assertTrue(p.database());
        assertEquals(List.of(new PolicyStore.Table("order_", "PREFIX"), new PolicyStore.Table("sales.订单", "EXACT"),
                new PolicyStore.Table("_log", "SUFFIX")), p.tables());
    }

    @Test
    void dataScopeTablesMissingFailsWhenValid() {
        assertThrows(IllegalStateException.class, () -> fetch(base(PolicyStore.TYPE_DATA_SCOPE, "MYSQL")));
    }

    @Test
    void dataScopeBadMatchTypeFails() {
        assertThrows(IllegalStateException.class,
                () -> fetch(dataScope(List.of(Map.of("tableName", "t", "matchType", "REGEX")))));
    }

    @Test
    void dataScopeBadTableNameFails() {
        assertThrows(IllegalStateException.class,
                () -> fetch(dataScope(List.of(Map.of("tableName", "t;drop", "matchType", "EXACT")))));
    }

    /** 控制台对无效行下发 tables=[] + rulesInvalid=true: 正常接收, 由裁决侧按拒绝处理 */
    @Test
    void invalidDataScopeAccepted() throws Exception {
        Map<String, Object> p = dataScope(List.of());
        p.put("rulesInvalid", true);
        PolicyStore.Policy got = fetch(p).policies().get(0);
        assertTrue(got.rulesInvalid());
        assertEquals(List.of(), got.tables());
    }

    @Test
    void databaseOpsAcceptExactTenOps() throws Exception {
        Map<String, Object> p = base(PolicyStore.TYPE_WHITELIST, "ORACLE");
        p.put("ops", List.of(Map.of("value", "SELECT", "matchType", "EXACT"),
                Map.of("value", "describe", "matchType", "EXACT")));
        assertEquals(2, fetch(p).policies().get(0).ops().size());
    }

    @Test
    void databaseOpsRejectKeyword() {
        Map<String, Object> p = base(PolicyStore.TYPE_BLACKLIST, "MYSQL");
        p.put("ops", List.of(Map.of("value", "DROP", "matchType", "KEYWORD")));
        assertThrows(IllegalStateException.class, () -> fetch(p));
    }

    @Test
    void databaseOpsRejectOutOfDomain() {
        Map<String, Object> p = base(PolicyStore.TYPE_BLACKLIST, "MYSQL");
        p.put("ops", List.of(Map.of("value", "GRANT", "matchType", "EXACT")));
        assertThrows(IllegalStateException.class, () -> fetch(p));
    }

    /** HOST 类不受 DATABASE 值域约束, 也不要求 tables 字段 (老快照形态) */
    @Test
    void hostPolicyUnchanged() throws Exception {
        Map<String, Object> p = base(PolicyStore.TYPE_WHITELIST, "SSH");
        p.put("ops", List.of(Map.of("value", "rm", "matchType", "EXACT")));
        PolicyStore.Policy got = fetch(p).policies().get(0);
        assertFalse(got.database());
        assertEquals(List.of(), got.tables());
    }
}
