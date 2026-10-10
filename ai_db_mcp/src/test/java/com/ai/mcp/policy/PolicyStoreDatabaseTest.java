package com.ai.mcp.policy;

import com.ai.mcp.config.ConsoleClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PolicyStore 接收 DATABASE 类策略 (字段口径以 SOAG AgentGatewayPolicySnapshotVO / getPolicySnapshot 为准):
 * DATA_SCOPE 的 tables:[{tableName, matchType, ops}]、DATABASE 操作项只许 EXACT 十项
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

    private static Map<String, Object> table(String name, String matchType, Object ops) {
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("tableName", name);
        t.put("matchType", matchType);
        if (ops != null) {
            t.put("ops", ops);
        }
        return t;
    }

    @Test
    void dataScopeTablesParsed() throws Exception {
        PolicyStore.Policy p = fetch(dataScope(List.of(
                table("order_", "PREFIX", List.of("SELECT")),
                table("sales.订单", "EXACT", List.of("SELECT", "DELETE")),
                table("_log", "SUFFIX", List.of("INSERT"))))).policies().get(0);
        assertTrue(p.database());
        assertFalse(p.rulesInvalid());
        assertEquals(List.of(new PolicyStore.Table("order_", "PREFIX", Set.of("SELECT")),
                new PolicyStore.Table("sales.订单", "EXACT", Set.of("SELECT", "DELETE")),
                new PolicyStore.Table("_log", "SUFFIX", Set.of("INSERT"))), p.tables());
    }

    /** 小写 ops (同操作项 F10 口径) 大写化后接收 */
    @Test
    void dataScopeLowercaseOpsNormalized() throws Exception {
        PolicyStore.Policy p = fetch(dataScope(List.of(table("t", "EXACT", List.of("select", "Show"))))).policies().get(0);
        assertFalse(p.rulesInvalid());
        assertEquals(Set.of("SELECT", "SHOW"), p.tables().get(0).ops());
    }

    /** ops 缺失/空数组/不是数组/非文本/值域外: 只降级该策略为规则无效, 不让整次拉取失败 */
    @Test
    void dataScopeBadOpsDowngradesToRulesInvalid() throws Exception {
        List<Object> bads = new ArrayList<>();
        bads.add(null);
        bads.add(List.of());
        bads.add("SELECT");
        bads.add(List.of(1));
        bads.add(List.of("SELECT", "GRANT"));
        for (Object ops : bads) {
            PolicyStore.Policy p = fetch(dataScope(List.of(
                    table("ok", "EXACT", List.of("SELECT")), table("t", "EXACT", ops)))).policies().get(0);
            assertTrue(p.rulesInvalid(), "ops=" + ops);
            assertEquals(List.of(), p.tables());
        }
    }

    /** ops 坏行只影响所在策略: 同快照里的其它策略照常有效 */
    @Test
    void dataScopeBadOpsDoesNotAffectOtherPolicies() throws Exception {
        Map<String, Object> bad = dataScope(List.of(table("t", "EXACT", null)));
        Map<String, Object> good = dataScope(List.of(table("t", "EXACT", List.of("SELECT"))));
        good.put("id", 2L);
        FakeConsoleClient console = new FakeConsoleClient();
        console.data = Map.of("version", "v1", "policies", List.of(bad, good));
        List<PolicyStore.Policy> got = new PolicyStore(console, new ObjectMapper()).fetch("v1").policies();
        assertTrue(got.get(0).rulesInvalid());
        assertFalse(got.get(1).rulesInvalid());
        assertEquals(Set.of("SELECT"), got.get(1).tables().get(0).ops());
    }

    @Test
    void dataScopeTablesMissingFailsWhenValid() {
        assertThrows(IllegalStateException.class, () -> fetch(base(PolicyStore.TYPE_DATA_SCOPE, "MYSQL")));
    }

    @Test
    void dataScopeBadMatchTypeFails() {
        assertThrows(IllegalStateException.class,
                () -> fetch(dataScope(List.of(table("t", "REGEX", List.of("SELECT"))))));
    }

    @Test
    void dataScopeBadTableNameFails() {
        assertThrows(IllegalStateException.class,
                () -> fetch(dataScope(List.of(table("t;drop", "EXACT", List.of("SELECT"))))));
    }

    /** 坏表名仍整次失败, 不因同策略另一项 ops 坏 (降级) 而被放过 —— 与项的先后顺序无关 */
    @Test
    void dataScopeBadTableNameFailsEvenWithBadOps() {
        assertThrows(IllegalStateException.class,
                () -> fetch(dataScope(List.of(table("t", "EXACT", null), table("t;drop", "EXACT", List.of("SELECT"))))));
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
        assertEquals("ALLOW", got.effect());
    }

    // ---------------- 数据范围允许/禁止动作 (设计文档 2026-10-10 §3.3 / §4 U6 U8) ----------------

    /** U6 effect 缺失 (旧控制台) → ALLOW; 显式 ALLOW / DENY 原样接收 */
    @Test
    void effectMissingDefaultsToAllow() throws Exception {
        Map<String, Object> p = dataScope(List.of(table("t1", "EXACT", List.of("DELETE"))));
        PolicyStore.Policy got = fetch(p).policies().get(0);
        assertFalse(got.rulesInvalid());
        assertEquals("ALLOW", got.effect());
        for (String e : List.of("ALLOW", "DENY")) {
            p.put("effect", e);
            got = fetch(p).policies().get(0);
            assertFalse(got.rulesInvalid(), "effect=" + e);
            assertEquals(e, got.effect());
        }
    }

    /**
     * U6/U8 effect 显式 null / 空串 / 大小写不符 / 未知值 / 数字 / 布尔 / 对象 → 该策略 rulesInvalid,
     * 不整次拉取失败, 同快照其它策略照常有效
     */
    @Test
    void effectInvalidDowngradesOnlyThatPolicy() throws Exception {
        List<Object> bads = new ArrayList<>();
        bads.add(null);
        bads.add("");
        bads.add("deny");
        bads.add("X");
        bads.add(5);
        bads.add(true);
        bads.add(Map.of("v", "DENY"));
        for (Object e : bads) {
            Map<String, Object> bad = dataScope(List.of(table("t1", "EXACT", List.of("DELETE"))));
            bad.put("effect", e);
            Map<String, Object> good = dataScope(List.of(table("t1", "EXACT", List.of("SELECT"))));
            good.put("id", 2L);
            good.put("effect", "DENY");
            FakeConsoleClient console = new FakeConsoleClient();
            console.data = Map.of("version", "v1", "policies", List.of(bad, good));
            List<PolicyStore.Policy> got = new PolicyStore(console, new ObjectMapper()).fetch("v1").policies();
            assertTrue(got.get(0).rulesInvalid(), "effect=" + e);
            assertFalse(got.get(1).rulesInvalid(), "effect=" + e);
            assertEquals("DENY", got.get(1).effect());
        }
    }

    /** U8 DENY + tables=[] / 表名有空段 / 超过两段 (修复轮 1 P1-1) → rulesInvalid (DENY 下「永不命中」等于放行); ALLOW 同形态不收紧 */
    @Test
    void denyEffectEmptyOrBadSegmentTablesInvalid() throws Exception {
        Map<String, Object> empty = dataScope(List.of());
        empty.put("effect", "DENY");
        assertTrue(fetch(empty).policies().get(0).rulesInvalid());
        for (String name : List.of("sales.", ".x", "a..b", "a.b.c", "mydb.public.users")) {
            Map<String, Object> p = dataScope(List.of(table("t1", "EXACT", List.of("DELETE")),
                    table(name, "PREFIX", List.of("DELETE"))));
            p.put("effect", "DENY");
            assertTrue(fetch(p).policies().get(0).rulesInvalid(), "tableName=" + name);
            p.put("effect", "ALLOW");
            assertFalse(fetch(p).policies().get(0).rulesInvalid(), "ALLOW 不收紧: tableName=" + name);
        }
        Map<String, Object> ok = dataScope(List.of(table("sales.t1", "EXACT", List.of("DELETE"))));
        ok.put("effect", "DENY");
        assertFalse(fetch(ok).policies().get(0).rulesInvalid());
    }

    /** 非 DATA_SCOPE 不读 effect: 即使带了非法值也不影响 (黑白名单行为不变) */
    @Test
    void effectIgnoredForNonDataScope() throws Exception {
        Map<String, Object> p = base(PolicyStore.TYPE_BLACKLIST, "MYSQL");
        p.put("ops", List.of(Map.of("value", "DROP", "matchType", "EXACT")));
        p.put("effect", "X");
        PolicyStore.Policy got = fetch(p).policies().get(0);
        assertFalse(got.rulesInvalid());
        assertEquals("ALLOW", got.effect());
    }
}
