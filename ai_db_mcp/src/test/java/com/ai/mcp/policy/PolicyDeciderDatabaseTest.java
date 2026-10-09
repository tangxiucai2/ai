package com.ai.mcp.policy;

import com.ai.mcp.config.ConsoleClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DATABASE 类裁决单测 (设计文档 2026-09-29-智能体数据库运维对接DBC-设计.md §3.5 真值表 / §3.6 表名规则 / §5 P1–P11)
 * <p>
 * 用例名前缀 T* 对应真值表行, P* 对应验收断言; 输入 (op / tables / defaultNamespace) 模拟 DBC 解析结果
 */
class PolicyDeciderDatabaseTest {

    private static class FakeConsoleClient extends ConsoleClient {
        Map<String, Object> data;
        PolicyHeartbeat captured;

        @Override
        public Map<String, Object> policySnapshot() {
            return data;
        }

        @Override
        public void policyHeartbeat(PolicyHeartbeat h) {
            this.captured = h;
        }
    }

    private static final long AGENT = 7;
    private static final long HOST = 1;

    private static PolicyDecider decider(Object... policies) {
        FakeConsoleClient console = new FakeConsoleClient();
        console.data = Map.of("version", "v1", "policies", List.of(policies));
        PolicyStore store = new PolicyStore(console, new ObjectMapper());
        store.register();
        console.captured.onReport("v1");
        assertFalse(store.unavailable(), "快照应已加载成功");
        return new PolicyDecider(store);
    }

    private static Map<String, Object> base(long id, String type, String hostType, String mode) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", id);
        p.put("name", "p-" + id);
        p.put("type", type);
        p.put("hostType", hostType);
        p.put("hostIds", List.of(0));
        p.put("agentIds", List.of(0));
        p.put("approvalMode", mode);
        p.put("rulesInvalid", false);
        p.put("ops", List.of());
        return p;
    }

    private static Map<String, Object> list(long id, String type, String mode, String... ops) {
        Map<String, Object> p = base(id, type, "MYSQL", mode);
        List<Object> items = new ArrayList<>();
        for (String op : ops) {
            items.add(Map.of("value", op, "matchType", "EXACT"));
        }
        p.put("ops", items);
        return p;
    }

    private static Map<String, Object> wl(long id, String mode, String... ops) {
        return list(id, PolicyStore.TYPE_WHITELIST, mode, ops);
    }

    private static Map<String, Object> bl(long id, String mode, String... ops) {
        return list(id, PolicyStore.TYPE_BLACKLIST, mode, ops);
    }

    /** 十项操作全给: 只测表名维度的用例用它, 等价于改造前「只管表不管操作」 */
    private static final List<String> ALL_OPS =
            List.of("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "CREATE", "SHOW", "DESCRIBE");

    /**
     * DATA_SCOPE: 规则按 "表名:匹配方式:操作1|操作2" 传, 匹配方式缺省 EXACT, 操作缺省十项全给
     */
    private static Map<String, Object> scope(long id, String hostType, String... rules) {
        Map<String, Object> p = base(id, PolicyStore.TYPE_DATA_SCOPE, hostType, "NONE");
        List<Object> tables = new ArrayList<>();
        for (String r : rules) {
            String[] kv = r.split(":");
            tables.add(Map.of("tableName", kv[0], "matchType", kv.length > 1 ? kv[1] : "EXACT",
                    "ops", kv.length > 2 ? List.of(kv[2].split("\\|")) : ALL_OPS));
        }
        p.put("tables", tables);
        return p;
    }

    private static Map<String, Object> rate(long id, String hostType, long limit) {
        Map<String, Object> p = base(id, PolicyStore.TYPE_RATE_LIMIT, hostType, "NONE");
        p.put("limit", limit);
        p.put("windowSeconds", 60);
        return p;
    }

    private static PolicyDecider.Decision db(PolicyDecider d, String op, String... tables) {
        return d.decideDatabase(AGENT, "MYSQL", HOST, op, List.of(tables), "appdb");
    }

    private static PolicyDecider.Kind kind(PolicyDecider d, String op, String... tables) {
        return db(d, op, tables).kind();
    }

    // ---------------- 真值表 ----------------

    /** T1 最先判定的无条件拒绝 (HOST 已删除禁用清单, 对应的是规则无效): 白名单命中也救不回来 */
    @Test
    void t1RulesInvalidDeniesFirst() {
        Map<String, Object> bad = base(2, PolicyStore.TYPE_BLACKLIST, "MYSQL", "NONE");
        bad.put("rulesInvalid", true);
        PolicyDecider d = decider(wl(1, "NONE", "SELECT"), bad);
        PolicyDecider.Decision r = db(d, "SELECT", "appdb.t");
        assertEquals(PolicyDecider.Kind.DENY, r.kind());
        assertEquals("命中策略规则无效, 已按拒绝处理", r.reason());
    }

    /** T1b 无效的 DATA_SCOPE (tables=[] + rulesInvalid) 同样按拒绝, 连 SHOW 例外都不给 */
    @Test
    void t1InvalidDataScopeDeniesEvenShow() {
        Map<String, Object> bad = base(2, PolicyStore.TYPE_DATA_SCOPE, "MYSQL", "NONE");
        bad.put("rulesInvalid", true);
        bad.put("tables", List.of());
        PolicyDecider d = decider(bad);
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "SHOW"));
    }

    /** T2 限流超限 → DENY; 记账只给 DATABASE 类限流器 */
    @Test
    void t2RateLimitExceeded() {
        PolicyDecider d = decider(rate(1, "MYSQL", 1));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "SELECT", "appdb.t"));
        d.recordDatabaseRate(AGENT, "MYSQL", HOST);
        PolicyDecider.Decision r = db(d, "SELECT", "appdb.t");
        assertEquals(PolicyDecider.Kind.DENY, r.kind());
        assertEquals("超出频率限制, 已拒绝执行", r.reason());
    }

    /** T2b HOST 记账不占 DATABASE 限流配额, 反之亦然 */
    @Test
    void t2RateIsolatedByCategory() {
        PolicyDecider d = decider(rate(1, "MYSQL", 1), rate(2, "SSH", 1));
        d.recordRate(AGENT, "SSH", HOST);
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "SELECT", "appdb.t"), "SSH 记账不该占 DB 配额");
        assertEquals(PolicyDecider.Kind.DENY, d.decide(AGENT, "SSH", HOST, "ls").kind());

        PolicyDecider d2 = decider(rate(1, "MYSQL", 1), rate(2, "SSH", 1));
        d2.recordDatabaseRate(AGENT, "MYSQL", HOST);
        assertEquals(PolicyDecider.Kind.ALLOW, d2.decide(AGENT, "SSH", HOST, "ls").kind(), "DB 记账不该占 SSH 配额");
        assertEquals(PolicyDecider.Kind.DENY, kind(d2, "SELECT", "appdb.t"));
    }

    /** T3 无任何黑白名单/数据范围 (含只有限流) → ALLOW */
    @Test
    void t3NoPolicyAllows() {
        assertEquals(PolicyDecider.Kind.ALLOW, kind(decider(), "DROP", "appdb.t"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(decider(rate(1, "MYSQL", 100)), "DROP", "appdb.t"));
    }

    /** T4 黑名单 NONE → 直接拒; 全为 CONFIRM → 可确认; 一条 NONE + 一条 CONFIRM → 仍直接拒 */
    @Test
    void t4BlacklistDenyMode() {
        assertEquals(PolicyDecider.Kind.DENY, kind(decider(bl(1, "NONE", "DROP")), "DROP", "appdb.t"));
        assertEquals(PolicyDecider.Kind.CONFIRM, kind(decider(bl(1, "CONFIRM", "DROP")), "DROP", "appdb.t"));
        assertEquals(PolicyDecider.Kind.DENY,
                kind(decider(bl(1, "NONE", "DROP"), bl(2, "CONFIRM", "DROP")), "DROP", "appdb.t"));
    }

    /** T4b 黑名单命中时白名单只能抬到 APPROVAL/BOTH, 不覆盖无条件拒绝, 也不能把拒救成可确认 */
    @Test
    void t4WhitelistOnlyEscalatesBlacklist() {
        PolicyDecider.Decision up = db(decider(bl(1, "CONFIRM", "DROP"), wl(2, "APPROVAL", "DROP")), "DROP", "appdb.t");
        assertEquals(PolicyDecider.Kind.APPROVAL, up.kind());
        assertNotNull(up.policyRevision());
        assertEquals(PolicyDecider.Kind.BOTH,
                kind(decider(bl(1, "CONFIRM", "DROP"), wl(2, "BOTH", "DROP")), "DROP", "appdb.t"));
        assertEquals(PolicyDecider.Kind.DENY,
                kind(decider(bl(1, "NONE", "DROP"), wl(2, "APPROVAL", "DROP")), "DROP", "appdb.t"));
        assertEquals(PolicyDecider.Kind.DENY,
                kind(decider(bl(1, "NONE", "DROP"), wl(2, "CONFIRM", "DROP")), "DROP", "appdb.t"));
    }

    /** T5 白名单 anyHit (不做交集): 任一白名单含该 op 即命中; 未命中 → DENY「未命中任何白名单」 */
    @Test
    void t5WhitelistAnyHit() {
        PolicyDecider d = decider(wl(1, "NONE", "SELECT"), wl(2, "NONE", "INSERT"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "SELECT", "appdb.t"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "INSERT", "appdb.t"));
        PolicyDecider.Decision miss = db(d, "DELETE", "appdb.t");
        assertEquals(PolicyDecider.Kind.DENY, miss.kind());
        assertTrue(miss.reason().startsWith("未命中任何白名单"));
    }

    /** T5b 白名单多条命中取最严 (strictestMode) */
    @Test
    void t5WhitelistStrictestMode() {
        assertEquals(PolicyDecider.Kind.CONFIRM,
                kind(decider(wl(1, "NONE", "SELECT"), wl(2, "CONFIRM", "SELECT")), "SELECT", "appdb.t"));
        assertEquals(PolicyDecider.Kind.APPROVAL,
                kind(decider(wl(1, "CONFIRM", "SELECT"), wl(2, "APPROVAL", "SELECT")), "SELECT", "appdb.t"));
    }

    /** T5c 策略里的小写 op (存量行) 与大写 op 同样命中 */
    @Test
    void t5OpCaseInsensitive() {
        assertEquals(PolicyDecider.Kind.ALLOW, kind(decider(wl(1, "NONE", "select")), "SELECT", "appdb.t"));
    }

    /** T6 DATA_SCOPE: 每张都命中才过; 有一张不中即 DENY「超出数据范围」, 黑名单 CONFIRM 也不给确认 */
    @Test
    void t6DataScopeAllTablesMustHit() {
        PolicyDecider d = decider(scope(1, "MYSQL", "order_:PREFIX"), wl(2, "NONE", "SELECT"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "SELECT", "appdb.order_a", "appdb.order_b"));
        PolicyDecider.Decision out = db(d, "SELECT", "appdb.order_a", "appdb.user");
        assertEquals(PolicyDecider.Kind.DENY, out.kind());
        assertEquals("超出数据范围, 已拒绝执行", out.reason());

        PolicyDecider withConfirm = decider(scope(1, "MYSQL", "order_:PREFIX"), bl(2, "CONFIRM", "DELETE"));
        assertEquals(PolicyDecider.Kind.DENY, kind(withConfirm, "DELETE", "appdb.user"));
        assertEquals(PolicyDecider.Kind.CONFIRM, kind(withConfirm, "DELETE", "appdb.order_a"));
    }

    /** T6b DATA_SCOPE 与黑白名单是「与」: 范围内但白名单没放 → DENY; 范围内且白名单要审批 → APPROVAL */
    @Test
    void t6DataScopeAndLists() {
        PolicyDecider d = decider(scope(1, "MYSQL", "order_:PREFIX"), wl(2, "NONE", "SELECT"), wl(3, "APPROVAL", "UPDATE"));
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "DELETE", "appdb.order_a"));
        assertEquals(PolicyDecider.Kind.APPROVAL, kind(d, "UPDATE", "appdb.order_a"));
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "UPDATE", "appdb.user"));
    }

    /** T6c 只配 DATA_SCOPE (无黑白名单): 范围内放行, 不落进「未命中任何白名单」 */
    @Test
    void t6DataScopeAlone() {
        PolicyDecider d = decider(scope(1, "MYSQL", "user"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "DELETE", "appdb.user"));
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "DELETE", "appdb.other"));
    }

    /** T6d tables 为空: 只有 SHOW 例外放行 (前提是黑白名单放了 SHOW), 其余一律 DENY */
    @Test
    void t6EmptyTables() {
        PolicyDecider withShow = decider(scope(1, "MYSQL", "user"), wl(2, "NONE", "SHOW", "SELECT"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(withShow, "SHOW"));
        assertEquals(PolicyDecider.Kind.DENY, kind(withShow, "SELECT"));
        PolicyDecider noShow = decider(scope(1, "MYSQL", "user"), wl(2, "NONE", "SELECT"));
        assertEquals(PolicyDecider.Kind.DENY, kind(noShow, "SHOW"), "白名单没放 SHOW 时 SHOW 例外不生效");
        // tables=null 与空列表同口径
        assertEquals(PolicyDecider.Kind.DENY,
                withShow.decideDatabase(AGENT, "MYSQL", HOST, "SELECT", null, "appdb").kind());
    }

    /** T6e 多条 DATA_SCOPE 取并集 (与白名单 anyHit 同口径) */
    @Test
    void t6MultipleScopesUnion() {
        PolicyDecider d = decider(scope(1, "MYSQL", "order_a"), scope(2, "MYSQL", "user"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "SELECT", "appdb.order_a", "appdb.user"));
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "SELECT", "appdb.order_a", "appdb.x"));
    }

    /** T7 topPriority: 同类命中只看最高优先级; 被盖掉的 APPROVAL 白名单不抬档 */
    @Test
    void t7TopPriority() {
        Map<String, Object> high = wl(1, "NONE", "SELECT");
        high.put("priority", 10);
        Map<String, Object> low = wl(2, "APPROVAL", "SELECT");
        low.put("priority", 90);
        assertEquals(PolicyDecider.Kind.ALLOW, kind(decider(high, low), "SELECT", "appdb.t"));
        high.put("priority", 90);
        low.put("priority", 10);
        assertEquals(PolicyDecider.Kind.APPROVAL, kind(decider(high, low), "SELECT", "appdb.t"));
    }

    /** T7b policyRevision: 只摘要命中集, 命中策略内容变了就变, 无关策略变了不变 */
    @Test
    void t7PolicyRevision() {
        String r1 = db(decider(wl(1, "APPROVAL", "UPDATE"), wl(2, "NONE", "SELECT")), "UPDATE", "appdb.t").policyRevision();
        String r2 = db(decider(wl(1, "APPROVAL", "UPDATE"), wl(2, "NONE", "SELECT", "INSERT")), "UPDATE", "appdb.t").policyRevision();
        String r3 = db(decider(wl(1, "APPROVAL", "UPDATE", "DELETE"), wl(2, "NONE", "SELECT")), "UPDATE", "appdb.t").policyRevision();
        assertNotNull(r1);
        assertEquals(r1, r2, "改无关策略不该让在途审批失效");
        assertNotEquals(r1, r3, "改命中策略必须让在途审批失效");
    }

    // ---------------- DATA_SCOPE 档位参与合并 (fix round 1) ----------------

    private static Map<String, Object> scopeMode(long id, String mode, String... rules) {
        Map<String, Object> p = scope(id, "MYSQL", rules);
        p.put("approvalMode", mode);
        return p;
    }

    /** 只配 DATA_SCOPE: 范围内由它的档位决定 */
    @Test
    void scopeOnlyModes() {
        assertEquals(PolicyDecider.Kind.CONFIRM, kind(decider(scopeMode(1, "CONFIRM", "user")), "SELECT", "appdb.user"));
        PolicyDecider.Decision a = db(decider(scopeMode(1, "APPROVAL", "user")), "SELECT", "appdb.user");
        assertEquals(PolicyDecider.Kind.APPROVAL, a.kind());
        assertNotNull(a.policyRevision());
        assertEquals("数据范围限制", a.policyType());
        assertEquals(PolicyDecider.Kind.BOTH, kind(decider(scopeMode(1, "BOTH", "user")), "SELECT", "appdb.user"));
        // 超出范围时档位不给确认/审批机会
        assertEquals(PolicyDecider.Kind.DENY, kind(decider(scopeMode(1, "APPROVAL", "user")), "SELECT", "appdb.x"));
    }

    /** DATA_SCOPE APPROVAL + 白名单 NONE → 取最严 APPROVAL, 标签与类型都带上两条 */
    @Test
    void scopeApprovalWithWhitelistNone() {
        PolicyDecider.Decision r = db(decider(scopeMode(1, "APPROVAL", "user"), wl(2, "NONE", "SELECT")), "SELECT", "appdb.user");
        assertEquals(PolicyDecider.Kind.APPROVAL, r.kind());
        assertTrue(r.policyLabel().contains("p-1") && r.policyLabel().contains("p-2"));
        assertEquals("操作白名单,数据范围限制", r.policyType());
    }

    /** 黑名单拒判基调下 DATA_SCOPE 同白名单: 救不回 NONE, 只能把 CONFIRM 抬到 APPROVAL */
    @Test
    void scopeUnderBlacklist() {
        assertEquals(PolicyDecider.Kind.DENY,
                kind(decider(scopeMode(1, "APPROVAL", "user"), bl(2, "NONE", "DELETE")), "DELETE", "appdb.user"));
        assertEquals(PolicyDecider.Kind.APPROVAL,
                kind(decider(scopeMode(1, "APPROVAL", "user"), bl(2, "CONFIRM", "DELETE")), "DELETE", "appdb.user"));
        // 白名单没放行 op 时, 数据范围不能替代白名单
        assertEquals(PolicyDecider.Kind.DENY,
                kind(decider(scopeMode(1, "NONE", "user"), wl(2, "NONE", "SELECT")), "DELETE", "appdb.user"));
    }

    /** 多条 DATA_SCOPE 按优先级收敛后再参与档位 */
    @Test
    void scopeTopPriority() {
        Map<String, Object> high = scopeMode(1, "NONE", "user");
        high.put("priority", 10);
        Map<String, Object> low = scopeMode(2, "APPROVAL", "user");
        low.put("priority", 90);
        assertEquals(PolicyDecider.Kind.ALLOW, kind(decider(high, low), "SELECT", "appdb.user"));
    }

    /** 高优先级但没命中的 NONE 不能盖掉真正放行这张表的 APPROVAL (fix round 2 反例) */
    @Test
    void nonHittingHighPriorityScopeDoesNotMaskApproval() {
        Map<String, Object> a = scopeMode(1, "NONE", "order_:PREFIX");
        a.put("priority", 10);
        Map<String, Object> b = scopeMode(2, "APPROVAL", "user");
        b.put("priority", 90);
        PolicyDecider.Decision r = db(decider(a, b), "SELECT", "appdb.user");
        assertEquals(PolicyDecider.Kind.APPROVAL, r.kind());
        assertEquals("p-2", r.policyLabel());
    }

    /** 同优先级但没命中的 DATA_SCOPE 不进 matched: 不抬档, 也不改 policyRevision */
    @Test
    void nonHittingSamePriorityScopeIgnored() {
        Map<String, Object> hit = scopeMode(1, "CONFIRM", "user");
        Map<String, Object> other = scopeMode(2, "APPROVAL", "order_:PREFIX");
        assertEquals(PolicyDecider.Kind.CONFIRM, kind(decider(hit, other), "SELECT", "appdb.user"));
        Map<String, Object> hitA = scopeMode(1, "APPROVAL", "user");
        String alone = db(decider(hitA), "SELECT", "appdb.user").policyRevision();
        String withOther = db(decider(hitA, other), "SELECT", "appdb.user").policyRevision();
        assertEquals(alone, withOther);
    }

    /** 两张表分别由不同 DATA_SCOPE 放行 (NONE + APPROVAL) → 两条都参与 → APPROVAL */
    @Test
    void tablesHitByDifferentScopes() {
        PolicyDecider d = decider(scopeMode(1, "NONE", "order_:PREFIX"), scopeMode(2, "APPROVAL", "user"));
        assertEquals(PolicyDecider.Kind.APPROVAL, kind(d, "SELECT", "appdb.order_a", "appdb.user"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "SELECT", "appdb.order_a"));
    }

    /** 无表 SHOW 例外: 没有表可命中, 取 ops 含 SHOW 的那些 DATA_SCOPE 的 topPriority 定档 */
    @Test
    void tablelessShowUsesOnlyScopesGrantingShow() {
        assertEquals(PolicyDecider.Kind.CONFIRM, kind(decider(scopeMode(1, "CONFIRM", "user")), "SHOW"));
    }

    /** 改了 DATA_SCOPE 的表规则 → policyRevision 变 */
    @Test
    void scopeTablesInRevision() {
        String r1 = db(decider(scopeMode(1, "APPROVAL", "user", "order_:PREFIX")), "SELECT", "appdb.user").policyRevision();
        String r2 = db(decider(scopeMode(1, "APPROVAL", "user", "order_:SUFFIX")), "SELECT", "appdb.user").policyRevision();
        String r3 = db(decider(scopeMode(1, "APPROVAL", "user", "order_b:PREFIX")), "SELECT", "appdb.user").policyRevision();
        assertNotEquals(r1, r2);
        assertNotEquals(r1, r3);
    }

    /**
     * HOST 摘要逐字节不变: 期望值用改造前 (HEAD) 的 PolicyDecider.policyRevision 对同一条策略算出,
     * 等于 sha256("1|WHITELIST|APPROVAL|false|50|1|||EXACT:2:ls;\n")
     */
    @Test
    void hostRevisionGolden() {
        Map<String, Object> h = base(1, PolicyStore.TYPE_WHITELIST, "SSH", "APPROVAL");
        h.put("ops", List.of(Map.of("value", "ls", "matchType", "EXACT")));
        assertEquals("c754a076db1422c053be713c297de3f5c12f3d6bd86ddb9fbfb82d157ac213bd",
                decider(h).decide(AGENT, "SSH", HOST, "ls").policyRevision());
    }

    // ---------------- 类别隔离 ----------------

    /** HOST 裁决忽略 DATABASE 类 (含同 id 资源上的 DATA_SCOPE / 白名单), 行为与改造前快照一致 */
    @Test
    void hostDecisionIgnoresDatabasePolicies() {
        Map<String, Object> s = scope(1, "MYSQL", "user");
        s.put("hostIds", List.of(HOST));
        Map<String, Object> w = wl(2, "NONE", "SELECT");
        w.put("hostIds", List.of(HOST));
        PolicyDecider d = decider(s, w);
        assertEquals(PolicyDecider.Kind.ALLOW, d.decide(AGENT, "SSH", HOST, "rm").kind());
    }

    /** DATABASE 裁决忽略 HOST 类 (即使 hostIds 与数据库资源 id 相同) */
    @Test
    void databaseDecisionIgnoresHostPolicies() {
        Map<String, Object> h = base(1, PolicyStore.TYPE_WHITELIST, "SSH", "NONE");
        h.put("hostIds", List.of(HOST));
        h.put("ops", List.of(Map.of("value", "ls", "matchType", "EXACT")));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(decider(h), "DROP", "appdb.t"));
    }

    /** 全局策略按 hostType 定范围: 绑 POSTGRESQL 全部资源的策略不管 MYSQL 资源 */
    @Test
    void globalScopeMatchesDbType() {
        Map<String, Object> pg = wl(1, "NONE", "SELECT");
        pg.put("hostType", "POSTGRESQL");
        assertEquals(PolicyDecider.Kind.ALLOW, kind(decider(pg), "DROP", "appdb.t"));
        assertEquals(PolicyDecider.Kind.DENY,
                decider(pg).decideDatabase(AGENT, "POSTGRESQL", HOST, "DROP", List.of("public.t"), "public").kind());
    }

    // ---------------- §3.6 表名规则 ----------------

    /** PREFIX/SUFFIX 只作用于表名部分, 命名空间精确比较: 库名碰巧同前缀不算 */
    @Test
    void prefixSuffixOnlyOnTablePart() {
        PolicyDecider d = decider(scope(1, "MYSQL", "order_:PREFIX", "_log:SUFFIX"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "SELECT", "appdb.order_x", "appdb.op_log"));
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "SELECT", "order_db.secret"));
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "SELECT", "other.order_x"), "裸名 PREFIX 的库名视为默认库");
    }

    /** 策略写 库.表: 按完整名匹配, PREFIX 作用于表名部分 */
    @Test
    void qualifiedRule() {
        PolicyDecider d = decider(scope(1, "MYSQL", "sales.order_:PREFIX", "hr.emp"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "SELECT", "sales.order_1", "hr.emp"));
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "SELECT", "appdb.order_1"));
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "SELECT", "hr.emp2"));
    }

    /** 默认命名空间缺失时裸名规则补不出来 → 不命中 (fail-close); 限定名规则不受影响 */
    @Test
    void missingDefaultNamespace() {
        PolicyDecider d = decider(scope(1, "MYSQL", "user", "hr.emp"));
        assertEquals(PolicyDecider.Kind.DENY,
                d.decideDatabase(AGENT, "MYSQL", HOST, "SELECT", List.of("appdb.user"), null).kind());
        assertEquals(PolicyDecider.Kind.ALLOW,
                d.decideDatabase(AGENT, "MYSQL", HOST, "SELECT", List.of("hr.emp"), null).kind());
    }

    /** 空段的规则永不命中: sales. + PREFIX 不能放开整个 sales, .x / a..b 同理 */
    @Test
    void emptySegmentNeverMatches() {
        PolicyDecider d = decider(scope(1, "MYSQL", "sales.:PREFIX"));
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "SELECT", "sales.order_1"));
        assertEquals(PolicyDecider.Kind.DENY, kind(decider(scope(1, "MYSQL", ".x:EXACT")), "SELECT", "appdb.x"));
        assertEquals(PolicyDecider.Kind.DENY, kind(decider(scope(1, "MYSQL", "a..b:EXACT")), "SELECT", "a..b"));
        assertEquals(PolicyDecider.Kind.DENY, kind(decider(scope(1, "MYSQL", "a..b:SUFFIX")), "SELECT", "a.x.b"));
    }

    /** DBC 万一给出不带命名空间的裸表名: 补默认命名空间后再比 */
    @Test
    void bareParsedTableGetsDefaultNamespace() {
        assertEquals(PolicyDecider.Kind.ALLOW, kind(decider(scope(1, "MYSQL", "user")), "SELECT", "user"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(decider(scope(1, "MYSQL", "appdb.user")), "SELECT", "user"));
        assertEquals(PolicyDecider.Kind.DENY, kind(decider(scope(1, "MYSQL", "other.user")), "SELECT", "user"));
    }

    // ---------------- §5 验收 P1–P11 (单测能表达的部分) ----------------

    @Test
    void p1WhitelistSelectOnlyDeniesDelete() {
        assertEquals(PolicyDecider.Kind.DENY, kind(decider(wl(1, "NONE", "SELECT")), "DELETE", "appdb.t"));
    }

    @Test
    void p2BlacklistDrop() {
        assertEquals(PolicyDecider.Kind.DENY, kind(decider(bl(1, "NONE", "DROP")), "DROP", "appdb.t"));
        assertEquals(PolicyDecider.Kind.CONFIRM, kind(decider(bl(1, "CONFIRM", "DROP")), "DROP", "appdb.t"));
    }

    @Test
    void p3DataScopePrefixJoinUser() {
        assertEquals(PolicyDecider.Kind.DENY,
                kind(decider(scope(1, "MYSQL", "order_:PREFIX")), "SELECT", "appdb.order_a", "appdb.user"));
    }

    @Test
    void p4ApprovalModeUpdate() {
        PolicyDecider.Decision r = db(decider(wl(1, "APPROVAL", "UPDATE")), "UPDATE", "appdb.t");
        assertEquals(PolicyDecider.Kind.APPROVAL, r.kind());
        assertNotNull(r.policyRevision());
        assertEquals("操作白名单", r.policyType());
    }

    @Test
    void p5NoDbPolicyAllowsSelect() {
        assertEquals(PolicyDecider.Kind.ALLOW, kind(decider(), "SELECT", "appdb.t"));
    }

    @Test
    void p7DataScopeSelectOneDenied() {
        assertEquals(PolicyDecider.Kind.DENY, kind(decider(scope(1, "MYSQL", "user")), "SELECT"));
    }

    /**
     * 四种库的大小写与默认命名空间: {dbType, 默认命名空间 (DBC 已规范化), 另一个命名空间, 策略裸名写法, 表 user 在该库的规范化名}
     * <p>
     * 策略值故意写成与库口径相反的大小写 (Oracle/DM 写小写、PG 写大写), 验证策略侧同样做了规范化;
     * MySQL 原样, 所以策略写 user 就只认 user
     */
    static Stream<Arguments> dbs() {
        return Stream.of(
                Arguments.of("MYSQL", "appdb", "otherdb", "user", "user", "order_", "order_a", "order_b"),
                Arguments.of("POSTGRESQL", "public", "sales", "USER", "user", "ORDER_", "order_a", "order_b"),
                Arguments.of("ORACLE", "HR", "SCOTT", "user", "USER", "order_", "ORDER_A", "ORDER_B"),
                Arguments.of("DAMENG", "SYSDBA", "OTHER", "user", "USER", "order_", "ORDER_A", "ORDER_B"));
    }

    /** P9 DATA_SCOPE 只配裸名 user: FROM user / 默认命名空间.user 允许, 另一命名空间.user 拒绝 */
    @ParameterizedTest
    @MethodSource("dbs")
    void p9BareNameMeansDefaultNamespace(String dbType, String ns, String other, String rule, String user,
                                        String prefix, String orderA, String orderB) {
        PolicyDecider d = decider(scope(1, dbType, rule));
        // SELECT * FROM user 与 SELECT * FROM <默认>.user 经 DBC 规范化后都是 <默认>.user
        assertEquals(PolicyDecider.Kind.ALLOW, d.decideDatabase(AGENT, dbType, HOST, "SELECT", List.of(ns + "." + user), ns).kind());
        assertEquals(PolicyDecider.Kind.DENY, d.decideDatabase(AGENT, dbType, HOST, "SELECT", List.of(other + "." + user), ns).kind());
    }

    /** P10 DATA_SCOPE 只允许 order_*: INSERT…SELECT user / UPDATE…FROM user 拒绝; CTE 不算表 → 允许 */
    @ParameterizedTest
    @MethodSource("dbs")
    void p10NestedTables(String dbType, String ns, String other, String rule, String user,
                         String prefix, String orderA, String orderB) {
        PolicyDecider d = decider(scope(1, dbType, prefix + ":PREFIX"));
        assertEquals(PolicyDecider.Kind.DENY,
                d.decideDatabase(AGENT, dbType, HOST, "INSERT", List.of(ns + "." + orderA, ns + "." + user), ns).kind());
        assertEquals(PolicyDecider.Kind.ALLOW,
                d.decideDatabase(AGENT, dbType, HOST, "SELECT", List.of(ns + "." + orderB), ns).kind());
        assertEquals(PolicyDecider.Kind.DENY,
                d.decideDatabase(AGENT, dbType, HOST, "UPDATE", List.of(ns + "." + orderA, ns + "." + user), ns).kind());
    }

    /** P11 DATA_SCOPE + 白名单含 SHOW/DESCRIBE: SHOW TABLES / DESCRIBE order_a 允许; DESCRIBE user / SHOW COLUMNS FROM user 拒绝 */
    @ParameterizedTest
    @MethodSource("dbs")
    void p11ShowDescribe(String dbType, String ns, String other, String rule, String user,
                         String prefix, String orderA, String orderB) {
        Map<String, Object> w = wl(2, "NONE", "SHOW", "DESCRIBE");
        w.put("hostType", dbType);
        PolicyDecider d = decider(scope(1, dbType, prefix + ":PREFIX"), w);
        assertEquals(PolicyDecider.Kind.ALLOW, d.decideDatabase(AGENT, dbType, HOST, "SHOW", List.of(), ns).kind());
        assertEquals(PolicyDecider.Kind.ALLOW,
                d.decideDatabase(AGENT, dbType, HOST, "DESCRIBE", List.of(ns + "." + orderA), ns).kind());
        assertEquals(PolicyDecider.Kind.DENY,
                d.decideDatabase(AGENT, dbType, HOST, "DESCRIBE", List.of(ns + "." + user), ns).kind());
        assertEquals(PolicyDecider.Kind.DENY,
                d.decideDatabase(AGENT, dbType, HOST, "SHOW", List.of(ns + "." + user), ns).kind());
    }

    /** MySQL 表名原样比较: 策略写 User 不匹配 user (与 DBC 口径一致, 不擅自忽略大小写) */
    @Test
    void mysqlCaseSensitive() {
        assertEquals(PolicyDecider.Kind.DENY, kind(decider(scope(1, "MYSQL", "User")), "SELECT", "appdb.user"));
    }

    /** P8 的裁决侧: 审批中管理员改了命中策略 → fresh decide 的 policyRevision 不同 (闸门侧见 PolicyGateDatabaseTest) */
    @Test
    void p8RevisionChangesWhenPolicyEdited() {
        Map<String, Object> w = wl(1, "APPROVAL", "UPDATE");
        String before = db(decider(w), "UPDATE", "appdb.t").policyRevision();
        w.put("priority", 20);
        String after = db(decider(w), "UPDATE", "appdb.t").policyRevision();
        assertNotEquals(before, after);
    }

    // ---------------- 表级操作授权 (设计文档 2026-10-09 §5 A4–A10) ----------------

    /** A4–A7: orders 只读; log_ 前缀可读可删; JOIN 未授权表整体拒绝 */
    @Test
    void a4to7TableLevelOps() {
        PolicyDecider d = decider(scope(1, "MYSQL", "orders:EXACT:SELECT", "users:EXACT:SELECT", "log_:PREFIX:SELECT|DELETE"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "SELECT", "appdb.orders"));
        PolicyDecider.Decision del = db(d, "DELETE", "appdb.orders");
        assertEquals(PolicyDecider.Kind.DENY, del.kind(), "表命中但 op 不在该表授权内");
        assertEquals("超出数据范围, 已拒绝执行", del.reason());
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "DELETE", "appdb.log_2026"));
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "SELECT", "appdb.orders", "appdb.secret"));
        // 一条语句碰多张表: 每张表都要允许该 op (log_ 允许 DELETE, orders 不允许)
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "DELETE", "appdb.log_a", "appdb.orders"));
    }

    /** A9 并集: 同表两条策略分别给 SELECT / DELETE, 两种 op 都放行; 都没给的仍拒 */
    @Test
    void a9OpsUnionAcrossPolicies() {
        PolicyDecider d = decider(scope(1, "MYSQL", "orders:EXACT:SELECT"), scope(2, "MYSQL", "orders:EXACT:DELETE"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "SELECT", "appdb.orders"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "DELETE", "appdb.orders"));
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "UPDATE", "appdb.orders"));
    }

    /** A9 加法授权: 高优先级只给 SELECT 也收紧不了低优先级给的 DELETE; 档位只由允许该 op 的命中集决定 */
    @Test
    void a9PriorityDoesNotNarrowOps() {
        Map<String, Object> high = scopeMode(1, "NONE", "orders:EXACT:SELECT");
        high.put("priority", 10);
        Map<String, Object> low = scopeMode(2, "APPROVAL", "orders:EXACT:DELETE");
        low.put("priority", 90);
        PolicyDecider d = decider(high, low);
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "SELECT", "appdb.orders"));
        PolicyDecider.Decision r = db(d, "DELETE", "appdb.orders");
        assertEquals(PolicyDecider.Kind.APPROVAL, r.kind());
        assertEquals("p-2", r.policyLabel());
    }

    /** A9 同一策略内同表两条规则 (EXACT + PREFIX) 也取并集 */
    @Test
    void a9OpsUnionWithinPolicy() {
        PolicyDecider d = decider(scope(1, "MYSQL", "orders:EXACT:SELECT", "ord:PREFIX:UPDATE"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "SELECT", "appdb.orders"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "UPDATE", "appdb.orders"));
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "DELETE", "appdb.orders"));
    }

    /** A9 小写 ops (存量/人工导入) 可解析且与大写同样命中; 裁决侧 op 大小写也不敏感 */
    @Test
    void a9LowercaseOps() {
        PolicyDecider d = decider(scope(1, "MYSQL", "orders:EXACT:select|delete"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "SELECT", "appdb.orders"));
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "delete", "appdb.orders"));
        assertEquals(PolicyDecider.Kind.DENY, kind(d, "UPDATE", "appdb.orders"));
    }

    /** A9 ops 缺失: 只有该策略降级为规则无效 (它适用的智能体被拒), 其它策略照常裁决, 快照照常加载 */
    @Test
    void a9MissingOpsOnlyInvalidatesThatPolicy() {
        Map<String, Object> bad = base(2, PolicyStore.TYPE_DATA_SCOPE, "MYSQL", "NONE");
        bad.put("agentIds", List.of(99));
        bad.put("tables", List.of(Map.of("tableName", "orders", "matchType", "EXACT")));
        PolicyDecider d = decider(scope(1, "MYSQL", "orders:EXACT:SELECT"), bad);
        assertEquals(PolicyDecider.Kind.ALLOW, kind(d, "SELECT", "appdb.orders"));
        PolicyDecider.Decision r = d.decideDatabase(99, "MYSQL", HOST, "SELECT", List.of("appdb.orders"), "appdb");
        assertEquals(PolicyDecider.Kind.DENY, r.kind());
        assertEquals("命中策略规则无效, 已按拒绝处理", r.reason());
    }

    /** A9 policyRevision 随 ops 变化; ops 下发顺序不同不影响 */
    @Test
    void a9RevisionTracksOps() {
        String r1 = db(decider(scopeMode(1, "APPROVAL", "orders:EXACT:SELECT|DELETE")), "SELECT", "appdb.orders").policyRevision();
        String r2 = db(decider(scopeMode(1, "APPROVAL", "orders:EXACT:SELECT")), "SELECT", "appdb.orders").policyRevision();
        String r3 = db(decider(scopeMode(1, "APPROVAL", "orders:EXACT:DELETE|SELECT")), "SELECT", "appdb.orders").policyRevision();
        assertNotNull(r1);
        assertNotEquals(r1, r2, "改 ops 必须让在途审批失效");
        assertEquals(r1, r3, "ops 顺序不同不该让在途审批失效");
    }

    /** A10 无表 SHOW: 仅授 SELECT 时拒; 任一表规则勾 SHOW 后放行 (粒度是全部无表 SHOW) */
    @Test
    void a10TablelessShowNeedsShowOp() {
        PolicyDecider.Decision r = db(decider(scope(1, "MYSQL", "orders:EXACT:SELECT")), "SHOW");
        assertEquals(PolicyDecider.Kind.DENY, r.kind());
        assertEquals("超出数据范围, 已拒绝执行", r.reason());
        assertEquals(PolicyDecider.Kind.ALLOW,
                kind(decider(scope(1, "MYSQL", "orders:EXACT:SELECT", "log_:PREFIX:SHOW")), "SHOW"));
        assertEquals(PolicyDecider.Kind.ALLOW,
                kind(decider(scope(1, "MYSQL", "orders:EXACT:SELECT"), scope(2, "MYSQL", "x:EXACT:show")), "SHOW"));
    }

    /** A10 无表 SHOW 的返回集只取勾了 SHOW 的策略: 没勾 SHOW 的 APPROVAL 不参与抬档 */
    @Test
    void a10TablelessShowOnlyShowScopesSettle() {
        PolicyDecider d = decider(scopeMode(1, "APPROVAL", "orders:EXACT:SELECT"), scopeMode(2, "CONFIRM", "orders:EXACT:SHOW"));
        PolicyDecider.Decision r = db(d, "SHOW");
        assertEquals(PolicyDecider.Kind.CONFIRM, r.kind());
        assertEquals("p-2", r.policyLabel());
    }
}
