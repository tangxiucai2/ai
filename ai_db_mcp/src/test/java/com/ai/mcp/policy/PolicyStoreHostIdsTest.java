package com.ai.mcp.policy;

import com.ai.mcp.config.ConsoleClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PolicyStore 作用域集合解析单测: hostIds (设计文档 2026-09-18-访问控制策略目标资源多选-设计.md §5.2/§7.2 G2/G5/G10)
 * 与 agentIds / rulesInvalid / 版本代际 (设计文档 2026-09-19-访问控制策略-适用智能体多选.md §5/§7).
 * <p>
 * 所有畸形形态都必须让**整次拉取**失败: 跳过坏条目等于弱化黑名单, 折成 0 等于放大成「全部资源」,
 * 而 PolicyDecider 对"没有策略适用"是放行的 —— 任何静默降级都会让资源直接失去防护
 */
class PolicyStoreHostIdsTest {

    private static PolicyStore newStore(Map<String, Object> snapshotData) {
        ConsoleClient console = new ConsoleClient() {
            @Override
            public Map<String, Object> policySnapshot() {
                return snapshotData;
            }
        };
        return new PolicyStore(console, new ObjectMapper());
    }

    private static Map<String, Object> basePolicy() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", 1L);
        p.put("name", "测试策略");
        p.put("type", PolicyStore.TYPE_WHITELIST);
        p.put("hostType", "SSH");
        p.put("hostIds", List.of(12, 15));
        p.put("agentIds", List.of(0));
        p.put("approvalMode", "NONE");
        p.put("rulesInvalid", false);
        p.put("ops", List.of(Map.of("value", "ls", "matchType", "EXACT")));
        return p;
    }

    private static Map<String, Object> snapshot(Map<String, Object> policy) {
        return Map.of("version", "v1", "policies", List.of(policy));
    }

    /** 把 hostIds 换成畸形值 (null 代表整个字段缺失) 后断言整次拉取失败 */
    private static void assertHostIdsRejected(Object hostIds) {
        Map<String, Object> p = basePolicy();
        if (hostIds == null) {
            p.remove("hostIds");
        } else {
            p.put("hostIds", hostIds);
        }
        PolicyStore store = newStore(snapshot(p));
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> store.fetch("v1"),
                () -> "hostIds=" + hostIds + " 应当让整次拉取失败");
        // 断言到具体信息: 否则被别的字段校验抢先抛出也会让用例"通过", 测不到 hostIds 这条路径
        assertTrue(e.getMessage().startsWith("策略快照条目的 hostIds 非法"), e.getMessage());
    }

    @Test
    void validHostIdsParse() throws Exception {
        PolicyStore.Snapshot snap = newStore(snapshot(basePolicy())).fetch("v1");
        assertEquals(List.of(12L, 15L), snap.policies().get(0).hostIds());
    }

    @Test
    void sentinelZeroAloneParses() throws Exception {
        Map<String, Object> p = basePolicy();
        p.put("hostIds", List.of(0));
        PolicyStore.Snapshot snap = newStore(snapshot(p)).fetch("v1");
        assertEquals(List.of(0L), snap.policies().get(0).hostIds());
    }

    @Test
    void missingHostIdsRejected() {
        assertHostIdsRejected(null);
    }

    @Test
    void nonArrayHostIdsRejected() {
        assertHostIdsRejected(12);
    }

    @Test
    void emptyHostIdsRejected() {
        assertHostIdsRejected(List.of());
    }

    @Test
    void textElementRejected() {
        assertHostIdsRejected(List.of("x"));
    }

    @Test
    void negativeElementRejected() {
        assertHostIdsRejected(List.of(-1));
    }

    // 12.9 绝不能被 asLong() 截成 12 —— 那会让策略悄悄改管另一台真实主机 (设计文档 R4)
    @Test
    void fractionalElementRejected() {
        assertHostIdsRejected(List.of(12.9d));
    }

    // 1e3 是 JSON 浮点字面量, 同样不是整数
    @Test
    void scientificNotationElementRejected() {
        assertHostIdsRejected(List.of(1e3));
    }

    // 超 long 的整数: isIntegralNumber() 为真但 asLong() 会溢出成另一个 id
    @Test
    void overflowElementRejected() {
        assertHostIdsRejected(List.of(new BigInteger("9223372036854775808")));
    }

    @Test
    void nullElementRejected() {
        assertHostIdsRejected(Arrays.asList((Object) null));
    }

    @Test
    void booleanElementRejected() {
        assertHostIdsRejected(List.of(true));
    }

    // [0, 12] 语义不明: 按哨兵解读就是把范围放大到全部资源
    @Test
    void sentinelMixedWithConcreteIdRejected() {
        assertHostIdsRejected(List.of(0, 12));
    }

    // 心跳报 B 但响应是 C: 快照必须贴 C, 否则 synced() 会永远认为"版本没变"而不再拉取 (既有 bug 回归)
    @Test
    void snapshotLabelledWithResponseVersion() throws Exception {
        Map<String, Object> data = Map.of("version", "C", "policies", List.of(basePolicy()));
        assertEquals("C", newStore(data).fetch("B").version());
    }

    @Test
    void missingResponseVersionRejected() {
        PolicyStore store = newStore(Map.of("policies", List.of(basePolicy())));
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> store.fetch("B"));
        assertEquals("策略快照响应缺少 version", e.getMessage());
    }

    // ---- 适用智能体集合 (agentIds): 与 hostIds 共用 parseIds, 这里只钉住第二个调用点与去重/上限 ----

    /** 把 agentIds 换成畸形值 (null 代表整个字段缺失) 后断言整次拉取失败 */
    private static void assertAgentIdsRejected(Object agentIds) {
        Map<String, Object> p = basePolicy();
        if (agentIds == null) {
            p.remove("agentIds");
        } else {
            p.put("agentIds", agentIds);
        }
        PolicyStore store = newStore(snapshot(p));
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> store.fetch("v1"),
                () -> "agentIds 应当让整次拉取失败");
        // 断言到具体信息: 否则被 hostIds 或别的字段校验抢先抛出也会让用例"通过"
        assertTrue(e.getMessage().startsWith("策略快照条目的 agentIds 非法"), e.getMessage());
    }

    private static List<Integer> ids(int from, int count) {
        return IntStream.range(0, count).map(i -> from + i).boxed().toList();
    }

    @Test
    void validAgentIdsParse() throws Exception {
        Map<String, Object> p = basePolicy();
        p.put("agentIds", List.of(12, 15));
        PolicyStore.Snapshot snap = newStore(snapshot(p)).fetch("v1");
        assertEquals(List.of(12L, 15L), snap.policies().get(0).agentIds());
    }

    @Test
    void agentIdsDeduplicatedPreservingOrder() throws Exception {
        Map<String, Object> p = basePolicy();
        p.put("agentIds", List.of(15, 12, 15));
        PolicyStore.Snapshot snap = newStore(snapshot(p)).fetch("v1");
        assertEquals(List.of(15L, 12L), snap.policies().get(0).agentIds());
    }

    @Test
    void missingAgentIdsRejected() {
        assertAgentIdsRejected(null);
    }

    @Test
    void emptyAgentIdsRejected() {
        assertAgentIdsRejected(List.of());
    }

    @Test
    void agentIdsSentinelMixedWithConcreteIdRejected() {
        assertAgentIdsRejected(List.of(0, 12));
    }

    @Test
    void agentIdsAtUpperBoundParses() throws Exception {
        Map<String, Object> p = basePolicy();
        p.put("agentIds", ids(1, 200));
        PolicyStore.Snapshot snap = newStore(snapshot(p)).fetch("v1");
        assertEquals(200, snap.policies().get(0).agentIds().size());
    }

    @Test
    void agentIdsOverUpperBoundRejected() {
        assertAgentIdsRejected(ids(1, 201));
    }

    // 上限按**去重后**的规模判 (与控制台 service 同口径): 201 个元素去重成 200 个仍然合法
    @Test
    void agentIdsOverBoundByDuplicatesStillParses() throws Exception {
        List<Integer> withDup = new ArrayList<>(ids(1, 200));
        withDup.add(1);
        Map<String, Object> p = basePolicy();
        p.put("agentIds", withDup);
        PolicyStore.Snapshot snap = newStore(snapshot(p)).fetch("v1");
        assertEquals(200, snap.policies().get(0).agentIds().size());
    }

    // ---- rulesInvalid 严格布尔: 缺字段被读成"规则有效" + agentIds=[0] = 全部智能体一律放行 (fail-open 缺口) ----

    private static void assertRulesInvalidRejected(Map<String, Object> p) {
        PolicyStore store = newStore(snapshot(p));
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> store.fetch("v1"));
        assertTrue(e.getMessage().startsWith("策略快照条目的 rulesInvalid 不是布尔"), e.getMessage());
    }

    @Test
    void missingRulesInvalidRejected() {
        Map<String, Object> p = basePolicy();
        p.put("agentIds", List.of(0));
        p.remove("rulesInvalid");
        assertRulesInvalidRejected(p);
    }

    @Test
    void nonBooleanRulesInvalidRejected() {
        Map<String, Object> p = basePolicy();
        p.put("agentIds", List.of(0));
        p.put("rulesInvalid", "false");
        assertRulesInvalidRejected(p);
    }

    @Test
    void nullRulesInvalidRejected() {
        Map<String, Object> p = basePolicy();
        p.put("agentIds", List.of(0));
        p.put("rulesInvalid", (String) null);
        assertRulesInvalidRejected(p);
    }

    // ---- 版本代际与 fail-closed: 心跳驱动的重拉时机 (设计文档 §7 R2 P2-2) ----

    private static final class CountingConsole extends ConsoleClient {
        Map<String, Object> data;
        PolicyHeartbeat captured;
        int fetches;

        @Override
        public Map<String, Object> policySnapshot() {
            fetches++;
            return data;
        }

        @Override
        public void policyHeartbeat(PolicyHeartbeat h) {
            this.captured = h;
        }
    }

    private static CountingConsole registered(Map<String, Object> data) {
        CountingConsole console = new CountingConsole();
        console.data = data;
        new PolicyStore(console, new ObjectMapper()).register();
        return console;
    }

    @Test
    void sameVersionDoesNotRefetch() {
        CountingConsole console = registered(Map.of("version", "v1", "policies", List.of(basePolicy())));
        console.captured.onReport("v1");
        console.captured.onReport("v1");
        assertEquals(1, console.fetches, "心跳版本与本地快照版本相同, 不应重复拉取");
    }

    @Test
    void changedVersionTriggersRefetch() {
        CountingConsole console = registered(Map.of("version", "v1", "policies", List.of(basePolicy())));
        console.captured.onReport("v1");
        console.data = Map.of("version", "v2", "policies", List.of(basePolicy()));
        console.captured.onReport("v2");
        assertEquals(2, console.fetches, "版本变化应触发重拉");
    }

    @Test
    void firstFetchFailureKeepsSourceUnavailable() {
        CountingConsole console = new CountingConsole();
        Map<String, Object> bad = basePolicy();
        bad.remove("agentIds");
        console.data = Map.of("version", "v1", "policies", List.of(bad));
        PolicyStore store = new PolicyStore(console, new ObjectMapper());
        store.register();
        console.captured.onReport("v1");
        // 从未成功拉到过快照 → 策略源不可用 → HOST 命令全拒 (fail-closed)
        assertTrue(store.unavailable(), "首次拉取非法时策略源必须仍算不可用");
    }

    // 控制台**成功**返回 policies=[] 是合法快照, 不是"读不到": loaded 之后按「无适用策略」放行
    @Test
    void emptyPolicyListIsAvailable() {
        CountingConsole console = new CountingConsole();
        console.data = Map.of("version", "v1", "policies", List.of());
        PolicyStore store = new PolicyStore(console, new ObjectMapper());
        store.register();
        console.captured.onReport("v1");
        assertFalse(store.unavailable(), "成功拉到空策略列表是合法快照, 不应按不可用处理");
    }
}
