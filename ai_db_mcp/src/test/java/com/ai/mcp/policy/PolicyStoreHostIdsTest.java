package com.ai.mcp.policy;

import com.ai.mcp.config.ConsoleClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PolicyStore 目标资源集合 (hostIds) 解析单测 (设计文档 2026-09-18-访问控制策略目标资源多选-设计.md §5.2/§7.2 G2/G5/G10).
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
        p.put("agentId", 0);
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
}
