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
 * PolicyStore 时间段控制值域/格式校验单测 (设计文档 2026-09-18-访问控制策略时间段控制-设计.md §8 测试清单第 1/2/3/4/5/15 项).
 * fetch() 已改为包级可见, 直接灌快照数据校验, 不必绕心跳/HTTP.
 */
class PolicyStoreActionTimeTest {

    private static PolicyStore newStore(Map<String, Object> snapshotData) {
        ConsoleClient console = new ConsoleClient() {
            @Override
            public Map<String, Object> policySnapshot() {
                return snapshotData;
            }
        };
        return new PolicyStore(console, new ObjectMapper());
    }

    private static Map<String, Object> basePolicy(long id) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", id);
        p.put("name", "测试策略" + id);
        p.put("type", PolicyStore.TYPE_WHITELIST);
        p.put("hostType", "SSH");
        p.put("hostId", 0);
        p.put("agentId", 0);
        p.put("approvalMode", "NONE");
        p.put("rulesInvalid", false);
        p.put("ops", List.of(Map.of("value", "ls", "matchType", "EXACT")));
        return p;
    }

    private static Map<String, Object> snapshot(Map<String, Object> policy) {
        return Map.of("policies", List.of(policy));
    }

    // 1. 缺字段兼容: 老控制台快照(三字段全缺) → 按 "1" 全天, 不抛异常
    @Test
    void missingFieldsDefaultToAllDay() throws Exception {
        Map<String, Object> p = basePolicy(1);
        PolicyStore store = newStore(snapshot(p));
        PolicyStore.Snapshot snap = store.fetch("v1");
        assertEquals(1, snap.policies().size());
        assertEquals("1", snap.policies().get(0).actionTimeType());
        assertFalse(snap.policies().get(0).rulesInvalid());
    }

    // 2. 显式 null: 硬失败
    @Test
    void explicitNullTypeHardFails() {
        Map<String, Object> p = basePolicy(2);
        p.put("actionTimeType", null);
        p.put("actionTimeStart", null);
        p.put("actionTimeEnd", null);
        PolicyStore store = newStore(snapshot(p));
        assertThrows(IllegalStateException.class, () -> store.fetch("v2"));
    }

    // 15 (五轮评审补充). type 缺失但 start/end 存在的混合形态: 不能兼容成老控制台, 必须硬失败
    @Test
    void mixedMissingHardFails() {
        Map<String, Object> p = basePolicy(3);
        p.put("actionTimeStart", "09:00:00");
        p.put("actionTimeEnd", "18:00:00");
        PolicyStore store = newStore(snapshot(p));
        assertThrows(IllegalStateException.class, () -> store.fetch("v3"));
    }

    // 3. 语法非法: 格式坏掉 → rulesInvalid=true, 不抛异常, 不丢弃该条策略
    @Test
    void malformedTimeMarksRulesInvalid() throws Exception {
        Map<String, Object> p = basePolicy(4);
        p.put("actionTimeType", "0");
        p.put("actionTimeStart", "not-a-time");
        p.put("actionTimeEnd", "18:00:00");
        PolicyStore store = newStore(snapshot(p));
        PolicyStore.Snapshot snap = store.fetch("v4");
        assertEquals(1, snap.policies().size());
        assertTrue(snap.policies().get(0).rulesInvalid());
    }

    // 4a. 语义非法: type=0 start == end (空窗口)
    @Test
    void emptyWindowMarksRulesInvalid() throws Exception {
        Map<String, Object> p = basePolicy(5);
        p.put("actionTimeType", "0");
        p.put("actionTimeStart", "09:00:00");
        p.put("actionTimeEnd", "09:00:00");
        PolicyStore store = newStore(snapshot(p));
        PolicyStore.Snapshot snap = store.fetch("v5");
        assertTrue(snap.policies().get(0).rulesInvalid());
    }

    // 4b. 语义非法: type=2 start >= end (反向绝对区间)
    @Test
    void reversedAbsoluteRangeMarksRulesInvalid() throws Exception {
        Map<String, Object> p = basePolicy(6);
        p.put("actionTimeType", "2");
        p.put("actionTimeStart", "2026-09-20 18:00:00");
        p.put("actionTimeEnd", "2026-09-20 09:00:00");
        PolicyStore store = newStore(snapshot(p));
        PolicyStore.Snapshot snap = store.fetch("v6");
        assertTrue(snap.policies().get(0).rulesInvalid());
    }

    // 5. 合法 type=2 (uuuu + STRICT) 能正常解析, 不误判非法 (防 formatter 再次写错)
    @Test
    void validAbsoluteRangeParsesOk() throws Exception {
        Map<String, Object> p = basePolicy(7);
        p.put("actionTimeType", "2");
        p.put("actionTimeStart", "2026-09-20 09:00:00");
        p.put("actionTimeEnd", "2026-09-20 18:00:00");
        PolicyStore store = newStore(snapshot(p));
        PolicyStore.Snapshot snap = store.fetch("v7");
        assertFalse(snap.policies().get(0).rulesInvalid());
        assertEquals("2026-09-20 09:00:00", snap.policies().get(0).actionTimeStart());
    }

    // 13. STRICT 拒绝 SMART 会接受的非法日历日期 (2 月 30 日), 与控制台侧同一套 formatter
    @Test
    void strictFormatterRejectsInvalidCalendarDate() throws Exception {
        Map<String, Object> p = basePolicy(8);
        p.put("actionTimeType", "2");
        p.put("actionTimeStart", "2026-02-30 09:00:00");
        p.put("actionTimeEnd", "2026-02-30 18:00:00");
        PolicyStore store = newStore(snapshot(p));
        PolicyStore.Snapshot snap = store.fetch("v8");
        assertTrue(snap.policies().get(0).rulesInvalid());
    }
}
