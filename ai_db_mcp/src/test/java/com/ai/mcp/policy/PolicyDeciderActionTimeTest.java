package com.ai.mcp.policy;

import com.ai.mcp.config.ConsoleClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * PolicyDecider 时间段控制单测 (设计文档 2026-09-18-访问控制策略时间段控制-设计.md §8 测试清单第 6/7/8/9 项).
 * 时间通过包级重载 decide(..., now)/recordRate(..., now) 注入, 不依赖系统时钟或 Clock 注入.
 */
class PolicyDeciderActionTimeTest {

    private static final ZoneId ZONE = ZoneId.of("Asia/Shanghai");

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

    private static PolicyDecider newDecider(List<Map<String, Object>> policies) {
        FakeConsoleClient console = new FakeConsoleClient();
        console.data = Map.of("version", "v1", "policies", policies);
        PolicyStore store = new PolicyStore(console, new ObjectMapper());
        store.register();
        console.captured.onReport("v1");
        assertFalse(store.unavailable(), "快照应已加载成功");
        return new PolicyDecider(store);
    }

    private static Map<String, Object> whitelist(long id, String actionTimeType, String start, String end, String... cmds) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", id);
        p.put("name", "wl-" + id);
        p.put("type", PolicyStore.TYPE_WHITELIST);
        p.put("hostType", "SSH");
        p.put("hostIds", List.of(0));
        p.put("agentId", 0);
        p.put("approvalMode", "NONE");
        p.put("rulesInvalid", false);
        List<Map<String, Object>> ops = new ArrayList<>();
        for (String c : cmds) {
            ops.add(Map.of("value", c, "matchType", "EXACT"));
        }
        p.put("ops", ops);
        if (actionTimeType != null) {
            p.put("actionTimeType", actionTimeType);
            p.put("actionTimeStart", start);
            p.put("actionTimeEnd", end);
        }
        return p;
    }

    private static ZonedDateTime at(String iso) {
        return ZonedDateTime.of(LocalDateTime.parse(iso.replace(' ', 'T')), ZONE);
    }

    // 6. 跨天: type=0 22:00~06:00, 在 23:00 与 05:00 都适用, 12:00 不适用
    @Test
    void crossDayWindowAppliesAcrossMidnight() {
        List<Map<String, Object>> policies = List.of(
                whitelist(1, "0", "22:00:00", "06:00:00", "ls"),
                // 全天兜底策略, 只认 pwd —— 用来区分"policy1 被排除出 applicable"与"ls 单纯没匹配上"
                whitelist(2, "1", null, null, "pwd")
        );
        PolicyDecider decider = newDecider(policies);

        assertEquals(PolicyDecider.Kind.ALLOW,
                decider.decide(0, "SSH", 1L, "ls", at("2026-09-20 23:00:00")).kind());
        assertEquals(PolicyDecider.Kind.ALLOW,
                decider.decide(0, "SSH", 1L, "ls", at("2026-09-21 05:00:00")).kind());
        // 12:00 不在跨天窗口内: policy1 被排除, 只剩只认 pwd 的 policy2 -> ls 未命中白名单 -> 拒绝
        assertEquals(PolicyDecider.Kind.DENY,
                decider.decide(0, "SSH", 1L, "ls", at("2026-09-20 12:00:00")).kind());
    }

    // 7 / 7b. 闭区间边界 + 纳秒截断: 左端 09:00:00 与右端 18:00:00.500 都适用
    @Test
    void closedIntervalBoundariesApply() {
        List<Map<String, Object>> policies = List.of(whitelist(1, "0", "09:00:00", "18:00:00", "ls"));
        PolicyDecider decider = newDecider(policies);

        assertEquals(PolicyDecider.Kind.ALLOW,
                decider.decide(0, "SSH", 1L, "ls", at("2026-09-20 09:00:00")).kind());
        assertEquals(PolicyDecider.Kind.ALLOW,
                decider.decide(0, "SSH", 1L, "ls", at("2026-09-20 18:00:00").plusNanos(500_000_000)).kind());
    }

    // 9. 时间段字段必须进入 policyRevision: 只改时间段, 摘要应跟着变 (审批凭证失效判据)
    @Test
    void policyRevisionChangesWithActionTime() {
        Map<String, Object> allDay = whitelist(1, "1", null, null, "ls");
        allDay.put("approvalMode", "APPROVAL");
        PolicyDecider decider1 = newDecider(List.of(allDay));
        PolicyDecider.Decision d1 = decider1.decide(0, "SSH", 1L, "ls", at("2026-09-20 12:00:00"));
        assertEquals(PolicyDecider.Kind.APPROVAL, d1.kind());

        Map<String, Object> scheduled = whitelist(1, "0", "09:00:00", "18:00:00", "ls");
        scheduled.put("approvalMode", "APPROVAL");
        PolicyDecider decider2 = newDecider(List.of(scheduled));
        PolicyDecider.Decision d2 = decider2.decide(0, "SSH", 1L, "ls", at("2026-09-20 12:00:00"));
        assertEquals(PolicyDecider.Kind.APPROVAL, d2.kind());

        assertNotEquals(d1.policyRevision(), d2.policyRevision(),
                "只改时间段而 policyRevision 不变, 会让改动前的在途审批凭证在改动后仍被接受");
    }

    // 8. 限流判定与记账跨边界 (§10 已知限制, 两个方向都验证真实发生而不是理论假设)
    @Test
    void rateLimitEndBoundaryRecordMiss() {
        PolicyDecider decider = newDecider(List.of(rateLimit("09:00:00", "18:00:00")));
        // 判定发生在窗口内 (未超限) -> 放行
        assertEquals(PolicyDecider.Kind.ALLOW,
                decider.decide(0, "SSH", 1L, "whoami", at("2026-09-20 17:59:59")).kind());
        // 记账却发生在窗口外 (结束边界之后), recordRate 内部重新 inScope() 判定该策略已不适用 -> 不计数
        decider.recordRate(0, "SSH", 1L, at("2026-09-20 18:00:01"));
        // 仍在窗口内的下一次调用应仍放行: 若上一次真被计数, limit=1 时这里就会超限
        assertEquals(PolicyDecider.Kind.ALLOW,
                decider.decide(0, "SSH", 1L, "whoami", at("2026-09-20 17:59:58")).kind(),
                "记账落在窗口外没有真正计数, 复现已知限制: 结束边界漏计数");
    }

    @Test
    void rateLimitStartBoundaryRecordWithoutCheck() {
        PolicyDecider decider = newDecider(List.of(rateLimit("09:00:00", "18:00:00")));
        // 判定发生在窗口外 (策略未被选中, 不受限流检查) -> 放行
        assertEquals(PolicyDecider.Kind.ALLOW,
                decider.decide(0, "SSH", 1L, "whoami", at("2026-09-20 08:59:59")).kind());
        // 记账却发生在窗口内 (开始边界之后), 该策略此时适用 -> 真被计数 (count 达到 limit=1)
        decider.recordRate(0, "SSH", 1L, at("2026-09-20 09:00:01"));
        // 窗口内的下一次调用此时应已超限
        assertEquals(PolicyDecider.Kind.DENY,
                decider.decide(0, "SSH", 1L, "whoami", at("2026-09-20 09:00:02")).kind(),
                "开始边界记账落在窗口内被计数, 复现已知限制: 该次调用未受检查却被计数");
    }

    private static Map<String, Object> rateLimit(String start, String end) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", 1L);
        p.put("name", "rate-1");
        p.put("type", PolicyStore.TYPE_RATE_LIMIT);
        p.put("hostType", "SSH");
        p.put("hostIds", List.of(0));
        p.put("agentId", 0);
        p.put("approvalMode", "NONE");
        p.put("rulesInvalid", false);
        p.put("ops", List.of());
        p.put("limit", 1);
        p.put("windowSeconds", 3600);
        p.put("actionTimeType", "0");
        p.put("actionTimeStart", start);
        p.put("actionTimeEnd", end);
        return p;
    }
}
