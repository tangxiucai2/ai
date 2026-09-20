package com.ai.mcp.policy;

import com.ai.mcp.config.ConsoleClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * PolicyDecider 目标资源集合作用域单测 (设计文档 2026-09-18-访问控制策略目标资源多选-设计.md §7.2 G3/G4/G8).
 * <p>
 * 用"白名单只放 ls, 实际发 rm"来区分两种结果: 策略适用 → DENY (未命中白名单);
 * 策略不适用 → applicable 为空 → ALLOW. 只断言 ALLOW 是分不出"命中并放行"和"压根没管"的
 */
class PolicyDeciderHostIdsTest {

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

    private static PolicyDecider newDecider(List<Object> hostIds) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", 1L);
        p.put("name", "wl-1");
        p.put("type", PolicyStore.TYPE_WHITELIST);
        p.put("hostType", "SSH");
        p.put("hostIds", hostIds);
        p.put("agentIds", List.of(0));
        p.put("approvalMode", "NONE");
        p.put("rulesInvalid", false);
        p.put("ops", List.of(Map.of("value", "ls", "matchType", "EXACT")));

        FakeConsoleClient console = new FakeConsoleClient();
        console.data = Map.of("version", "v1", "policies", List.of(p));
        PolicyStore store = new PolicyStore(console, new ObjectMapper());
        store.register();
        console.captured.onReport("v1");
        assertFalse(store.unavailable(), "快照应已加载成功");
        return new PolicyDecider(store);
    }

    @Test
    void concreteIdsCoverEveryListedHost() {
        PolicyDecider decider = newDecider(List.of(12, 15));
        // 集合内的每一台都受管: 白名单外的命令被拒
        assertEquals(PolicyDecider.Kind.DENY, decider.decide(0, "SSH", 12L, "rm").kind());
        assertEquals(PolicyDecider.Kind.DENY, decider.decide(0, "SSH", 15L, "rm").kind());
        // 白名单内的命令放行, 证明策略确实适用而不是被整条跳过
        assertEquals(PolicyDecider.Kind.ALLOW, decider.decide(0, "SSH", 15L, "ls").kind());
    }

    @Test
    void hostOutsideTheSetIsNotGoverned() {
        PolicyDecider decider = newDecider(List.of(12, 15));
        assertEquals(PolicyDecider.Kind.ALLOW, decider.decide(0, "SSH", 99L, "rm").kind());
    }

    @Test
    void sentinelZeroGovernsEveryHostOfSameType() {
        PolicyDecider decider = newDecider(List.of(0));
        assertEquals(PolicyDecider.Kind.DENY, decider.decide(0, "SSH", 12L, "rm").kind());
        assertEquals(PolicyDecider.Kind.DENY, decider.decide(0, "SSH", 99999L, "rm").kind());
    }

    @Test
    void sentinelZeroDoesNotCrossHostType() {
        PolicyDecider decider = newDecider(List.of(0));
        assertEquals(PolicyDecider.Kind.ALLOW, decider.decide(0, "MYSQL", 12L, "rm").kind());
    }
}
