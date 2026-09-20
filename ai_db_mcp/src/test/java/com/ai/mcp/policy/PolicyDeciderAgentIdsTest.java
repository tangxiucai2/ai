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
 * PolicyDecider 适用智能体集合作用域单测 (设计文档 2026-09-19-访问控制策略-适用智能体多选.md §5/§7 R3 P3-1).
 * <p>
 * 照 {@link PolicyDeciderHostIdsTest}: 用"白名单只放 ls, 实际发 rm"区分两种结果 ——
 * 策略适用 → DENY (未命中白名单); 策略不适用 → applicable 为空 → ALLOW.
 * 只断言 ALLOW 分不出"命中并放行"和"压根没管"
 */
class PolicyDeciderAgentIdsTest {

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

    private static PolicyDecider newDecider(Map<String, Object> policy) {
        FakeConsoleClient console = new FakeConsoleClient();
        console.data = Map.of("version", "v1", "policies", List.of(policy));
        PolicyStore store = new PolicyStore(console, new ObjectMapper());
        store.register();
        console.captured.onReport("v1");
        assertFalse(store.unavailable(), "快照应已加载成功");
        return new PolicyDecider(store);
    }

    /** 白名单只放 ls, 资源侧用 [0] 哨兵覆盖全部 SSH 资源, 把变量收敛到 agentIds 一个 */
    private static Map<String, Object> whitelist(List<Object> agentIds) {
        Map<String, Object> p = basePolicy(agentIds);
        p.put("type", PolicyStore.TYPE_WHITELIST);
        p.put("ops", List.of(Map.of("value", "ls", "matchType", "EXACT")));
        return p;
    }

    /** 黑名单拦 rm + 指定人工介入档位: 档位只在命中黑名单时才有机会生效 */
    private static Map<String, Object> blacklist(List<Object> agentIds, String approvalMode) {
        Map<String, Object> p = basePolicy(agentIds);
        p.put("type", PolicyStore.TYPE_BLACKLIST);
        p.put("approvalMode", approvalMode);
        p.put("ops", List.of(Map.of("value", "rm", "matchType", "EXACT")));
        return p;
    }

    private static Map<String, Object> basePolicy(List<Object> agentIds) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("id", 1L);
        p.put("name", "p-1");
        p.put("hostType", "SSH");
        p.put("hostIds", List.of(0));
        p.put("agentIds", agentIds);
        p.put("approvalMode", "NONE");
        p.put("rulesInvalid", false);
        return p;
    }

    @Test
    void concreteIdsCoverEveryListedAgent() {
        PolicyDecider decider = newDecider(whitelist(List.of(12, 15)));
        // 集合内的每一个智能体都受管: 白名单外的命令被拒
        assertEquals(PolicyDecider.Kind.DENY, decider.decide(12, "SSH", 1L, "rm").kind());
        assertEquals(PolicyDecider.Kind.DENY, decider.decide(15, "SSH", 1L, "rm").kind());
        // 白名单内的命令放行, 证明策略确实适用而不是被整条跳过
        assertEquals(PolicyDecider.Kind.ALLOW, decider.decide(15, "SSH", 1L, "ls").kind());
    }

    @Test
    void agentOutsideTheSetIsNotGoverned() {
        PolicyDecider decider = newDecider(whitelist(List.of(12, 15)));
        assertEquals(PolicyDecider.Kind.ALLOW, decider.decide(99, "SSH", 1L, "rm").kind());
    }

    @Test
    void sentinelZeroGovernsEveryAgent() {
        PolicyDecider decider = newDecider(whitelist(List.of(0)));
        assertEquals(PolicyDecider.Kind.DENY, decider.decide(12, "SSH", 1L, "rm").kind());
        assertEquals(PolicyDecider.Kind.DENY, decider.decide(99999, "SSH", 1L, "rm").kind());
    }

    // 人工介入档位只对范围内的智能体触发: 范围外的智能体连策略都不适用, 不该弹确认/建审批单
    @Test
    void confirmOnlyForAgentsInScope() {
        PolicyDecider decider = newDecider(blacklist(List.of(12), "CONFIRM"));
        assertEquals(PolicyDecider.Kind.CONFIRM, decider.decide(12, "SSH", 1L, "rm").kind());
        assertEquals(PolicyDecider.Kind.ALLOW, decider.decide(99, "SSH", 1L, "rm").kind());
    }

    @Test
    void approvalOnlyForAgentsInScope() {
        PolicyDecider decider = newDecider(blacklist(List.of(12), "APPROVAL"));
        assertEquals(PolicyDecider.Kind.APPROVAL, decider.decide(12, "SSH", 1L, "rm").kind());
        assertEquals(PolicyDecider.Kind.ALLOW, decider.decide(99, "SSH", 1L, "rm").kind());
    }

    @Test
    void bothOnlyForAgentsInScope() {
        PolicyDecider decider = newDecider(blacklist(List.of(12), "BOTH"));
        assertEquals(PolicyDecider.Kind.BOTH, decider.decide(12, "SSH", 1L, "rm").kind());
        assertEquals(PolicyDecider.Kind.ALLOW, decider.decide(99, "SSH", 1L, "rm").kind());
    }
}
