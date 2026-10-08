package com.ai.mcp.config;

import com.ai.mcp.audit.AuditLog;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 固定资源模式的用户身份: 只认 X-User-Token 反查结果, 不写用户自选模式的 attribute; 拒绝审计不归因自报身份
 */
class McpRequestFilterFixedUserTokenTest {

    private static class FakeConsole extends ConsoleClient {
        String lastUserToken;
        RuntimeException reject;
        ConsoleClient.Resolved resolved;

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public boolean checkToken(String authorization, boolean clientCertVerified, boolean secure) {
            return true;
        }

        @Override
        public boolean tryAcquire() {
            return true;
        }

        @Override
        public Resolved resolve(String agentCode, String token, String userToken, String peerIp) {
            lastUserToken = userToken;
            if (reject != null) {
                throw reject;
            }
            return resolved;
        }
    }

    /** 只截获鉴权拒绝审计 */
    private static class FakeAudit extends AuditLog {
        final List<String[]> denied = new ArrayList<>();

        FakeAudit() {
            super(null, null, null);
        }

        @Override
        public void denied(String agent, String user, String reason, String srcIp, String userId) {
            denied.add(new String[]{agent, user, reason, userId});
        }
    }

    private final FakeConsole console = new FakeConsole();
    private final FakeAudit audit = new FakeAudit();
    private final McpRequestFilter filter = new McpRequestFilter(console, audit, "/mcp");

    private static MockHttpServletRequest request(String userToken) {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/mcp");
        req.addHeader("X-Agent-Id", "agent-7");
        req.addHeader("X-Virtual-Token", "vt");
        req.addHeader("X-User-Name", "admin");
        req.addHeader("X-User-Id", "1");
        if (userToken != null) {
            req.addHeader("X-User-Token", userToken);
        }
        return req;
    }

    private static ConsoleClient.Resolved resolved(String userName, Long userId) {
        return new ConsoleClient.Resolved(7, 9, "HOST", "SSH", "10.0.0.1", 22, null, "u", "p",
                "agent-7", userName, 1L, null, userId);
    }

    @Test
    void tokenIdentityOverridesClaimedUser() throws Exception {
        console.resolved = resolved("bob", 6L);
        MockHttpServletRequest req = request("ut");
        filter.doFilter(req, new MockHttpServletResponse(), new MockFilterChain());

        assertEquals("ut", console.lastUserToken);
        assertEquals("6", req.getAttribute(McpRequestFilter.USER_ID));
        assertEquals("ut", req.getAttribute(McpRequestFilter.FIXED_USER_TOKEN));
        // 不能写用户自选模式的 attribute, 否则 list_credentials 等会对固定资源开放
        assertNull(req.getAttribute(McpRequestFilter.USER_TOKEN));
        assertNull(req.getAttribute(McpRequestFilter.USER_IDENTITY));
        assertEquals("ut", McpTransportConfig.extract(req).get(McpRequestFilter.FIXED_USER_TOKEN));
    }

    @Test
    void anonymousDropsClaimedUser() throws Exception {
        console.resolved = resolved(null, null);
        MockHttpServletRequest req = request(null);
        filter.doFilter(req, new MockHttpServletResponse(), new MockFilterChain());

        assertNull(console.lastUserToken);
        assertNull(req.getAttribute(McpRequestFilter.USER_ID));
        assertNull(req.getAttribute(McpRequestFilter.FIXED_USER_TOKEN));
    }

    @Test
    void denyAuditDoesNotAttributeClaimedUser() throws Exception {
        console.reject = new ConsoleClient.Rejected("用户身份无效");
        MockHttpServletResponse resp = new MockHttpServletResponse();
        filter.doFilter(request("bad"), resp, new MockFilterChain());

        assertEquals(403, resp.getStatus());
        assertEquals("{\"code\":403,\"msg\":\"用户身份无效\"}", resp.getContentAsString(java.nio.charset.StandardCharsets.UTF_8));
        String[] d = audit.denied.get(0);
        assertNull(d[1]);
        assertNull(d[3]);
        assertEquals("用户身份无效（客户端自报: admin, userId=1）", d[2]);
    }
}
