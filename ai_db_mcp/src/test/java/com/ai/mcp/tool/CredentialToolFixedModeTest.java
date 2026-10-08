package com.ai.mcp.tool;

import com.ai.mcp.audit.AuditLog;
import com.ai.mcp.config.ConsoleClient;
import com.ai.mcp.config.McpRequestFilter;
import io.modelcontextprotocol.common.McpTransportContext;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 固定资源连接 (带不带 X-User-Token) 调 list_credentials 都应提示改用用户自选模式, 不能提示「补 X-User-Token」
 */
class CredentialToolFixedModeTest {

    /** 审计不是本测试关注点, 直接执行工具体 */
    private static final AuditLog PASS_AUDIT = new AuditLog(null, null, null) {
        @Override
        public Map<String, Object> run(McpTransportContext ctx, String tool, String connectionId, String summary,
                                       Supplier<Map<String, Object>> call) {
            return call.get();
        }
    };

    private static final String FIXED_MODE_ERROR =
            "固定资源模式 (携带 X-Virtual-Token) 不支持列出凭据, 请改用用户自选模式 (仅携带 X-User-Token)";

    private final CredentialTool tool = new CredentialTool(PASS_AUDIT, null);

    private static ConsoleClient.Resolved cred(String userName) {
        return new ConsoleClient.Resolved(7, 9, "HOST", "SSH", "10.0.0.1", 22, null, "u", null, "agent-7", userName, 1L);
    }

    @Test
    void anonymousFixedModeHintsUserMode() {
        McpTransportContext ctx = McpTransportContext.create(Map.of(McpRequestFilter.CREDENTIAL, cred(null)));
        assertEquals(FIXED_MODE_ERROR, tool.list_credentials(null, ctx).get("error"));
    }

    @Test
    void namedFixedModeHintsUserMode() {
        McpTransportContext ctx = McpTransportContext.create(Map.of(McpRequestFilter.CREDENTIAL, cred("alice")));
        assertEquals(FIXED_MODE_ERROR, tool.list_credentials(null, ctx).get("error"));
    }

    @Test
    void noIdentityStillAsksForUserToken() {
        Map<String, Object> result = tool.list_credentials(null, McpTransportContext.create(Map.of()));
        assertEquals("该操作需要用户 Token, 请在请求头补充 X-User-Token", result.get("error"));
    }

}
