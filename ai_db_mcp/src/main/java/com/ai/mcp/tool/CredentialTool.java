package com.ai.mcp.tool;

import com.ai.mcp.audit.AuditLog;
import com.ai.mcp.config.ConsoleClient;
import com.ai.mcp.config.McpRequestFilter;
import io.modelcontextprotocol.common.McpTransportContext;
import org.springaicommunity.mcp.annotation.McpTool;
import org.springaicommunity.mcp.annotation.McpToolParam;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * 可用凭据发现工具 (仅用户自选模式可用)
 * <p>
 * 老模式 (只带 X-Virtual-Token) 一律拒绝: 那条路径的 X-User-Name 是客户端自填的明文,
 * 放开等于让一个「只能连一台机器」的凭据额外获得「侦察该用户全部资产」的能力 ——
 * 就算连不上, address:port + 账号 + 资源名的清单本身就是横向移动的地图
 */
@Component
public class CredentialTool {

    private final AuditLog audit;
    private final ConsoleClient console;

    public CredentialTool(AuditLog audit, ConsoleClient console) {
        this.audit = audit;
        this.console = console;
    }

    @McpTool(name = "list_credentials", description = "List resources the current user is authorized to access. "
            + "Returns credentialId plus display info (never passwords). "
            + "Use the returned credentialId with ssh_connect or db_create_connection. "
            + "Requires the request to carry a user token")
    public Map<String, Object> list_credentials(
            @McpToolParam(description = "Filter by resource name, address or account (optional)", required = false) String keyword,
            McpTransportContext ctx) {
        return audit.run(ctx, "list_credentials", null, "list", () -> list_credentials0(keyword, ctx));
    }

    private Map<String, Object> list_credentials0(String keyword, McpTransportContext ctx) {
        Map<String, Object> result = new HashMap<>();
        ConsoleClient.ResolvedUser identity = McpRequestFilter.userIdentity(ctx);
        if (identity == null) {
            result.put("success", false);
            result.put("error", "该操作需要用户 Token, 请在请求头补充 X-User-Token");
            return result;
        }
        try {
            Map<String, Object> data = console.listCredentials(identity.agentCode(),
                    McpRequestFilter.userToken(ctx), keyword);
            result.put("success", true);
            result.put("credentials", data.get("items"));
            result.put("total", data.get("total"));
            if (Boolean.TRUE.equals(data.get("truncated"))) {
                result.put("truncated", true);
                result.put("hint", "结果过多已截断, 请用 keyword 按资源名/地址/账号筛选后重试");
            }
        } catch (ConsoleClient.Rejected e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", "控制台不可达, 无法获取凭据列表");
        }
        return result;
    }

}
