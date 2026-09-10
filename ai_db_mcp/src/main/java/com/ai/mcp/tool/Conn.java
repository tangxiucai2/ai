package com.ai.mcp.tool;

import com.ai.mcp.config.ConsoleClient;
import io.modelcontextprotocol.common.McpTransportContext;
import com.ai.mcp.config.McpRequestFilter;

/**
 * 连接条目: 句柄与归属元数据合并成一个 entry, 一次 put/remove
 * <p>
 * 分成两张表存会留下「有句柄无归属」的窗口 (建连线程先登记、sweep 抢先清掉、再发布句柄),
 * 结果是连接建立了却谁也用不了还占着句柄. 合并后句柄存在 ⟺ 归属存在, 无第三态.
 */
public record Conn<T>(T handle, ConnMeta meta) {

    /** 固定资源模式: 凭据来自 X-Virtual-Token, 身份不可信 */
    public static final String MODE_CREDENTIAL = "CREDENTIAL";

    /** 用户自选模式: 身份来自 X-User-Token, 可信 */
    public static final String MODE_USER = "USER";

    /**
     * 不可变归属元数据
     * <p>
     * 四元组而非只记用户: 只按用户判定会漏两条路径 —— 同一用户从智能体 B 操作智能体 A 的连接;
     * 老模式持同一 credentialId 的虚拟凭据靠前缀匹配摸到新模式建的连接
     */
    public record ConnMeta(String authMode, long agentId, Long userId, long credentialId, String resource) {

        /** 固定资源模式的归属 */
        public static ConnMeta ofCredential(ConsoleClient.Resolved cred, String resource) {
            return new ConnMeta(MODE_CREDENTIAL, cred.agentId(), null, cred.credentialId(), resource);
        }

        /** 用户自选模式的归属 */
        public static ConnMeta ofUser(ConsoleClient.ResolvedUser identity, long credentialId, String resource) {
            return new ConnMeta(MODE_USER, identity.agentId(), identity.userId(), credentialId, resource);
        }

        /**
         * 当前请求能否访问该连接: 模式必须一致, 智能体必须一致, 用户模式还要求用户一致
         */
        public boolean accessibleBy(McpTransportContext ctx) {
            ConsoleClient.Resolved cred = McpRequestFilter.credential(ctx);
            if (cred != null) {
                return MODE_CREDENTIAL.equals(authMode)
                        && cred.agentId() == agentId
                        && cred.credentialId() == credentialId;
            }
            ConsoleClient.ResolvedUser identity = McpRequestFilter.userIdentity(ctx);
            return identity != null
                    && MODE_USER.equals(authMode)
                    && identity.agentId() == agentId
                    && userId != null
                    && identity.userId() == userId;
        }
    }
}
