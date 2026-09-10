package com.ai.mcp.tool;

import com.ai.mcp.config.ConsoleClient;
import com.ai.mcp.config.McpRequestFilter;
import io.modelcontextprotocol.common.McpTransportContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * 工具层的授权重校验与在途保护
 * <p>
 * 建连时校验一次是不够的: 撤权后已建立的连接仍能执行命令. 用户自选模式下每次操作已有连接
 * 都回控制台按连接元数据里的 credentialId 重校验, 撤权/过期/禁用即刻生效.
 * 代价是控制台不可达时用户模式无法操作已有连接 (老模式不受影响, 保持原行为).
 */
@Component
public class ToolAuth {

    private static final Logger log = LoggerFactory.getLogger(ToolAuth.class);

    private static ConsoleClient console;

    @Autowired
    void setConsole(ConsoleClient client) {
        ToolAuth.console = client;
    }

    /** 授权重校验结果: 故障必须与明确撤权区分, 否则列表会把"授权服务挂了"伪装成"你没有连接" */
    enum Verdict {
        /** 放行 */
        ALLOW,
        /** 控制台明确拒绝: 撤权/过期/禁用 */
        DENY,
        /** 控制台不可达或 5xx: 不知道该不该放行, 一律不放行但要让调用方知道是故障 */
        UNAVAILABLE
    }

    /**
     * 操作已有连接前的实时授权重校验
     * <p>
     * 固定资源模式不重校验: 身份本就不可信, 加了既改变存量行为又白付性能
     */
    static Verdict verdict(McpTransportContext ctx, Conn.ConnMeta meta) {
        if (!Conn.MODE_USER.equals(meta.authMode())) {
            return Verdict.ALLOW;
        }
        ConsoleClient.ResolvedUser identity = McpRequestFilter.userIdentity(ctx);
        String userToken = McpRequestFilter.userToken(ctx);
        if (identity == null || userToken == null || console == null) {
            return Verdict.DENY;
        }
        try {
            McpRequestFilter.setResolved(ctx,
                    console.resolveCredential(identity.agentCode(), userToken, meta.credentialId(), identity.userName()));
            return Verdict.ALLOW;
        } catch (ConsoleClient.Rejected e) {
            // 拒绝路径也要留痕: 否则撤权后的越权尝试在审计里只是笼统的「连接不存在」, 看不出对哪台机器、为什么被拒
            log.info("已有连接授权已失效 credentialId={}: {}", meta.credentialId(), e.getMessage());
            denied(ctx, meta, e.getMessage());
            return Verdict.DENY;
        } catch (Exception e) {
            // 控制台不可达: 拒绝而非放行, 否则撤权在故障窗口内失效
            log.warn("重校验控制台不可达 credentialId={}: {}", meta.credentialId(), e.toString());
            denied(ctx, meta, CONSOLE_UNAVAILABLE);
            return Verdict.UNAVAILABLE;
        }
    }

    /** 单连接操作只关心放不放行 */
    static boolean recheck(McpTransportContext ctx, Conn.ConnMeta meta) {
        return verdict(ctx, meta) == Verdict.ALLOW;
    }

    static final String CONSOLE_UNAVAILABLE = "控制台不可达, 无法校验凭据授权";

    /**
     * 拒绝时把已通过本地归属校验的连接元数据与原因交给审计
     * <p>
     * 控制台按 credentialId 补目标资产, 缺了这次被拒操作就关联不到任何资源
     */
    private static void denied(McpTransportContext ctx, Conn.ConnMeta meta, String reason) {
        McpRequestFilter.setDenyReason(ctx, reason);
        ConsoleClient.ResolvedUser identity = McpRequestFilter.userIdentity(ctx);
        McpRequestFilter.setResolved(ctx, new ConsoleClient.Resolved(
                meta.agentId(), meta.credentialId(), null, null, meta.resource(),
                null, null, null, null,
                identity == null ? null : identity.agentCode(),
                identity == null ? null : identity.userName()));
    }

    /**
     * 建连时取凭据: 固定资源模式直接用请求绑定的凭据 (忽略入参);
     * 用户自选模式按 credentialId 回控制台换取, 控制台重新校验授权, 不信任网关传回的 id
     *
     * @return 凭据; 用户自选模式未指定 credentialId 时返回 null (由调用方给 LLM 引导文案)
     */
    static ConsoleClient.Resolved resolveForTools(McpTransportContext ctx, Long credentialId) throws Exception {
        ConsoleClient.Resolved bound = McpRequestFilter.credential(ctx);
        if (bound != null) {
            return bound;
        }
        ConsoleClient.ResolvedUser identity = McpRequestFilter.userIdentity(ctx);
        if (identity == null || credentialId == null) {
            return null;
        }
        ConsoleClient.Resolved cred;
        try {
            cred = console.resolveCredential(identity.agentCode(),
                    McpRequestFilter.userToken(ctx), credentialId, identity.userName());
        } catch (ConsoleClient.Rejected e) {
            // 被拒也要留下"想连哪台": 否则审计只有用户与原因, 追不到访问目标.
            // 标成 attempt: 这是尝试访问的目标, 不是已授权资源, 别让审计看起来像连成功过
            attempted(ctx, identity, credentialId);
            throw e;
        }
        // 回填供审计补资源: 用户模式 Filter 阶段没有凭据, 不补则审计里 resource 恒为 "-"
        McpRequestFilter.setResolved(ctx, cred);
        return cred;
    }

    /**
     * 建连被拒时登记尝试访问的凭据 (无地址: 控制台没返回, 也不该由网关臆造)
     */
    private static void attempted(McpTransportContext ctx, ConsoleClient.ResolvedUser identity, long credentialId) {
        McpRequestFilter.setResolved(ctx, new ConsoleClient.Resolved(
                identity.agentId(), credentialId, null, null, null,
                null, null, null, null, identity.agentCode(), identity.userName()));
    }

    /**
     * 按当前模式生成连接归属元数据
     */
    static Conn.ConnMeta metaOf(McpTransportContext ctx, ConsoleClient.Resolved cred, String resource) {
        ConsoleClient.ResolvedUser identity = McpRequestFilter.userIdentity(ctx);
        return identity == null
                ? Conn.ConnMeta.ofCredential(cred, resource)
                : Conn.ConnMeta.ofUser(identity, cred.credentialId(), resource);
    }

    /**
     * 在途保护: 用户自选模式的凭据在 Filter 阶段还不知道, 保护下移到工具层.
     * <p>
     * begin 在这里做 (拿到凭据后、用句柄前), end 交给 Filter 的 finally 统一收 —— 工具内
     * 提前 return / 抛异常的路径很多, 逐个 try/finally 迟早漏一条; 集合去重保证 begin/end 成对.
     * 固定资源模式的保护已在 Filter 做过, 这里不重复计数.
     */
    static void markInFlight(McpTransportContext ctx, long credentialId) {
        java.util.Set<Long> marked = McpRequestFilter.inFlight(ctx);
        if (marked != null && marked.add(credentialId)) {
            IdleReaper.begin(credentialId);
        }
    }

}
