package com.ai.mcp.policy;

import com.ai.mcp.config.ConsoleClient;
import com.ai.mcp.config.McpRequestFilter;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema;
import com.ai.mcp.policy.PolicyDecider.Decision;
import com.ai.mcp.policy.PolicyDecider.Kind;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * 策略闸门: 工具执行前的最后一道判定 + 二次确认
 * <p>
 * 二次确认走 MCP 协议级 elicitation (客户端弹给用户, 网关等结果), 不是控制台页面 ——
 * 所以控制台不参与确认动作, 只负责下发策略.
 * <p>
 * 客户端没声明 elicitation 能力时<b>自动拒绝</b>, 不降级为放行: 降级等于把"本该有人看着"的命令
 * 变成无人确认直接执行.
 */
@Component
public class PolicyGate {

    private static final Logger log = LoggerFactory.getLogger(PolicyGate.class);

    /**
     * 确认超时: 超时按拒绝处理, 否则客户端不响应会永久占住线程
     * <p>
     * 必须小于 spring.ai.mcp.server.request-timeout (默认 20s!): SDK 用它限出站请求,
     * 配小了就是 SDK 先抛异常, 这里成了死代码. application.yml 里已调到 130s
     */
    private static final long CONFIRM_TIMEOUT_SEC = 120;

    /**
     * 确认等待是有界的: 16 路并发, 队列再攒 32 个, 之后直接拒绝
     * <p>
     * 不用 Executors.newFixedThreadPool —— 它的队列是无界的, submit 永远不会被拒, 池满只会无限积压
     * ponytail: 16+32 是拍脑袋的上限; 真被打满要看日志, 按会话数放大或按智能体分池
     */
    private static final int CONFIRM_MAX = 16;
    private static final ExecutorService CONFIRM_POOL = new ThreadPoolExecutor(
            CONFIRM_MAX, CONFIRM_MAX, 0L, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(32),
            r -> {
                Thread t = new Thread(r, "policy-confirm");
                t.setDaemon(true);
                return t;
            },
            new ThreadPoolExecutor.AbortPolicy());

    private final PolicyDecider decider;

    public PolicyGate(PolicyDecider decider) {
        this.decider = decider;
    }

    /**
     * 判定一条 HOST 命令; 需要确认时在此阻塞等待用户点选
     *
     * @return 判定结果, {@link Kind#ALLOW} 之外一律按拒绝处理
     */
    public Decision check(McpTransportContext ctx, McpSyncServerExchange exchange, String command) {
        ConsoleClient.Resolved cred = credential(ctx);
        if (cred == null) {
            return Decision.auth(Kind.DENY, "无法确定调用身份, 不能放行命令");
        }
        Decision decision = decider.decide(cred.agentId(), cred.dbType(), cred.hostId(), command);
        if (decision.kind() != Kind.CONFIRM) {
            return decision;
        }
        Decision verdict = confirm(exchange, command, decision);
        if (verdict.kind() == Kind.ALLOW) {
            // 用户已同意, 但等待期间(最长 120 秒)策略可能已经变严 —— 只信旧判定就可能放行一条
            // 已被新策略拒绝(甚至改成要管理员审批)的命令。用当前快照重新裁决一次:
            // 只在新结果比"确认放行"更严 (DENY/APPROVAL) 时才收回旧许可; 新结果仍是 ALLOW/CONFIRM
            // 说明许可没被削弱, 不用为同一件事再弹一次窗 (那样会形成确认死循环)
            Decision fresh = decider.decide(cred.agentId(), cred.dbType(), cred.hostId(), command);
            if (fresh.kind() != Kind.ALLOW && fresh.kind() != Kind.CONFIRM) {
                verdict = fresh;
            }
        }
        // waited(): 这条判定在人工确认上阻塞过。等待期间凭据可能被撤权/过期,
        // 调用方用句柄前要重校验一次授权 —— 与「确认通过不再回头查白名单」不冲突, 查的是授权不是策略
        return verdict.waited();
    }

    /**
     * 放行执行时记账, 由调用方在**真的要执行**时调用 (不是判定为 ALLOW 就调)
     * <p>
     * 限流配额只计"真正执行的调用"(结论 16): 等过确认的调用还要过工具层的授权复检, 复检没过就不会
     * 真的执行 —— 在 {@link #check} 判定为 ALLOW 那一刻就记账, 会把没执行的调用也算进配额
     */
    public void recordRate(McpTransportContext ctx) {
        ConsoleClient.Resolved cred = credential(ctx);
        if (cred != null) {
            decider.recordRate(cred.agentId(), cred.dbType(), cred.hostId());
        }
    }

    /** 已解析出的凭据优先 (用户自选模式在建连/重校验时才拿得到), 再退回请求级凭据 */
    private static ConsoleClient.Resolved credential(McpTransportContext ctx) {
        ConsoleClient.Resolved resolved = McpRequestFilter.resolved(ctx);
        return resolved != null ? resolved : McpRequestFilter.credential(ctx);
    }

    private Decision confirm(McpSyncServerExchange exchange, String command, Decision decision) {
        if (exchange == null || !supportsElicitation(exchange)) {
            return Decision.confirm(Kind.DENY, "该客户端不支持人工二次确认, 已拒绝执行", decision.policyLabel());
        }
        McpSchema.ElicitResult result;
        Future<McpSchema.ElicitResult> future;
        try {
            future = CONFIRM_POOL.submit(() -> exchange.createElicitation(request(command, decision.policyLabel())));
        } catch (Exception e) {
            return Decision.confirm(Kind.DENY, "二次确认通道繁忙, 已拒绝执行", decision.policyLabel());
        }
        try {
            result = future.get(CONFIRM_TIMEOUT_SEC, TimeUnit.SECONDS);
        } catch (java.util.concurrent.TimeoutException e) {
            // 超时: 撤掉等待, 但底层请求可能仍挂在客户端 — 由会话关闭或客户端作答回收
            future.cancel(true);
            log.info("二次确认超时 policy={} command={}", decision.policyLabel(), command);
            return Decision.confirm(Kind.DENY, "二次确认超时 (" + CONFIRM_TIMEOUT_SEC + " 秒), 已拒绝执行", decision.policyLabel());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Decision.confirm(Kind.DENY, "二次确认被中断, 已拒绝执行", decision.policyLabel());
        } catch (Exception e) {
            log.warn("二次确认失败 policy={}: {}", decision.policyLabel(), e.toString());
            return Decision.confirm(Kind.DENY, "二次确认失败, 已拒绝执行", decision.policyLabel());
        }
        return verdict(result, decision);
    }

    private static Decision verdict(McpSchema.ElicitResult result, Decision decision) {
        McpSchema.ElicitResult.Action action = result == null ? null : result.action();
        if (action == McpSchema.ElicitResult.Action.ACCEPT) {
            Object approve = result.content() == null ? null : result.content().get(FIELD);
            // 用户勾了拒绝 (客户端把表单原样回传的场景) 也算拒绝
            if (Boolean.FALSE.equals(approve)) {
                return Decision.confirm(Kind.DENY, "发起人已拒绝执行该命令", decision.policyLabel());
            }
            // 只认显式 true: 客户端不可信, 不能指望它按 requestedSchema 校验 —— 缺字段 / null / 类型不对
            // 一律当"没确认过". 否则一个不回内容的客户端就是一条自动放行通道, 整个闸门白设
            if (!Boolean.TRUE.equals(approve)) {
                return Decision.confirm(Kind.DENY, "未取得明确的确认结果, 已拒绝执行", decision.policyLabel());
            }
            // 确认通过即终局放行, 不再回头查白名单
            return Decision.confirm(Kind.ALLOW, "发起人已确认", decision.policyLabel());
        }
        String why = action == McpSchema.ElicitResult.Action.DECLINE ? "发起人已拒绝执行该命令"
                : action == McpSchema.ElicitResult.Action.CANCEL ? "发起人已取消确认" : "未取得确认结果";
        return Decision.confirm(Kind.DENY, why, decision.policyLabel());
    }

    private static final String FIELD = "approve";

    /** 客户端未声明 elicitation 能力时不得发请求 (MCP 协议规定), 这里直接拒 */
    private static boolean supportsElicitation(McpSyncServerExchange exchange) {
        try {
            McpSchema.ClientCapabilities caps = exchange.getClientCapabilities();
            return caps != null && caps.elicitation() != null;
        } catch (Exception e) {
            return false;
        }
    }

    /** 弹窗正文: 完整命令原文 —— 参数不做自动规则, 交给本人看着点 */
    private static McpSchema.ElicitRequest request(String command, String policyLabel) {
        Map<String, Object> properties = new LinkedHashMap<>();
        Map<String, Object> approve = new LinkedHashMap<>();
        approve.put("type", "boolean");
        approve.put("title", "允许执行");
        approve.put("description", "勾选后仅放行本次调用");
        properties.put(FIELD, approve);

        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", properties);
        schema.put("required", java.util.List.of(FIELD));

        return McpSchema.ElicitRequest.builder()
                .message("智能体请求在目标主机执行以下命令, 请确认是否允许:\n\n" + command
                        + "\n\n命中策略: " + policyLabel + "\n未确认或拒绝都会阻止执行。")
                .requestedSchema(schema)
                .build();
    }
}
