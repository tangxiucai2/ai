package com.ai.mcp.policy;

import com.ai.mcp.config.ConsoleClient;
import com.ai.mcp.config.McpRequestFilter;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema;
import com.ai.mcp.policy.PolicyDecider.Decision;
import com.ai.mcp.policy.PolicyDecider.Kind;
import com.ai.mcp.policy.PolicyDecider.Source;
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
    private final ConsoleClient console;

    public PolicyGate(PolicyDecider decider, ConsoleClient console) {
        this.decider = decider;
        this.console = console;
    }

    /**
     * 判定一条 HOST 命令; 需要确认时在此阻塞等待用户点选
     *
     * @param tool 调用方工具名 (ssh_execute / ssh_execute_long_running), 第二部分随 /gate 请求体传给控制台展示
     * @return 判定结果, {@link Kind#ALLOW} 之外一律按拒绝处理
     */
    public Decision check(McpTransportContext ctx, McpSyncServerExchange exchange, String command, String tool) {
        ConsoleClient.Resolved cred = credential(ctx);
        if (cred == null) {
            return Decision.auth(Kind.DENY, "无法确定调用身份, 不能放行命令");
        }
        Decision decision = decider.decide(cred.agentId(), cred.dbType(), cred.hostId(), command);
        if (decision.kind() == Kind.APPROVAL) {
            return approval(ctx, decision, tool, command, cred);
        }
        if (decision.kind() == Kind.BOTH) {
            return confirmThenApproval(ctx, exchange, decision, tool, command, cred);
        }
        if (decision.kind() != Kind.CONFIRM) {
            return decision;
        }
        Decision verdict = confirm(exchange, command, decision);
        if (verdict.kind() == Kind.ALLOW) {
            // 用户已同意, 但等待期间(最长按控制台下发的确认超时)策略可能已经变严 —— 只信旧判定就可能放行一条
            // 已被新策略拒绝(甚至改成要管理员审批)的命令。用当前快照重新裁决一次:
            // 只在新结果比"确认放行"更严 (DENY/APPROVAL) 时才收回旧许可; 新结果仍是 ALLOW/CONFIRM
            // 说明许可没被削弱, 不用为同一件事再弹一次窗 (那样会形成确认死循环)
            Decision fresh = decider.decide(cred.agentId(), cred.dbType(), cred.hostId(), command);
            // （对现网问题的修订）fresh 升级为 APPROVAL 时必须走 /gate 建单, 不能像 DENY 那样直接
            // 把这条未处理的裁决原样当拒绝返回——那样永远不会调用 approvalGate(), 审批单压根建不出来,
            // 审计里还会显示成"策略拒绝"而不是"审批拦截" (二次确认期间策略被改成需要审批时的真实现网案例)
            // fresh 升级为 BOTH 时同样要走: 用户已经做完确认, 不需要再走 confirmThenApproval() 重弹一次
            if (fresh.kind() == Kind.APPROVAL || fresh.kind() == Kind.BOTH) {
                return approval(ctx, fresh, tool, command, cred);
            }
            if (fresh.kind() != Kind.ALLOW && fresh.kind() != Kind.CONFIRM) {
                verdict = fresh;
            }
        }
        // waited(): 这条判定在人工确认上阻塞过。等待期间凭据可能被撤权/过期,
        // 调用方用句柄前要重校验一次授权 —— 与「确认通过不再回头查白名单」不冲突, 查的是授权不是策略
        return verdict.waited();
    }

    /**
     * 二次确认 + 风险审批都要: decide() 判定为 BOTH 时走这里, 先 confirm() 再 approval()——
     * 先本人确认再管理员审批, 任一环节拒绝即终止 (设计文档 2026-09-18 §2.3)
     */
    private Decision confirmThenApproval(McpTransportContext ctx, McpSyncServerExchange exchange,
                                          Decision decision, String tool, String command, ConsoleClient.Resolved cred) {
        Decision verdict = confirm(exchange, command, decision);
        if (verdict.kind() != Kind.ALLOW) {
            // 确认失败/拒绝/超时/不支持: 终止, 不进入审批
            return verdict.waited();
        }
        // 与既有 CONFIRM 分支同款: 确认等待期间策略可能已变, 用当前快照重新裁决一次
        Decision fresh = decider.decide(cred.agentId(), cred.dbType(), cred.hostId(), command);
        if (fresh.kind() == Kind.APPROVAL || fresh.kind() == Kind.BOTH) {
            // 仍需要审批 (原样是 BOTH, 或被放宽成纯 APPROVAL 都要走): 用 fresh 走 /gate
            return approval(ctx, fresh, tool, command, cred).waited();
        }
        if (fresh.kind() != Kind.ALLOW && fresh.kind() != Kind.CONFIRM) {
            // 策略在等待期间被收紧到 DENY: 收回许可
            return fresh.waited();
        }
        // 降级为 ALLOW/CONFIRM (已经确认过一次, 不重复弹): 确认已完成, 直接放行
        return Decision.confirm(Kind.ALLOW, "发起人已确认", decision.policyLabel()).waited();
    }

    /**
     * 审批闸门 (第二部分): decide() 判定为 APPROVAL 时走这里, 立即返回 (不阻塞等待, 设计文档结论 1)——
     * 不占 CONFIRM_POOL, 这是一次短 HTTP 调用 (ConsoleClient 的 readTimeout 是 10s), 不是可能阻塞
     * 数十至数百秒 (控制台下发, 最长 300 秒) 的 elicitation
     * <p>
     * 也被 {@link #confirmThenApproval} 复用 (BOTH 模式确认通过后): 传入的 decision 可能来自 fresh 重新裁决,
     * kind() 可能是 APPROVAL 或 BOTH, 本方法内部不读 kind(), 只读 policyLabel/policyRevision/policyType 三个字段
     */
    private Decision approval(McpTransportContext ctx, Decision decision, String tool, String command, ConsoleClient.Resolved cred) {
        ConsoleClient.ResolvedUser identity = McpRequestFilter.userIdentity(ctx);
        Long userId = identity != null ? identity.userId() : null;
        String bareRequestId = McpRequestFilter.requestId(ctx);
        String fullRequestId = console.nodeId() + "-" + bareRequestId;
        String resource = cred.address() == null || cred.address().isBlank() ? "cred#" + cred.credentialId()
                : cred.address() + (cred.port() == null || cred.port() == 22 ? "" : ":" + cred.port());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("agentId", cred.agentId());
        body.put("agentCode", cred.agentCode());
        if (userId != null) {
            body.put("userId", userId);
        }
        body.put("userName", cred.userName());
        body.put("hostId", cred.hostId());
        // ponytail: connectionId 只是展示字段, 不参与指纹, 这里不额外把它从调用方的签名里穿进来
        body.put("resource", resource);
        body.put("credentialId", cred.credentialId());
        body.put("policyLabel", decision.policyLabel());
        body.put("policyRevision", decision.policyRevision());
        body.put("policyType", decision.policyType());
        body.put("tool", tool);
        body.put("operation", command);
        body.put("requestId", fullRequestId);
        body.put("clientRequestId", java.util.UUID.randomUUID().toString());

        ConsoleClient.ApprovalGateResult result;
        try {
            result = console.approvalGate(body);
        } catch (ConsoleClient.Rejected e) {
            return Decision.approval(Kind.DENY, e.getMessage(), decision.policyLabel());
        } catch (Exception e) {
            log.warn("审批闸门调用失败 policy={}: {}", decision.policyLabel(), e.toString());
            return Decision.approval(Kind.DENY, "审批服务不可达, 已暂停命令执行", decision.policyLabel());
        }

        // 必填字段缺失按响应异常处理, fail-closed (设计文档 §4.1 结尾): 不能只认 action 字段就放行,
        // 控制台版本不一致/序列化异常时不能是一条无校验的放行/展示通道 —— 按 action 各自的必填字段表逐个校验
        // （对本轮评审的修订：此前只校验了 ALLOW.approvalNo, PENDING/REJECTED 的必填字段没校验）
        String action = result.action() == null ? "" : result.action();
        boolean missing = switch (action) {
            case "ALLOW", "PENDING" -> result.id() == null || isBlank(result.approvalNo())
                    || ("PENDING".equals(action) && result.expireTimeMillis() == null);
            case "REJECTED" -> result.id() == null || isBlank(result.approvalNo())
                    || isBlank(result.comment()) || isBlank(result.approvedBy());
            default -> false;
        };
        if (missing) {
            return Decision.approval(Kind.DENY, "审批服务响应异常, 已暂停命令执行", decision.policyLabel());
        }

        switch (action) {
            case "ALLOW": {
                // fresh decide: 判据是 policyRevision 相等, 不是 kind() 归类 —— fresh 结果仍是 APPROVAL/BOTH
                // 完全可能是另一条策略的 (结论 18 要堵的正是这个), 按 kind() 归类会把刚绑上的
                // policyRevision 又绕开。其余一切结果一律拒绝执行, 即便凭证已被消费也不回退 (结论 21, §12 残留风险 4)
                // BOTH 也要纳入 (设计文档 2026-09-18 §0.5): confirmThenApproval() 通过 BOTH 走到这里时,
                // fresh 重新裁决出的仍是 BOTH 不是 APPROVAL —— 漏判会导致 BOTH 模式走完全部流程仍被拒绝
                Decision fresh = decider.decide(cred.agentId(), cred.dbType(), cred.hostId(), command);
                if ((fresh.kind() == Kind.APPROVAL || fresh.kind() == Kind.BOTH)
                        && decision.policyRevision().equals(fresh.policyRevision())) {
                    // .waited(): 复用既有 confirmWaited()/stillAuthorized() 机制堵撤权窗口 (结论 21 第二项) ——
                    // 用户自选模式下 /gate 那段 HTTP 往返期间凭据可能被撤权, 这里同样要求调用方用句柄前重校验一次授权
                    return Decision.approval(Kind.ALLOW, "经审批放行 " + result.approvalNo(), decision.policyLabel()).waited();
                }
                // 拒绝来源: 只有"fresh 仍判 APPROVAL/BOTH 只是内容变了"才算 Source.APPROVAL；fresh 变成标准
                // DENY/CONFIRM/ALLOW 时要保留它自己的 Source, 否则命中新黑名单这类真实策略拒绝会被审计
                // 误归类成"审批拦截" (设计文档 §7 表格第 373 行, 两种情形要分清)
                // policyLabel 同理改用 fresh 自己的标签 (对本轮评审的修订): decision.policyLabel() 是旧策略
                // 的标签, SshTool.policyReason() 会把它拼进审计原因 (auditError), 继续用旧标签会把"命中新
                // 黑名单"这类场景误归因到已经过时的旧策略
                Source denySource = (fresh.kind() == Kind.APPROVAL || fresh.kind() == Kind.BOTH) ? Source.APPROVAL : fresh.source();
                return new Decision(Kind.DENY, "凭证已消费但策略已变更, 已拒绝执行", fresh.policyLabel(), false, denySource, null, null, null, null);
            }
            case "PENDING":
                return Decision.approval(Kind.DENY,
                        "该命令需管理员审批, 已提交审批单 " + result.approvalNo()
                                + "。请勿修改命令内容——修改后需重新审批。审批通过后原样重试本命令即可执行。",
                        decision.policyLabel(), result.approvalNo(), "PENDING");
            case "REJECTED":
                // 处理人一并拼进文案 (设计文档 §10 验收清单第 5 条: "直接回拒绝意见 + 处理人"),
                // comment/approvedBy 已在上面的必填校验里保证非空, 不用再判空
                return Decision.approval(Kind.DENY,
                        "该命令已被拒绝执行 (单号 " + result.approvalNo() + ", 处理人: " + result.approvedBy()
                                + ", 理由: " + result.comment() + ")",
                        decision.policyLabel(), result.approvalNo(), "REJECTED");
            case "BUSY":
                // /gate 内部加锁失败 (设计文档 §4.2), 与"控制台不可达"是两种不同原因, 文案分开
                return Decision.approval(Kind.DENY, "审批服务繁忙, 请重试", decision.policyLabel());
            default:
                return Decision.approval(Kind.DENY, "审批服务响应异常, 已暂停命令执行", decision.policyLabel());
        }
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

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
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
        int timeout = console.confirmTimeoutSeconds();
        try {
            result = future.get(timeout, TimeUnit.SECONDS);
        } catch (java.util.concurrent.TimeoutException e) {
            // 超时: 撤掉等待, 但底层请求可能仍挂在客户端 — 由会话关闭或客户端作答回收
            future.cancel(true);
            log.info("二次确认超时 policy={} command={}", decision.policyLabel(), command);
            return Decision.confirm(Kind.DENY, "二次确认超时 (" + timeout + " 秒), 已拒绝执行", decision.policyLabel());
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
