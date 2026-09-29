package com.ai.mcp.tool;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import org.springaicommunity.mcp.annotation.McpTool;
import org.springaicommunity.mcp.annotation.McpToolParam;
import org.springframework.stereotype.Component;

import com.ai.mcp.audit.AuditLog;
import com.ai.mcp.config.ConsoleClient;
import com.ai.mcp.config.DbcClient;
import com.ai.mcp.config.McpRequestFilter;
import com.ai.mcp.policy.PolicyDecider;
import com.ai.mcp.policy.PolicyGate;

/**
 * 数据库工具: 不再直连数据库, 每条 SQL 经 DBC 解析 → 本地策略闸门 → DBC 执行 (设计文档 2026-09-29 §3.1)
 * <p>
 * 网关只持有连接的归属元数据与最新的 DBC 票据, 真正的数据库连接由 DBC 在首条 SQL 时按 connectId 懒建
 */
@Component
public class DatabaseTool {

    /** DBC 内部错误 / 不可达时回给智能体的固定文案 */
    static final String DBC_FAULT_MESSAGE = "DBC 内部错误, 请联系管理员";

    /** DBC 拒绝类错误: 审计记 DENIED, 来源 DBC; EXEC (数据库返回的 SQL 错误) 与 INTERNAL / 不可达记 FAILED */
    private static final Set<String> DBC_DENY_TYPES = Set.of("AUTH", "PARSE", "MULTI_STATEMENT", "UNSUPPORTED_OP",
            "UNSUPPORTED_DB_TYPE", "PARSE_MISMATCH", "CONN_LIMIT", "CONN_CLOSED");

    static final String DENY_SOURCE_DBC = "DBC";

    private static final String VERSION_MISMATCH = "控制台版本不匹配: 数据库凭据未返回 DBC 票据, 请升级控制台";

    /**
     * 网关侧的连接句柄: DBC 的 connectId + 最近一次拿到的票据 (关闭与空闲回收时要用它签名)
     */
    static final class DbcConn {
        final String connectId;
        private volatile ConsoleClient.DbcTicket ticket;

        DbcConn(String connectId, ConsoleClient.DbcTicket ticket) {
            this.connectId = connectId;
            this.ticket = ticket;
        }

        ConsoleClient.DbcTicket ticket() {
            return ticket;
        }

        /** 只换成更晚到期的票据: 并发请求不会把新票据覆盖回旧的 */
        synchronized void offer(ConsoleClient.DbcTicket t) {
            if (t != null && (ticket == null || t.expireAt() > ticket.expireAt())) {
                ticket = t;
            }
        }
    }

    private final AuditLog audit;
    private final PolicyGate gate;
    private final DbcClient dbc;
    private final ConsoleClient console;
    private final Map<String, Conn<DbcConn>> connections = new ConcurrentHashMap<>();
    private final IdleReaper<DbcConn> reaper;

    public DatabaseTool(AuditLog audit, PolicyGate gate, DbcClient dbc, ConsoleClient console) {
        this.audit = audit;
        this.gate = gate;
        this.dbc = dbc;
        this.console = console;
        // 空闲回收时通知 DBC 释放连接; 票据若已过期 DBC 回 AUTH, 由 DBC 自己的空闲回收兜底
        this.reaper = new IdleReaper<>("db-idle-reaper", connections, this::closeQuietly);
        // 固定资源模式续签被拒 (撤权/过期/禁用): 主动关掉该凭据在本节点的全部连接
        console.credentialRevoked(this::revokeCredential);
    }

    @McpTool(name = "db_create_connection", description = "Create a new database connection handle. "
            + "The database session is opened lazily by the audit service on the first SQL. "
            + "When the request carries a virtual credential the target is fixed and credentialId is ignored; "
            + "otherwise pass a credentialId obtained from list_credentials")
    public Map<String, Object> db_create_connection(
            @McpToolParam(description = "Credential ID from list_credentials (omit when the request is bound to a fixed credential)", required = false) Long credentialId,
            McpTransportContext ctx) {
        return audit.run(ctx, "db_create_connection", null, "connect", () -> db_create_connection0(credentialId, ctx));
    }

        private Map<String, Object> db_create_connection0(Long credentialId, McpTransportContext ctx) {
        Map<String, Object> result = new HashMap<>();
        ConsoleClient.Resolved cred;
        try {
            // 固定资源模式忽略入参; 用户自选模式按 credentialId 回控制台换凭据 (服务端重新校验授权)
            cred = ToolAuth.resolveForTools(ctx, credentialId);
        } catch (ConsoleClient.Rejected e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            // 控制台明确拒绝记为授权拒绝 (审计 DENIED/AUTH), 不可达走下面的故障分支
            result.put("denySource", PolicyDecider.Source.AUTH.name());
            return result;
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", "控制台不可达, 无法校验凭据授权");
            return result;
        }
        if (cred == null) {
            result.put("success", false);
            result.put("error", "未指定凭据, 请先调用 list_credentials 获取可用凭据列表, 再用其中的 credentialId 重试");
            return result;
        }
        if (!"DATABASE".equals(cred.category())) {
            result.put("success", false);
            result.put("error", "该凭据不是数据库资源");
            return result;
        }
        if (!dbc.configured()) {
            result.put("success", false);
            result.put("error", "未配置 dbc.base-url, 数据库工具不可用");
            return result;
        }
        if (cred.dbc() == null) {
            result.put("success", false);
            result.put("error", VERSION_MISMATCH);
            return result;
        }
        // 节点句柄总量闸门 (控制台下发 maxConnections, 未配置不限)
        if (IdleReaper.atLimit()) {
            result.put("success", false);
            result.put("error", "节点连接数已达上限, 请稍后重试或释放空闲连接");
            return result;
        }
        // 单资源闸门 (跨凭据合并计数: 同一个实例不论哪个账号登录都算在一起)
        String resource = cred.address() + ":" + cred.port();
        if (IdleReaper.atResourceLimit(resource)) {
            result.put("success", false);
            result.put("error", "该资源连接数已达上限, 请稍后重试或释放空闲连接");
            return result;
        }
        // 句柄按凭据隔离: credentialId 前缀, 其他凭据的 connectionId 一律"不存在";
        // DBC 侧 connectId 固定格式 agent_{credentialId}_{32hex}, 与票据里的 credentialId 对不上 DBC 直接拒
        UUID uuid = UUID.randomUUID();
        String connectionId = cred.credentialId() + ":" + uuid;
        String connectId = "agent_" + cred.credentialId() + "_" + uuid.toString().replace("-", "");
        // 归属元数据与句柄一次 put, 不留「有句柄无归属」的窗口
        connections.put(connectionId, new Conn<>(new DbcConn(connectId, cred.dbc()), ToolAuth.metaOf(ctx, cred, resource)));
        reaper.register(connectionId);
        ToolAuth.markInFlight(ctx, cred.credentialId());
        result.put("success", true);
        result.put("connectionId", connectionId);
        result.put("dbType", cred.dbType());
        result.put("message", "Connection created successfully");
        return result;
    }

    /**
     * 归属校验: 先比本地四元组 (模式/智能体/用户), 用户模式再回控制台按连接元数据里的 credentialId 重校验授权
     * <p>
     * 本次重校验被控制台明确拒绝时在 result 标记授权拒绝 (审计 DENIED/AUTH) 并主动关闭该连接;
     * 不可达/本地不存在不标, 按失败记
     */
    private Conn<DbcConn> lookup(String connectionId, McpTransportContext ctx, Map<String, Object> result) {
        if (connectionId == null) {
            return null;
        }
        // 先只读校验, 校验通过才 acquire 续期: 被拒的调用不能给连接续命
        Conn<DbcConn> conn = reaper.peek(connectionId);
        if (conn == null || !conn.meta().accessibleBy(ctx)) {
            return null;
        }
        ToolAuth.Check c = ToolAuth.check(ctx, conn.meta());
        if (c.verdict() != ToolAuth.Verdict.ALLOW) {
            if (c.verdict() == ToolAuth.Verdict.DENY) {
                result.put("denySource", PolicyDecider.Source.AUTH.name());
                revoke(connectionId);
            }
            // 报本次原因, 不取请求级 DENY_REASON (首写, 会串成同一请求里前一次的原因)
            result.put("error", ToolAuth.notFound(connectionId, c));
            return null;
        }
        Conn<DbcConn> live = reaper.acquire(connectionId);
        if (live == null) {
            return null;
        }
        // 用句柄前进入在途保护: 超过空闲阈值的长 SQL 不会被回收器掐断
        ToolAuth.markInFlight(ctx, live.meta().credentialId());
        return live;
    }

    /**
     * 取可用的 DBC 票据: 先吸收本次请求已解析出的凭据里的票据 (Filter 或用户模式重校验拿到的, 至少一样新),
     * 快到期 (不足 60s) 再回控制台续签 —— 确认/审批等待可能长达数分钟, 请求开始时的票据未必还活着
     * <p>
     * 续签被明确拒绝 = 撤权, 主动关闭该连接并按授权拒绝记; 控制台不可达按失败记
     *
     * @return 票据; 取不到时返回 null, 原因已写进 result
     */
    private ConsoleClient.DbcTicket ticket(String connectionId, Conn<DbcConn> conn, McpTransportContext ctx,
                                           Map<String, Object> result) {
        ConsoleClient.Resolved cur = McpRequestFilter.resolved(ctx);
        if (cur == null) {
            cur = McpRequestFilter.credential(ctx);
        }
        if (cur != null && cur.credentialId() == conn.meta().credentialId()) {
            conn.handle().offer(cur.dbc());
        }
        ConsoleClient.DbcTicket t = conn.handle().ticket();
        if (t != null && !t.expiring(System.currentTimeMillis())) {
            return t;
        }
        ConsoleClient.Resolved fresh;
        try {
            fresh = renew(ctx, conn.meta());
        } catch (ConsoleClient.Rejected e) {
            revoke(connectionId);
            result.put("success", false);
            result.put("error", e.getMessage());
            result.put("denySource", PolicyDecider.Source.AUTH.name());
            return null;
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", ToolAuth.CONSOLE_UNAVAILABLE);
            return null;
        }
        if (fresh == null || fresh.dbc() == null) {
            result.put("success", false);
            result.put("error", fresh == null ? ToolAuth.CONSOLE_UNAVAILABLE : VERSION_MISMATCH);
            return null;
        }
        conn.handle().offer(fresh.dbc());
        return conn.handle().ticket();
    }

    /** 按连接的模式回控制台换新票据: 固定资源模式走 resolve (快到期时绕过缓存), 用户模式走 resolve-credential */
    private ConsoleClient.Resolved renew(McpTransportContext ctx, Conn.ConnMeta meta) throws Exception {
        String peerIp = McpRequestFilter.peerIp(ctx);
        if (Conn.MODE_USER.equals(meta.authMode())) {
            ConsoleClient.ResolvedUser identity = McpRequestFilter.userIdentity(ctx);
            String userToken = McpRequestFilter.userToken(ctx);
            if (identity == null || userToken == null) {
                return null;
            }
            return console.resolveCredential(identity.agentCode(), userToken, meta.credentialId(), identity.userName(), peerIp);
        }
        ConsoleClient.Resolved cred = McpRequestFilter.credential(ctx);
        String token = McpRequestFilter.virtualToken(ctx);
        if (cred == null || token == null) {
            return null;
        }
        return console.resolve(cred.agentCode(), token, cred.userName(), peerIp);
    }

    /** 撤权/关闭: 以原子 remove 的返回值决定谁负责通知 DBC, 与 sweep/并发关闭不会重复关 */
    private void revoke(String connectionId) {
        Conn<DbcConn> removed = connections.remove(connectionId);
        if (removed != null) {
            // 撤权路径在请求线程或控制台回调里, 不为 DBC 往返阻塞
            CompletableFuture.runAsync(() -> closeQuietly(removed.handle()));
        }
    }

    /** 固定资源模式续签被拒: 只关同一智能体、同一凭据、固定资源模式建的连接 */
    private void revokeCredential(long agentId, long credentialId) {
        for (Map.Entry<String, Conn<DbcConn>> e : connections.entrySet()) {
            Conn.ConnMeta m = e.getValue().meta();
            if (Conn.MODE_CREDENTIAL.equals(m.authMode()) && m.agentId() == agentId && m.credentialId() == credentialId) {
                revoke(e.getKey());
            }
        }
    }

    private void closeQuietly(DbcConn c) {
        ConsoleClient.DbcTicket t = c.ticket();
        if (t != null && dbc.configured()) {
            dbc.close(t, c.connectId);
        }
    }

    @McpTool(name = "db_close_connection", description = "Close an existing database connection")
    public Map<String, Object> db_close_connection(
            @McpToolParam(description = "Connection ID to close") String connectionId, McpTransportContext ctx) {
        return audit.run(ctx, "db_close_connection", connectionId, "disconnect", () -> db_close_connection0(connectionId, ctx));
    }

        private Map<String, Object> db_close_connection0(String connectionId, McpTransportContext ctx) {
        Map<String, Object> result = new HashMap<>();

        Conn<DbcConn> conn = lookup(connectionId, ctx, result);
        // 以原子 remove 的返回值决定谁负责关闭: 与 sweep/异常清理并发时不会重复关
        Conn<DbcConn> removed = conn == null ? null : connections.remove(connectionId);
        if (removed == null) {
            result.put("success", false);
            result.putIfAbsent("error", ToolAuth.notFound(connectionId, null));
            return result;
        }
        // 用本次请求带来的新票据关, 旧票据可能已过期; 本地句柄已摘除, DBC 关失败也由它自己的空闲回收兜底
        ConsoleClient.Resolved cur = McpRequestFilter.resolved(ctx);
        if (cur == null) {
            cur = McpRequestFilter.credential(ctx);
        }
        if (cur != null && cur.credentialId() == removed.meta().credentialId()) {
            removed.handle().offer(cur.dbc());
        }
        ConsoleClient.DbcTicket t = removed.handle().ticket();
        DbcClient.Result r = t == null ? null : dbc.close(t, removed.handle().connectId);
        result.put("success", true);
        result.put("message", "Connection closed successfully");
        if (r == null || !r.ok()) {
            result.put("warning", "数据库会话未能即时释放, 将由服务端空闲回收");
        }
        return result;
    }

    @McpTool(name = "db_list_connections", description = "List all valid database connections")
    public Map<String, Object> db_list_connections(McpTransportContext ctx) {
        Map<String, Object> result = new HashMap<>();
        List<String> validConnections = new ArrayList<>();
        // 本工具不走 lookup, 归属过滤必须自己做一遍 (否则可枚举他人连接)
        for (Map.Entry<String, Conn<DbcConn>> entry : connections.entrySet()) {
            if (!entry.getValue().meta().accessibleBy(ctx)) {
                continue;
            }
            // 明确撤权才跳过; 校验故障整体报错, 否则客户端会把"授权服务挂了"当成"没有连接"而重复建连
            ToolAuth.Verdict v = ToolAuth.verdict(ctx, entry.getValue().meta());
            if (v == ToolAuth.Verdict.UNAVAILABLE) {
                result.put("success", false);
                result.put("error", ToolAuth.CONSOLE_UNAVAILABLE);
                return result;
            }
            if (v == ToolAuth.Verdict.ALLOW) {
                validConnections.add(entry.getKey());
            }
        }

        result.put("success", true);
        result.put("connections", validConnections);
        result.put("count", validConnections.size());
        return result;
    }

    @McpTool(name = "db_execute", description = "Execute exactly one SQL statement. "
            + "Multiple statements and transactions are not supported; each statement is committed on its own. "
            + "Query results return at most maxRows rows (default and upper limit 1000); "
            + "truncated=true in the result means more rows exist, so narrow the query (WHERE / LIMIT) instead of relying on the partial rows")
    public Map<String, Object> db_execute(
            @McpToolParam(description = "Connection ID") String connectionId,
            @McpToolParam(description = "One SQL statement to execute") String sql,
            @McpToolParam(description = "Maximum rows to return for a query (optional, capped at 1000)", required = false) Integer maxRows,
            McpTransportContext ctx, McpSyncServerExchange exchange) {
        return audit.run(ctx, "db_execute", connectionId, sql, () -> db_execute0(connectionId, sql, maxRows, ctx, exchange));
    }

        private Map<String, Object> db_execute0(String connectionId, String sql, Integer maxRows, McpTransportContext ctx,
                                                McpSyncServerExchange exchange) {
        Map<String, Object> result = new HashMap<>();

        Conn<DbcConn> conn = lookup(connectionId, ctx, result);
        if (conn == null) {
            result.put("success", false);
            result.putIfAbsent("error", ToolAuth.notFound(connectionId, null));
            return result;
        }
        if (!dbc.configured()) {
            result.put("success", false);
            result.put("error", "未配置 dbc.base-url, 数据库工具不可用");
            return result;
        }
        ConsoleClient.DbcTicket t = ticket(connectionId, conn, ctx, result);
        if (t == null) {
            return result;
        }
        String connectId = conn.handle().connectId;

        // 1. DBC 解析: op / tables / defaultNamespace 以 DBC 为准, 网关不自己解析 SQL
        DbcClient.Result parsed = dbc.parse(t, connectId, sql);
        if (!parsed.ok()) {
            return dbcError(result, parsed, connectionId);
        }
        Map<String, Object> p = parsed.data();
        String op = p.get("op") instanceof String s ? s : null;
        List<?> rawTables = p.get("tables") instanceof List<?> l ? l : null;
        List<String> tables = new ArrayList<>();
        if (rawTables != null) {
            rawTables.forEach(o -> tables.add(String.valueOf(o)));
        }
        String ns = p.get("defaultNamespace") instanceof String s ? s : null;
        // 解析通过后, 拒绝与执行都带上 op / tables 进审计 (AuditLog 读完即摘掉, 不外传)
        result.put(AuditLog.AUDIT_OP, op);
        result.put(AuditLog.AUDIT_TABLES, tables);

        // 2-3. 策略裁决 + 确认/审批闸门 (用户模式的凭据含 hostId, 是 lookup 重校验时才拿到的)
        Deny denied = policyDeny(gate.checkDatabase(ctx, exchange, sql, op, tables, ns, "db_execute"), connectionId, ctx);
        if (denied != null) {
            result.put("success", false);
            result.put("error", denied.reason());
            // 来源为 null 是复检故障 (不可达/句柄失效), 不标拒绝, 审计按失败记
            if (denied.source() != null) {
                result.put("denySource", denied.source().name());
                result.put("auditError", denied.auditReason());
            }
            if (denied.approvalNo() != null) {
                result.put("approvalNo", denied.approvalNo());
                result.put("approvalStatus", denied.approvalStatus());
            }
            return result;
        }
        // 确认/审批可能等了几分钟, 执行前再确认一次票据还活着
        t = ticket(connectionId, conn, ctx, result);
        if (t == null) {
            return result;
        }

        // 4. 执行: DBC 重新解析并与 digest/op/tables 逐项比对, 不一致回 PARSE_MISMATCH
        DbcClient.Result exec = dbc.execute(t, connectId, sql, (String) p.get("sqlDigest"), op, rawTables,
                maxRows == null || maxRows <= 0 ? null : maxRows);
        // 限流只计真正到了数据库的调用: 成功或数据库返回 SQL 错误 (EXEC) 都算执行过; DBC 拒绝/不可达不占配额
        if (exec.ok() || "EXEC".equals(exec.errorType())) {
            gate.recordDatabaseRate(ctx);
        }
        if (!exec.ok()) {
            return dbcError(result, exec, connectionId);
        }
        Map<String, Object> d = exec.data();
        boolean truncated = Boolean.TRUE.equals(d.get("truncated"));
        List<?> headers = d.get("headers") instanceof List<?> h ? h : List.of();
        result.put("success", true);
        result.put("truncated", truncated);
        if (!headers.isEmpty()) {
            List<?> rows = d.get("rows") instanceof List<?> r ? r : List.of();
            result.put("type", "query");
            result.put("columns", headers);
            result.put("rows", rows);
            result.put("rowCount", rows.size());
        } else {
            // DDL 与驱动报 -1 / 不报的一律记 0 (设计文档 §3.4 lines 口径)
            long affected = d.get("affectedRows") instanceof Number n && n.longValue() > 0 ? n.longValue() : 0;
            result.put("type", "update");
            result.put("affectedRows", affected);
            result.put("message", "Successfully updated " + affected + " rows");
        }
        return result;
    }

    /**
     * DBC 错误 → 工具结果: 拒绝类记 DENIED/DBC, EXEC 是数据库返回的 SQL 错误, INTERNAL / 不可达是故障, 都记 FAILED
     * <p>
     * CONN_CLOSED: DBC 那边连接已作废 (超时作废/空闲回收/已关闭), 本地元数据一并丢掉, 让智能体重新建连
     */
    private Map<String, Object> dbcError(Map<String, Object> result, DbcClient.Result r, String connectionId) {
        String type = r.errorType();
        result.put("success", false);
        if (DBC_DENY_TYPES.contains(type)) {
            result.put("denySource", DENY_SOURCE_DBC);
            if ("CONN_CLOSED".equals(type)) {
                connections.remove(connectionId);
                result.put("error", "连接已失效, 请重新调用 db_create_connection 建立连接 (" + r.message() + ")");
            } else {
                result.put("error", "DBC 拒绝执行 [" + type + "]: " + r.message());
            }
        } else if ("EXEC".equals(type)) {
            result.put("error", "SQL execution error: " + r.message());
        } else if ("INTERNAL".equals(type) || DbcClient.UNREACHABLE.equals(type)) {
            // INTERNAL / 不可达: 详情可能带 DBC 内部异常或网络地址, 只进审计; 回给智能体的是固定文案
            result.put("error", DBC_FAULT_MESSAGE);
            result.put("auditError", ("INTERNAL".equals(type) ? "DBC 内部错误: " : "") + r.message());
        } else {
            result.put("error", r.message());
        }
        return result;
    }

    /**
     * 拒绝原因 + 来源环节, 与 SshTool 同口径
     *
     * @param reason      对外理由, 回给调用方; 不含策略名与规则摘要
     * @param auditReason 审计理由, 带命中策略标签, 只进 auditError 不外传
     */
    private record Deny(String reason, String auditReason, PolicyDecider.Source source, String approvalNo, String approvalStatus) {
    }

    /**
     * 策略判定 → 拒绝原因; 通过返回 null
     * <p>
     * 等过人工确认/审批的判定要再校验一次授权 (与 SshTool 同): 用户模式回控制台重校验, 被撤归 AUTH;
     * 复检时控制台不可达或句柄已失效是故障, 来源为 null 按失败记
     */
    private Deny policyDeny(PolicyDecider.Decision decision, String connectionId, McpTransportContext ctx) {
        if (decision.kind() != PolicyDecider.Kind.ALLOW) {
            String label = decision.policyLabel();
            String auditReason = label == null ? decision.reason() : decision.reason() + " [策略: " + label + "]";
            return new Deny(decision.reason(), auditReason, decision.source(), decision.approvalNo(), decision.approvalStatus());
        }
        if (decision.confirmWaited()) {
            Conn<DbcConn> conn = reaper.peek(connectionId);
            ToolAuth.Check c = conn == null || !conn.meta().accessibleBy(ctx) ? null : ToolAuth.check(ctx, conn.meta());
            if (c == null || c.verdict() != ToolAuth.Verdict.ALLOW) {
                if (c != null && c.verdict() == ToolAuth.Verdict.DENY) {
                    revoke(connectionId);
                }
                String reason = ToolAuth.notFound(connectionId, c);
                return new Deny(reason, reason, c != null && c.verdict() == ToolAuth.Verdict.DENY ? PolicyDecider.Source.AUTH : null, null, null);
            }
        }
        return null;
    }
}
