package com.ai.mcp.audit;

import com.ai.mcp.config.ConsoleClient;
import com.ai.mcp.config.McpRequestFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.common.McpTransportContext;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/**
 * 工具调用审计: 每次 tools/call 记一条 (谁/哪个智能体/对哪个资源/做了什么/多久/结果), 同时打一行 app.log
 * <p>
 * 内存环形 10000 条供节点自查 (重启即清); 每条同时写入 AuditSpool 上报控制台落 CK 持久化
 */
@Component
public class AuditLog {

    private static final Logger log = LoggerFactory.getLogger(AuditLog.class);
    private static final int MAX = 10_000;
    private static final int SUMMARY_MAX = 4000;
    private static final int LOG_SUMMARY_MAX = 200;

    private static final int ERROR_MAX = 1000;
    private static final int RESULT_MAX = 2000;

    public static final String SUCCESS = "SUCCESS";
    public static final String FAILED = "FAILED";
    public static final String DENIED = "DENIED";

    private final ArrayDeque<Entry> ring = new ArrayDeque<>();
    private final AuditSpool spool;
    private final ObjectMapper json;
    private final ConsoleClient console;
    private final AtomicInteger seq = new AtomicInteger();

    public AuditLog(AuditSpool spool, ObjectMapper json, ConsoleClient console) {
        this.spool = spool;
        this.json = json;
        this.console = console;
    }

    /** 节点自身事件 (注册/心跳/审计上报) 由 ConsoleClient 与 AuditSpool 经此回调进环 */
    @PostConstruct
    void registerNodeAudit() {
        console.nodeAudit(this::node);
    }

    /**
     * 节点自身事件: 只进内存环与 app.log, 不上报控制台 —— CK 那张表是智能体调用日志,
     * 混入节点运维事件会污染「今日调用」统计
     */
    public void node(String status, String summary) {
        String s = summary == null ? "" : cut(summary, SUMMARY_MAX);
        add(new Entry(System.currentTimeMillis(), "-", "-", "node", "节点", "-", s, 0, status, null, null));
    }

    public record Entry(long time, String agent, String user, String tool, String type, String resource,
                        String summary, long costMs, String status, String error, String connectionId) {
    }

    /** 上报控制台的事件 (比 Entry 多身份/结果字段) */
    private record Event(String id, String connectionId, long time, long costMs, Long agentId, String agentCode, Long credentialId,
                         String userName, String userId, String srcIp, String tool, String type, String status,
                         String summary, String result, Integer lines, String error) {
    }

    /**
     * 包裹工具调用: 按返回 Map 的 success 判定状态; connectionId 为空时取返回值里的 connectionId (连接类工具)
     */
    public Map<String, Object> run(McpTransportContext ctx, String tool, String connectionId, String summary,
                                   Supplier<Map<String, Object>> call) {
        ConsoleClient.Resolved cred = McpRequestFilter.credential(ctx);
        // 用户自选模式没有请求级凭据, 身份取 resolve-user 的可信结果 (审计不能因此丢智能体与用户)
        ConsoleClient.ResolvedUser identity = McpRequestFilter.userIdentity(ctx);
        McpTransportContext auditCtx = ctx;
        String srcIp = ctx == null ? null : (String) ctx.get(McpRequestFilter.SRC_IP);
        String userId = ctx == null ? null : (String) ctx.get(McpRequestFilter.USER_ID);
        long t0 = System.currentTimeMillis();
        Map<String, Object> r;
        try {
            r = call.get();
        } catch (RuntimeException e) {
            record(pick(cred, auditCtx), identity, srcIp, userId, tool, summary, t0, FAILED, e.toString(), connectionId, null, null);
            throw e;
        }
        // SSH 命令: 工具协议里非零退出码仍 success=true, 审计按退出码判失败并保留 stderr
        Object exit = r == null ? null : r.get("exitCode");
        boolean nonZero = exit instanceof Integer && (Integer) exit != 0;
        boolean ok = r != null && Boolean.TRUE.equals(r.get("success")) && !nonZero;
        String cid = connectionId != null || r == null ? connectionId : (String) r.get("connectionId");
        String error = ok || r == null ? null
                : nonZero ? "exit=" + exit + (r.get("errorOutput") == null ? "" : " " + r.get("errorOutput"))
                : String.valueOf(r.get("error"));
        Object[] res = resultOf(tool, r);
        record(pick(cred, auditCtx), identity, srcIp, userId, tool, summary, t0, ok ? SUCCESS : FAILED, error, cid, (String) res[0], (Integer) res[1]);
        return r;
    }

    /** 鉴权链拒绝 (节点未启用 / Token / 缺头 / 控制台拒绝 / 不可达) */
    public void denied(String agent, String user, String reason, String srcIp, String userId) {
        long now = System.currentTimeMillis();
        add(new Entry(now, line(dash(agent)), line(dash(user)), "auth", "鉴权", "-", reason, 0, DENIED, reason, null));
        spool(new Event(nextId(now), null, now, 0, null, agent, null, user, userId, srcIp, "auth", "denied", DENIED, reason, null, null, reason));
    }

    /** 工具返回值 → 结果摘要 + 行数: SSH 取 stdout 前 2000 字与行数; SQL 查询取行数/列; 更新取影响行数; 事务取语句数/影响行数 */
    @SuppressWarnings("unchecked")
    private static Object[] resultOf(String tool, Map<String, Object> r) {
        if (r == null) {
            return new Object[]{null, null};
        }
        Object out = r.get("output");
        if (out instanceof String s) {
            int lines = s.isEmpty() ? 0 : (int) s.chars().filter(c -> c == '\n').count() + (s.endsWith("\n") ? 0 : 1);
            return new Object[]{cut(s, RESULT_MAX), lines};
        }
        if (r.get("rowCount") instanceof Number n) {
            return new Object[]{cut("rowCount=" + n + " columns=" + r.get("columns"), RESULT_MAX), n.intValue()};
        }
        if (r.get("affectedRows") instanceof Number n) {
            return new Object[]{"affectedRows=" + n, n.intValue()};
        }
        if (r.get("results") instanceof List<?> list) {
            long affected = 0;
            for (Object o : list) {
                if (o instanceof Map<?, ?> m && m.get("affectedRows") instanceof Number n) {
                    affected += n.longValue();
                }
            }
            return new Object[]{"statements=" + list.size() + " affectedRows=" + affected, list.size()};
        }
        return new Object[]{null, null};
    }

    /** 事件 id: 毫秒时间戳 + 6 位序号, 节点内唯一; 跨节点重复概率可忽略 */
    private String nextId(long now) {
        return now + String.format("%06d", seq.getAndIncrement() % 1_000_000);
    }

    private void spool(Event e) {
        try {
            spool.offer(json.writeValueAsString(e));
        } catch (Exception ex) {
            log.warn("AUDIT 事件序列化失败: {}", ex.toString());
        }
    }

    /** 外部可控字段 (请求头/参数/命令/stderr) 去 CR/LF, 防 app.log 伪造行 */
    private static String line(String s) {
        return s == null ? "" : s.replace('\r', ' ').replace('\n', ' ');
    }

    /** 用户自选模式的凭据是工具层换来的, 调用结束时才有, 故审计取值放到最后 */
    private static ConsoleClient.Resolved pick(ConsoleClient.Resolved cred, McpTransportContext ctx) {
        return cred != null ? cred : McpRequestFilter.resolved(ctx);
    }

    /**
     * 审计输入分两类: 调用身份 (智能体+用户) 与操作资源 (凭据+地址).
     * 用户自选模式下 list_credentials 之类没有凭据, 但身份必须齐全, 否则审计链断一截
     */
    private void record(ConsoleClient.Resolved cred, ConsoleClient.ResolvedUser identity, String srcIp, String userId,
                        String tool, String summary, long t0,
                        String status, String error, String cid, String result, Integer lines) {
        String s = summary == null ? "" : cut(summary, SUMMARY_MAX);
        error = error == null ? null : cut(error, ERROR_MAX);
        long cost = System.currentTimeMillis() - t0;
        String type = typeOf(tool, s);
        String agentCode = cred != null ? cred.agentCode() : identity != null ? identity.agentCode() : null;
        Long agentId = cred != null ? cred.agentId() : identity != null ? identity.agentId() : null;
        String userName = cred != null ? cred.userName() : identity != null ? identity.userName() : null;
        Long credentialId = cred == null ? null : cred.credentialId();
        add(new Entry(System.currentTimeMillis(), dash(agentCode), dash(userName),
                tool, type, resourceOf(cred), s, cost, status, error, cid));
        // list_credentials 只是列出用户自己有权访问的凭据, 不碰任何资源, 不进审计日志;
        // 节点内存环仍然保留 —— 那是节点运维视角, 和合规审计视角不是一回事
        if (SKIP_SPOOL_TOOLS.contains(tool)) {
            return;
        }
        spool(new Event(nextId(t0), cid, t0, cost, agentId, agentCode,
                credentialId, userName, userId, srcIp,
                tool, eventType(tool, s), status, s, result, lines, error));
    }

    /** 不上报控制台的工具: 没有资源访问行为, 记进审计日志只是噪音 */
    private static final java.util.Set<String> SKIP_SPOOL_TOOLS = java.util.Set.of("list_credentials");

    /** 上报用类型码: connect / disconnect / command / SQL 动词 (SELECT/INSERT/...) */
    private static String eventType(String tool, String sql) {
        return switch (tool) {
            case "ssh_connect", "db_create_connection" -> "connect";
            case "ssh_disconnect", "db_close_connection" -> "disconnect";
            case "ssh_execute", "ssh_execute_long_running" -> "command";
            case "db_execute_transaction" -> "transaction";
            case "db_execute" -> {
                String head = sql == null ? "" : sql.trim().toUpperCase(Locale.ROOT);
                int sp = head.indexOf(' ');
                yield head.isEmpty() ? "other" : (sp > 0 ? head.substring(0, sp) : head);
            }
            default -> tool;
        };
    }

    private void add(Entry e) {
        synchronized (ring) {
            if (ring.size() >= MAX) {
                ring.pollFirst();
            }
            ring.addLast(e);
        }
        log.info("AUDIT agent={} user={} type={} resource={} status={} cost={}ms summary={}{}",
                line(e.agent()), line(e.user()), e.type(), line(e.resource()), e.status(), e.costMs(), line(cut(e.summary(), LOG_SUMMARY_MAX)),
                e.error() == null ? "" : " error=" + line(cut(e.error(), LOG_SUMMARY_MAX)));
    }

    private static String cut(String s, int max) {
        return s.length() > max ? s.substring(0, max) + "…" : s;
    }

    /** 新→旧, 全部条件为可选的模糊匹配 */
    public List<Entry> query(String agent, String user, String type, String status, String keyword, int limit) {
        List<Entry> out = new ArrayList<>();
        synchronized (ring) {
            for (Iterator<Entry> it = ring.descendingIterator(); it.hasNext() && out.size() < limit; ) {
                Entry e = it.next();
                if (match(e.agent(), agent) && match(e.user(), user) && match(e.type(), type)
                        && (status == null || status.isBlank() || status.equalsIgnoreCase(e.status()))
                        && (match(e.summary(), keyword) || match(e.resource(), keyword))) {
                    out.add(e);
                }
            }
        }
        return out;
    }

    public int size() {
        synchronized (ring) {
            return ring.size();
        }
    }

    private static boolean match(String value, String q) {
        return q == null || q.isBlank() || (value != null && value.toLowerCase(Locale.ROOT).contains(q.trim().toLowerCase(Locale.ROOT)));
    }

    private static String dash(String s) {
        return s == null || s.isBlank() ? "-" : s;
    }

    static String typeOf(String tool, String summary) {
        return switch (tool) {
            case "ssh_connect" -> "SSH连接";
            case "ssh_disconnect" -> "SSH断开";
            case "ssh_execute", "ssh_execute_long_running" -> "SSH命令";
            case "db_create_connection" -> "DB连接";
            case "db_close_connection" -> "DB断开";
            case "db_execute_transaction" -> "SQL事务";
            case "db_execute" -> sqlType(summary);
            case "list_credentials" -> "凭据查询";
            default -> tool;
        };
    }

    private static String sqlType(String sql) {
        String head = sql == null ? "" : sql.trim().toUpperCase(Locale.ROOT);
        if (head.startsWith("SELECT") || head.startsWith("WITH") || head.startsWith("SHOW") || head.startsWith("DESC") || head.startsWith("EXPLAIN")) {
            return "SQL查询";
        }
        if (head.startsWith("INSERT") || head.startsWith("UPDATE") || head.startsWith("REPLACE") || head.startsWith("MERGE")) {
            return "SQL更新";
        }
        if (head.startsWith("DELETE") || head.startsWith("DROP") || head.startsWith("TRUNCATE")) {
            return "SQL删除";
        }
        return "SQL其他";
    }

    private static String resourceOf(ConsoleClient.Resolved c) {
        if (c == null) {
            return "-";
        }
        // 建连被拒时控制台没返回地址 (也不该由网关臆造), 用凭据 id 标出尝试访问的目标, 别拼成 "null"
        if (c.address() == null || c.address().isBlank()) {
            return c.credentialId() > 0 ? "cred#" + c.credentialId() : "-";
        }
        if ("DATABASE".equals(c.category())) {
            return c.address() + ":" + c.port() + (c.dbName() == null || c.dbName().isBlank() ? "" : "/" + c.dbName());
        }
        return c.address() + (c.port() == null || c.port() == 22 ? "" : ":" + c.port());
    }
}
