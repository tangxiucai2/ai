package com.ai.mcp.audit;

import com.ai.mcp.config.ConsoleClient;
import com.ai.mcp.config.McpRequestFilter;
import io.modelcontextprotocol.common.McpTransportContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;

/**
 * 工具调用审计: 每次 tools/call 记一条 (谁/哪个智能体/对哪个资源/做了什么/多久/结果), 同时打一行 app.log
 * <p>
 * ponytail: 内存环形 10000 条, 重启即清; 需持久/跨节点检索时由控制台落库
 */
@Component
public class AuditLog {

    private static final Logger log = LoggerFactory.getLogger(AuditLog.class);
    private static final int MAX = 10_000;
    private static final int SUMMARY_MAX = 4000;
    private static final int LOG_SUMMARY_MAX = 200;

    private static final int ERROR_MAX = 1000;

    public static final String SUCCESS = "SUCCESS";
    public static final String FAILED = "FAILED";
    public static final String DENIED = "DENIED";

    private final ArrayDeque<Entry> ring = new ArrayDeque<>();

    public record Entry(long time, String agent, String user, String tool, String type, String resource,
                        String summary, long costMs, String status, String error, String connectionId) {
    }

    /**
     * 包裹工具调用: 按返回 Map 的 success 判定状态; connectionId 为空时取返回值里的 connectionId (连接类工具)
     */
    public Map<String, Object> run(McpTransportContext ctx, String tool, String connectionId, String summary,
                                   Supplier<Map<String, Object>> call) {
        ConsoleClient.Resolved cred = McpRequestFilter.credential(ctx);
        long t0 = System.currentTimeMillis();
        Map<String, Object> r;
        try {
            r = call.get();
        } catch (RuntimeException e) {
            record(cred, tool, summary, System.currentTimeMillis() - t0, FAILED, e.toString(), connectionId);
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
        record(cred, tool, summary, System.currentTimeMillis() - t0, ok ? SUCCESS : FAILED, error, cid);
        return r;
    }

    /** 鉴权链拒绝 (节点未启用 / Token / 缺头 / 控制台拒绝 / 不可达) */
    public void denied(String agent, String user, String reason) {
        add(new Entry(System.currentTimeMillis(), line(dash(agent)), line(dash(user)), "auth", "鉴权", "-", reason, 0, DENIED, reason, null));
    }

    /** 外部可控字段 (请求头/参数/命令/stderr) 去 CR/LF, 防 app.log 伪造行 */
    private static String line(String s) {
        return s == null ? "" : s.replace('\r', ' ').replace('\n', ' ');
    }

    private void record(ConsoleClient.Resolved cred, String tool, String summary, long cost, String status, String error, String cid) {
        String s = summary == null ? "" : cut(summary, SUMMARY_MAX);
        error = error == null ? null : cut(error, ERROR_MAX);
        add(new Entry(System.currentTimeMillis(), cred == null ? "-" : dash(cred.agentCode()), cred == null ? "-" : dash(cred.userName()),
                tool, typeOf(tool, s), resourceOf(cred), s, cost, status, error, cid));
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
        if ("DATABASE".equals(c.category())) {
            return c.address() + ":" + c.port() + (c.dbName() == null || c.dbName().isBlank() ? "" : "/" + c.dbName());
        }
        return c.address() + (c.port() == null || c.port() == 22 ? "" : ":" + c.port());
    }
}
