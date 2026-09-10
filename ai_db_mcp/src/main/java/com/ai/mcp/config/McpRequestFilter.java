package com.ai.mcp.config;

import com.ai.mcp.audit.AuditLog;
import com.ai.mcp.tool.IdleReaper;

import io.modelcontextprotocol.common.McpTransportContext;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.util.UrlPathHelper;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicLong;
import java.nio.charset.StandardCharsets;

/**
 * /mcp 鉴权: 节点级 (503/401) → 智能体身份链 (缺头 401 / 控制台拒绝 403 / 控制台不可达 503)
 * <p>
 * 解析结果放 request attribute, 由 McpTransportConfig 的 contextExtractor 带进 McpTransportContext;
 * 工具方法在 Reactor boundedElastic 线程执行, ThreadLocal 到不了
 */
public class McpRequestFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(McpRequestFilter.class);

    /** request attribute / McpTransportContext 键 */
    public static final String CREDENTIAL = "soag.credential";

    /** 用户自选模式的可信身份 (ConsoleClient.ResolvedUser) */
    public static final String USER_IDENTITY = "soag.userIdentity";

    /** 用户自选模式的原始用户 Token, 供工具层换取凭据 */
    public static final String USER_TOKEN = "soag.userToken";

    /** 用户自选模式本次请求的在途凭据集合: 工具层 begin 后写入, Filter 的 finally 统一 end */
    public static final String IN_FLIGHT = "soag.inFlight";

    /** 用户自选模式本次请求解析出的凭据: 工具层换取后写入, 供审计补齐资源与 credentialId */
    public static final String RESOLVED = "soag.resolved";

    /** 授权重校验被拒的原因: 供审计记录真实原因而非笼统的「连接不存在」 */
    public static final String DENY_REASON = "soag.denyReason";
    public static final String SRC_IP = "soag.src-ip";
    public static final String USER_ID = "soag.user-id";

    /** 429 无 Servlet 常量 */
    private static final int SC_TOO_MANY_REQUESTS = 429;

    private final ConsoleClient console;
    private final AuditLog audit;
    // 与传输层共用端点配置, 避免改了 mcp-endpoint 后鉴权仍只盯 /mcp
    private final String mcpEndpoint;
    // 限流拒绝的审计节流窗 (秒): 超限时请求密集, 每条都记会把日志环冲空
    // CAS 而非 volatile: 读-判-写有竞争时每秒会记到"并发线程数"条, 节流形同虚设; 时钟同 tryAcquire 用单调源
    private static final long NANO_BASE = System.nanoTime();
    private final AtomicLong lastQpsDenySec = new AtomicLong(-1);

    public McpRequestFilter(ConsoleClient console, AuditLog audit, String mcpEndpoint) {
        this.console = console;
        this.audit = audit;
        // 传输层 RequestPredicates.path 会给无前导斜杠的配置补 "/", 这里同步规范化否则配成 "mcp" 会整段绕过
        this.mcpEndpoint = mcpEndpoint.startsWith("/") ? mcpEndpoint : "/" + mcpEndpoint;
        // 传输层按 PathPattern 路由, 配成 /mcp/** 或 /mcp/{x} 时这里的等值判断会整段放行绕过鉴权: 启动即拒绝模式端点
        if (this.mcpEndpoint.matches(".*[*?{}].*")) {
            throw new IllegalArgumentException("mcp-endpoint 不支持路径模式(*?{}), 请配置固定路径: " + mcpEndpoint);
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        // 取 Servlet 映射内的规范化路径 (剥离 ;param/重复斜杠/spring.mvc.servlet.path 前缀), 与 MVC 路由口径一致; OPTIONS 预检不带 Token 直接放行
        String path = UrlPathHelper.defaultInstance.getLookupPathForRequest(req);
        if (!mcpEndpoint.equals(path) || "OPTIONS".equalsIgnoreCase(req.getMethod())) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletResponse resp = (HttpServletResponse) response;
        // fail-closed: 控制台未确认启用 (未注册/被禁用/密钥重置/已删除) 一律 503
        // 审计用: 鉴权失败也记录发起方声称的身份
        String agentCode = param(req, "X-Agent-Id", "agentId");
        String userName = param(req, "X-User-Name", "userName");
        String userId = param(req, "X-User-Id", "userId");
        String srcIp = srcIp(req);
        if (!console.isEnabled()) {
            deny(resp, HttpServletResponse.SC_SERVICE_UNAVAILABLE, "节点未启用", agentCode, userName, srcIp, userId);
            return;
        }
        Object certs = req.getAttribute("jakarta.servlet.request.X509Certificate");
        boolean clientCertVerified = certs instanceof Object[] arr && arr.length > 0;
        if (!console.checkToken(req.getHeader("Authorization"), clientCertVerified)) {
            resp.setHeader("WWW-Authenticate", "Bearer");
            deny(resp, HttpServletResponse.SC_UNAUTHORIZED, "Token 校验失败", agentCode, userName, srcIp, userId);
            return;
        }
        // QPS 闸门放在 Token 校验之后: 匿名流量打不满配额饿死正常调用; 又在 resolve 之前, 超限时不再压控制台
        if (!console.tryAcquire()) {
            resp.setHeader("Retry-After", "1");
            long sec = (System.nanoTime() - NANO_BASE) / 1_000_000_000L;
            long last = lastQpsDenySec.get();
            if (sec > last && lastQpsDenySec.compareAndSet(last, sec)) {
                deny(resp, SC_TOO_MANY_REQUESTS, "超过 QPS 限制", agentCode, userName, srcIp, userId);
            } else {
                reject(resp, SC_TOO_MANY_REQUESTS, "超过 QPS 限制");
            }
            return;
        }
        // 智能体身份: Header 优先, Query 兜底 (客户端不支持自定义头的场景)
        // 两种模式并存: 带虚拟凭据走固定资源模式 (老路径, 逐字节不变); 只带用户 Token 走用户自选模式.
        // 两个都带时以虚拟凭据优先 —— 更具体的胜出; 也避免 URL 里残留的 token 把模式意外切走
        String token = param(req, "X-Virtual-Token", "token");
        String userToken = token != null ? null : param(req, "X-User-Token", "userToken");
        if (agentCode == null || (token == null && userToken == null)) {
            deny(resp, HttpServletResponse.SC_UNAUTHORIZED, "缺少智能体标识或凭据", agentCode, userName, srcIp, userId);
            return;
        }
        ConsoleClient.Resolved credential = null;
        ConsoleClient.ResolvedUser identity = null;
        try {
            if (token != null) {
                credential = console.resolve(agentCode, token, userName);
            } else {
                identity = console.resolveUser(agentCode, userToken);
            }
        } catch (ConsoleClient.Rejected e) {
            deny(resp, HttpServletResponse.SC_FORBIDDEN, e.getMessage(), agentCode, userName, srcIp, userId);
            return;
        } catch (Exception e) {
            log.warn("resolve 控制台不可达 agent={}: {}", agentCode, e.toString());
            deny(resp, HttpServletResponse.SC_SERVICE_UNAVAILABLE, "控制台不可达", agentCode, userName, srcIp, userId);
            return;
        }
        if (credential != null) {
            req.setAttribute(CREDENTIAL, credential);
        } else {
            req.setAttribute(USER_IDENTITY, identity);
            req.setAttribute(USER_TOKEN, userToken);
            req.setAttribute(IN_FLIGHT, java.util.concurrent.ConcurrentHashMap.<Long>newKeySet());
            req.setAttribute(RESOLVED, new java.util.concurrent.atomic.AtomicReference<ConsoleClient.Resolved>());
            req.setAttribute(DENY_REASON, new java.util.concurrent.atomic.AtomicReference<String>());
            // 身份可信后覆盖客户端自称的两个用户字段, 不留「可信用户名 + 可伪造用户 ID」的半可信组合
            userName = identity.userName();
            userId = String.valueOf(identity.userId());
        }
        req.setAttribute(SRC_IP, srcIp);
        req.setAttribute(USER_ID, userId);
        long t0 = System.currentTimeMillis();
        console.requestBegin();
        // 在途计数: 该凭据的句柄在请求期间不被空闲回收.
        // 用户自选模式此刻还不知道凭据, 保护下移到工具层 (取得句柄前 begin, finally end)
        Long inFlight = credential == null ? null : credential.credentialId();
        if (inFlight != null) {
            IdleReaper.begin(inFlight);
        }
        try {
            chain.doFilter(request, response);
        } finally {
            if (inFlight != null) {
                IdleReaper.end(inFlight);
            } else {
                // 工具层 begin 的逐个 end: 放在 Filter 的 finally 才能覆盖工具内提前 return / 抛异常的路径
                @SuppressWarnings("unchecked")
                java.util.Set<Long> marked = (java.util.Set<Long>) req.getAttribute(IN_FLIGHT);
                if (marked != null) {
                    marked.forEach(IdleReaper::end);
                }
            }
            console.requestEnd(System.currentTimeMillis() - t0);
        }
    }

    private static String param(HttpServletRequest req, String header, String query) {
        String v = req.getHeader(header);
        if (v == null || v.isBlank()) {
            v = req.getParameter(query);
        }
        return v == null || v.isBlank() ? null : v.trim();
    }

    private void deny(HttpServletResponse resp, int status, String msg, String agent, String user, String srcIp, String userId) throws IOException {
        audit.denied(agent, user, msg, srcIp, userId);
        reject(resp, status, msg);
    }

    /** 智能体→网关的源 IP: X-Forwarded-For 首段优先 (前置代理), 否则对端地址 */
    private static String srcIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return req.getRemoteAddr();
    }

    /** sendError 的文案会被 Boot 默认错误页丢掉, 直接写 JSON 让客户端/控制台连接测试拿到原因 */
    private static void reject(HttpServletResponse resp, int status, String msg) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json;charset=UTF-8");
        String json = "{\"code\":" + status + ",\"msg\":\"" + msg.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}";
        resp.getOutputStream().write(json.getBytes(StandardCharsets.UTF_8));
    }

    /** 工具方法从 McpTransportContext 取当前请求凭据 (固定资源模式才有) */
    public static ConsoleClient.Resolved credential(McpTransportContext ctx) {
        return ctx == null ? null : (ConsoleClient.Resolved) ctx.get(CREDENTIAL);
    }

    /** 工具方法从 McpTransportContext 取可信用户身份 (用户自选模式才有) */
    public static ConsoleClient.ResolvedUser userIdentity(McpTransportContext ctx) {
        return ctx == null ? null : (ConsoleClient.ResolvedUser) ctx.get(USER_IDENTITY);
    }

    /** 工具方法从 McpTransportContext 取原始用户 Token (换取凭据用) */
    public static String userToken(McpTransportContext ctx) {
        return ctx == null ? null : (String) ctx.get(USER_TOKEN);
    }

    /** 本次请求解析出的凭据 (用户自选模式才有); 审计据此补资源, 不影响鉴权 */
    @SuppressWarnings("unchecked")
    public static ConsoleClient.Resolved resolved(McpTransportContext ctx) {
        java.util.concurrent.atomic.AtomicReference<ConsoleClient.Resolved> ref = ctx == null
                ? null : (java.util.concurrent.atomic.AtomicReference<ConsoleClient.Resolved>) ctx.get(RESOLVED);
        return ref == null ? null : ref.get();
    }

    /** 工具层换取凭据后回填, 供审计补齐资源 */
    @SuppressWarnings("unchecked")
    public static void setResolved(McpTransportContext ctx, ConsoleClient.Resolved cred) {
        java.util.concurrent.atomic.AtomicReference<ConsoleClient.Resolved> ref = ctx == null
                ? null : (java.util.concurrent.atomic.AtomicReference<ConsoleClient.Resolved>) ctx.get(RESOLVED);
        if (ref != null) {
            ref.compareAndSet(null, cred);
        }
    }

    /** 授权重校验被拒的原因 (用户自选模式才有) */
    @SuppressWarnings("unchecked")
    public static String denyReason(McpTransportContext ctx) {
        java.util.concurrent.atomic.AtomicReference<String> ref = ctx == null
                ? null : (java.util.concurrent.atomic.AtomicReference<String>) ctx.get(DENY_REASON);
        return ref == null ? null : ref.get();
    }

    @SuppressWarnings("unchecked")
    public static void setDenyReason(McpTransportContext ctx, String reason) {
        java.util.concurrent.atomic.AtomicReference<String> ref = ctx == null
                ? null : (java.util.concurrent.atomic.AtomicReference<String>) ctx.get(DENY_REASON);
        if (ref != null) {
            ref.compareAndSet(null, reason);
        }
    }

    /** 本次请求的在途凭据集合 (用户自选模式才有) */
    @SuppressWarnings("unchecked")
    public static java.util.Set<Long> inFlight(McpTransportContext ctx) {
        return ctx == null ? null : (java.util.Set<Long>) ctx.get(IN_FLIGHT);
    }
}
