package com.ai.mcp.config;

import com.ai.mcp.tool.IdleReaper;

import io.modelcontextprotocol.common.McpTransportContext;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.util.UrlPathHelper;

import java.io.IOException;
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

    private final ConsoleClient console;
    // 与传输层共用端点配置, 避免改了 mcp-endpoint 后鉴权仍只盯 /mcp
    private final String mcpEndpoint;

    public McpRequestFilter(ConsoleClient console, String mcpEndpoint) {
        this.console = console;
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
        if (!console.isEnabled()) {
            reject(resp, HttpServletResponse.SC_SERVICE_UNAVAILABLE, "节点未启用");
            return;
        }
        Object certs = req.getAttribute("jakarta.servlet.request.X509Certificate");
        boolean clientCertVerified = certs instanceof Object[] arr && arr.length > 0;
        if (!console.checkToken(req.getHeader("Authorization"), clientCertVerified)) {
            resp.setHeader("WWW-Authenticate", "Bearer");
            reject(resp, HttpServletResponse.SC_UNAUTHORIZED, "Token 校验失败");
            return;
        }
        // 智能体身份: Header 优先, Query 兜底 (客户端不支持自定义头的场景)
        String agentCode = param(req, "X-Agent-Id", "agentId");
        String token = param(req, "X-Virtual-Token", "token");
        String userName = param(req, "X-User-Name", "userName");
        if (agentCode == null || token == null) {
            reject(resp, HttpServletResponse.SC_UNAUTHORIZED, "缺少智能体标识或虚拟凭据");
            return;
        }
        ConsoleClient.Resolved credential;
        try {
            credential = console.resolve(agentCode, token, userName);
        } catch (ConsoleClient.Rejected e) {
            reject(resp, HttpServletResponse.SC_FORBIDDEN, e.getMessage());
            return;
        } catch (Exception e) {
            log.warn("resolve 控制台不可达 agent={}: {}", agentCode, e.toString());
            reject(resp, HttpServletResponse.SC_SERVICE_UNAVAILABLE, "控制台不可达");
            return;
        }
        req.setAttribute(CREDENTIAL, credential);
        long t0 = System.currentTimeMillis();
        console.requestBegin();
        // 在途计数: 该凭据的句柄在请求期间不被空闲回收
        IdleReaper.begin(credential.credentialId());
        try {
            chain.doFilter(request, response);
        } finally {
            IdleReaper.end(credential.credentialId());
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

    /** sendError 的文案会被 Boot 默认错误页丢掉, 直接写 JSON 让客户端/控制台连接测试拿到原因 */
    private static void reject(HttpServletResponse resp, int status, String msg) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json;charset=UTF-8");
        String json = "{\"code\":" + status + ",\"msg\":\"" + msg.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}";
        resp.getOutputStream().write(json.getBytes(StandardCharsets.UTF_8));
    }

    /** 工具方法从 McpTransportContext 取当前请求凭据 */
    public static ConsoleClient.Resolved credential(McpTransportContext ctx) {
        return ctx == null ? null : (ConsoleClient.Resolved) ctx.get(CREDENTIAL);
    }
}
