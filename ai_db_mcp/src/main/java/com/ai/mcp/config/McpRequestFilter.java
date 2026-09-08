package com.ai.mcp.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.util.UrlPathHelper;
import java.io.IOException;

public class McpRequestFilter implements Filter {

    private static final ThreadLocal<HttpServletRequest> currentRequest = new ThreadLocal<>();

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
            resp.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "节点未启用");
            return;
        }
        Object certs = req.getAttribute("jakarta.servlet.request.X509Certificate");
        boolean clientCertVerified = certs instanceof Object[] arr && arr.length > 0;
        if (!console.checkToken(req.getHeader("Authorization"), clientCertVerified)) {
            resp.setHeader("WWW-Authenticate", "Bearer");
            resp.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token 校验失败");
            return;
        }
        long t0 = System.currentTimeMillis();
        console.requestBegin();
        currentRequest.set(req);
        try {
            chain.doFilter(request, response);
        } finally {
            currentRequest.remove();
            console.requestEnd(System.currentTimeMillis() - t0);
        }
    }

    public static HttpServletRequest getCurrentRequest() {
        return currentRequest.get();
    }

    public static String getHeader(String name) {
        HttpServletRequest req = currentRequest.get();
        return req != null ? req.getHeader(name) : null;
    }

    public static String getConnectionStringFromHeader() {
        return getHeader("X-AIDB-CONNECTION-STRING");
    }

    public static String getUsernameFromHeader() {
        return getHeader("X-AIDB-USERNAME");
    }

    public static String getPasswordFromHeader() {
        return getHeader("X-AIDB-PASSWORD");
    }
}
