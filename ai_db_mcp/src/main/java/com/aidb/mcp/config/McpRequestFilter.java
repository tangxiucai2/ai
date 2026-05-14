package com.aidb.mcp.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;

public class McpRequestFilter implements Filter {

    private static final ThreadLocal<HttpServletRequest> currentRequest = new ThreadLocal<>();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        currentRequest.set((HttpServletRequest) request);
        try {
            chain.doFilter(request, response);
        } finally {
            currentRequest.remove();
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