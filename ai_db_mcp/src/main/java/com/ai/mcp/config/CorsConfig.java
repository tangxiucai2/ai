package com.ai.mcp.config;

import com.ai.mcp.audit.AuditLog;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;

@Configuration
public class CorsConfig {

    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(Arrays.asList("*"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("*"));
        // STREAMABLE 下客户端要从初始化响应里读会话 id, 后续请求都带着它.
        // 响应头默认不暴露给跨域 JS, 不显式暴露的话浏览器客户端读到的会话 id 是 null, 初始化后寸步难行
        config.setExposedHeaders(Arrays.asList("Mcp-Session-Id"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        // 排在鉴权过滤器 (order 1) 之前, 401/503 错误响应也带 CORS 头
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
        bean.setOrder(0);
        return bean;
    }

    @Bean
    public FilterRegistrationBean<McpRequestFilter> mcpRequestFilter(ConsoleClient consoleClient, AuditLog auditLog,
            @Value("${spring.ai.mcp.server.streamable-http.mcp-endpoint:/mcp}") String mcpEndpoint) {
        FilterRegistrationBean<McpRequestFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new McpRequestFilter(consoleClient, auditLog, mcpEndpoint));
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(1);
        return registrationBean;
    }
}