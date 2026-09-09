package com.ai.mcp.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.transport.WebMvcStatelessServerTransport;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * 覆盖自动配置的 STATELESS 传输: 自动配置的 contextExtractor 恒为 EMPTY, 这里把 Filter 解析出的凭据带进 McpTransportContext
 */
@Configuration
public class McpTransportConfig {

    @Bean
    public WebMvcStatelessServerTransport webMvcStatelessServerTransport(ObjectMapper objectMapper,
            @Value("${spring.ai.mcp.server.streamable-http.mcp-endpoint:/mcp}") String mcpEndpoint) {
        return WebMvcStatelessServerTransport.builder()
                .jsonMapper(new JacksonMcpJsonMapper(objectMapper))
                .messageEndpoint(mcpEndpoint)
                .contextExtractor(req -> {
                    Map<String, Object> ctx = new HashMap<>();
                    for (String k : new String[]{McpRequestFilter.CREDENTIAL, McpRequestFilter.SRC_IP, McpRequestFilter.USER_ID}) {
                        Object v = req.servletRequest().getAttribute(k);
                        if (v != null) {
                            ctx.put(k, v);
                        }
                    }
                    return ctx.isEmpty() ? McpTransportContext.EMPTY : McpTransportContext.create(ctx);
                })
                .build();
    }
}
