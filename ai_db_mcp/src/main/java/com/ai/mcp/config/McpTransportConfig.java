package com.ai.mcp.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.transport.WebMvcStreamableServerTransportProvider;
import org.springframework.ai.mcp.server.common.autoconfigure.properties.McpServerStreamableHttpProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * 覆盖自动配置的 STREAMABLE 传输: 自动配置的 contextExtractor 恒为 EMPTY, 这里把 Filter 解析出的凭据带进 McpTransportContext
 * <p>
 * 必须是 streamable 而不是 stateless: 协议级二次确认 (elicitation) 挂在会话对象上, stateless 的工具回调拿不到 exchange
 */
@Configuration
public class McpTransportConfig {

    @Bean
    public WebMvcStreamableServerTransportProvider webMvcStreamableServerTransportProvider(
            ObjectMapper objectMapper, McpServerStreamableHttpProperties props) {
        return WebMvcStreamableServerTransportProvider.builder()
                .jsonMapper(new JacksonMcpJsonMapper(objectMapper))
                .mcpEndpoint(props.getMcpEndpoint())
                .keepAliveInterval(props.getKeepAliveInterval())
                .disallowDelete(props.isDisallowDelete())
                .contextExtractor(req -> {
                    Map<String, Object> ctx = new HashMap<>();
                    for (String k : new String[]{McpRequestFilter.CREDENTIAL, McpRequestFilter.USER_IDENTITY,
                            McpRequestFilter.USER_TOKEN, McpRequestFilter.IN_FLIGHT, McpRequestFilter.RESOLVED, McpRequestFilter.DENY_REASON,
                            McpRequestFilter.SRC_IP, McpRequestFilter.USER_ID}) {
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
