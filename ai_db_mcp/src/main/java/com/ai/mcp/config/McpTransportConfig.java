package com.ai.mcp.config;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.json.jackson.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.transport.WebMvcStreamableServerTransportProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.ai.mcp.server.common.autoconfigure.properties.McpServerStreamableHttpProperties;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
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
                .contextExtractor(req -> extract(req.servletRequest()))
                .build();
    }

    /**
     * SDK 出错时直接把 McpError 当响应体 (如 404 Session not found), Jackson 默认会带出堆栈/类名/行号, 500 分支还拼了 e.getMessage();
     * 这里 Throwable 一律只输出 message, 且只放行 SDK 自己的固定提示, 其余统一为 Internal server error (原始异常 SDK 已打日志)
     * <p>
     * 不能用 Jackson2ObjectMapperBuilderCustomizer: Spring AI 自带 mcpServerObjectMapper, Boot 的 ObjectMapper 不会创建, HTTP 转换器用的是它
     */
    @Bean
    public static BeanPostProcessor hideThrowableInternals() {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if (bean instanceof ObjectMapper mapper) {
                    mapper.addMixIn(Throwable.class, ThrowableMixIn.class);
                }
                return bean;
            }
        };
    }

    @JsonSerialize(using = SafeErrorSerializer.class)
    private abstract static class ThrowableMixIn {
    }

    static final class SafeErrorSerializer extends StdSerializer<Throwable> {

        /**
         * WebMvcStreamableServerTransportProvider 0.18.2 里 new McpError 的固定文案 (Session not found 后拼的是客户端自己传的会话 ID)
         */
        private static final List<String> SAFE_PREFIXES = List.of("Session not found: ", "Session ID missing",
                "Invalid message format", "Unknown message type", "Invalid Accept headers");

        SafeErrorSerializer() {
            super(Throwable.class);
        }

        @Override
        public void serialize(Throwable e, JsonGenerator gen, SerializerProvider provider) throws IOException {
            String msg = e.getMessage();
            gen.writeStartObject();
            gen.writeStringField("message", msg != null && SAFE_PREFIXES.stream().anyMatch(msg::startsWith) ? msg : "Internal server error");
            gen.writeEndObject();
        }
    }

    /**
     * Filter 写入的 request attribute → McpTransportContext (工具层只能从这里拿到身份与对端地址)
     */
    public static McpTransportContext extract(HttpServletRequest req) {
        Map<String, Object> ctx = new HashMap<>();
        for (String k : new String[]{McpRequestFilter.CREDENTIAL, McpRequestFilter.VIRTUAL_TOKEN, McpRequestFilter.USER_IDENTITY,
                McpRequestFilter.USER_TOKEN, McpRequestFilter.IN_FLIGHT, McpRequestFilter.RESOLVED, McpRequestFilter.DENY_REASON,
                McpRequestFilter.SRC_IP, McpRequestFilter.PEER_IP, McpRequestFilter.USER_ID, McpRequestFilter.REQUEST_ID}) {
            Object v = req.getAttribute(k);
            if (v != null) {
                ctx.put(k, v);
            }
        }
        return ctx.isEmpty() ? McpTransportContext.EMPTY : McpTransportContext.create(ctx);
    }
}
