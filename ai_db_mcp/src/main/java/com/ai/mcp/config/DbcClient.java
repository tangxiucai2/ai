package com.ai.mcp.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * DBC 智能体接口 (/agent/parse|execute|close) 客户端: 每次请求带票据并按会话密钥签名, nonce 一次一用
 * <p>
 * 签名串 = METHOD\npath\nts\nnonce\nhex(sha256(body)), path 取 DBC 看到的 requestURI (含 context-path),
 * 所以按配置的 base-url 算出, 不能写死 /agent/...。票据与会话密钥只在内存, 不打日志
 */
@Component
public class DbcClient {

    private static final Logger log = LoggerFactory.getLogger(DbcClient.class);

    /** 传输失败 / 响应不可解析 (非 DBC 定义的 error.type): 调用方按 DBC 不可达处理 */
    public static final String UNREACHABLE = "UNREACHABLE";

    private final String baseUrl;
    private final ObjectMapper json;
    private final SecureRandom random = new SecureRandom();
    /** 读超时: parse/execute 按 DBC 查询超时 300s 留 20s 余量; close 只是释放连接, 不该让空闲回收/撤权关连接卡几分钟 */
    private static final Duration CALL_TIMEOUT = Duration.ofSeconds(320);
    private static final Duration CLOSE_TIMEOUT = Duration.ofSeconds(10);

    private final HttpClient http = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public DbcClient(@Value("${dbc.base-url:}") String baseUrl, ObjectMapper json) {
        String b = baseUrl == null ? "" : baseUrl.trim();
        this.baseUrl = b.endsWith("/") ? b.substring(0, b.length() - 1) : b;
        this.json = json;
    }

    /**
     * 一次调用的结果: errorType 为 null 即成功
     *
     * @param errorType DBC 的 error.type, 或 {@link #UNREACHABLE}
     */
    public record Result(String errorType, String message, Map<String, Object> data) {
        public boolean ok() {
            return errorType == null;
        }
    }

    public boolean configured() {
        return !baseUrl.isEmpty();
    }

    public Result parse(ConsoleClient.DbcTicket t, String connectId, String sql) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("connectId", connectId);
        body.put("sql", sql);
        return post("parse", t, body, CALL_TIMEOUT);
    }

    /** tables 原样回传 parse 的结果: DBC 会重新解析并逐项比对 */
    public Result execute(ConsoleClient.DbcTicket t, String connectId, String sql, String sqlDigest, String op,
                          List<?> tables, Integer maxRows) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("connectId", connectId);
        body.put("sql", sql);
        body.put("sqlDigest", sqlDigest);
        body.put("op", op);
        body.put("tables", tables);
        if (maxRows != null) {
            body.put("maxRows", maxRows);
        }
        return post("execute", t, body, CALL_TIMEOUT);
    }

    public Result close(ConsoleClient.DbcTicket t, String connectId) {
        return post("close", t, Map.of("connectId", connectId), CLOSE_TIMEOUT);
    }

    @SuppressWarnings("unchecked")
    private Result post(String action, ConsoleClient.DbcTicket t, Map<String, Object> body, Duration timeout) {
        if (!configured()) {
            return new Result(UNREACHABLE, "未配置 dbc.base-url, 数据库工具不可用", null);
        }
        try {
            URI uri = URI.create(baseUrl + "/agent/" + action);
            byte[] bytes = json.writeValueAsBytes(body);
            String ts = String.valueOf(System.currentTimeMillis());
            byte[] n = new byte[16];
            random.nextBytes(n);
            String nonce = HexFormat.of().formatHex(n);
            HttpRequest req = HttpRequest.newBuilder(uri)
                    .timeout(timeout)
                    .header("Content-Type", "application/json")
                    .header("X-Dbc-Ticket", t.ticket())
                    .header("X-Ts", ts)
                    .header("X-Nonce", nonce)
                    .header("X-Sign", sign(t.sessionKey(), "POST", uri.getRawPath(), ts, nonce, bytes))
                    .POST(HttpRequest.BodyPublishers.ofByteArray(bytes))
                    .build();
            HttpResponse<byte[]> resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (resp.statusCode() != 200) {
                return new Result(UNREACHABLE, "DBC 响应异常 HTTP " + resp.statusCode(), null);
            }
            Map<String, Object> m = json.readValue(resp.body(), Map.class);
            if (Boolean.TRUE.equals(m.get("ok"))) {
                return new Result(null, null, m.get("data") instanceof Map<?, ?> d ? (Map<String, Object>) d : Map.of());
            }
            Map<String, Object> err = m.get("error") instanceof Map<?, ?> e ? (Map<String, Object>) e : Map.of();
            String type = err.get("type") instanceof String s && !s.isBlank() ? s : UNREACHABLE;
            return new Result(type, err.get("message") == null ? "" : err.get("message").toString(), null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Result(UNREACHABLE, "DBC 请求被中断", null);
        } catch (Exception e) {
            // 只记异常类型与消息: 请求头里的票据不会出现在 HttpClient 的异常消息里
            log.warn("DBC /agent/{} 调用失败: {}", action, e.toString());
            return new Result(UNREACHABLE, "DBC 不可达: " + e.getClass().getSimpleName(), null);
        }
    }

    /** X-Sign = base64url(HMAC-SHA256(sessionKey, METHOD\npath\nts\nnonce\nhex(sha256(body)))), 不带填充 */
    static String sign(String sessionKey, String method, String path, String ts, String nonce, byte[] body)
            throws Exception {
        String input = method + "\n" + path + "\n" + ts + "\n" + nonce + "\n"
                + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(Base64.getUrlDecoder().decode(sessionKey), "HmacSHA256"));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(input.getBytes(StandardCharsets.UTF_8)));
    }
}
