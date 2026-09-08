package com.ai.mcp.config;

import com.sun.management.OperatingSystemMXBean;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

/**
 * 控制台对接: 首次匿名注册拿密钥(落本地文件) → 60s 签名心跳; 心跳被拒(403)即 fail-closed
 */
@Component
public class ConsoleClient {

    private static final Logger log = LoggerFactory.getLogger(ConsoleClient.class);
    private static final long REPORT_INTERVAL_S = 30;
    private static final long RETRY_INTERVAL_S = 30;
    private static final long P99_WINDOW_MS = 60_000;

    @Value("${console.url}")
    private String consoleUrl;
    @Value("${console.node-id}")
    private String nodeId;
    @Value("${console.secret-file:./data/gateway.secret}")
    private Path secretFile;

    private final RestClient http;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "console-client");
        t.setDaemon(true);
        return t;
    });

    private volatile String secret;
    private String unsavedSecret;
    private Map<String, Object> unsavedData;
    // 控制台确认启用前一律拦截 (fail-closed)
    private volatile boolean enabled = false;
    private volatile String authType;
    private volatile String authToken;
    private volatile long consoleRttMs;

    // 身份解析缓存 key = agentCode\ntoken\nuserName; 访问序 LinkedHashMap, 超 1000 条淘汰最久未用; 拒绝不缓存
    private static final int RESOLVE_CACHE_MAX = 1000;
    private final LinkedHashMap<String, CachedResolved> resolveCache = new LinkedHashMap<>(64, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, CachedResolved> eldest) {
            return size() > RESOLVE_CACHE_MAX;
        }
    };

    /** 控制台解析出的连接信息 + 真实凭据 (只在内存, 不落盘不打日志) */
    public record Resolved(long agentId, long credentialId, String category, String dbType, String address,
                           Integer port, String dbName, String username, String password) {
    }

    private record CachedResolved(Resolved value, long expireAt) {
    }

    /** 控制台明确拒绝 (code=403 + 中文原因) */
    public static class Rejected extends RuntimeException {
        public Rejected(String msg) {
            super(msg);
        }
    }

    // 指标
    private final AtomicInteger inflight = new AtomicInteger();
    // 按日计数, 跨日切换与递增天然原子; 心跳时清掉旧日 key
    private final ConcurrentHashMap<LocalDate, LongAdder> daily = new ConcurrentHashMap<>();
    // [timestamp, costMs], 只保留最近 1 分钟
    private final ConcurrentLinkedDeque<long[]> samples = new ConcurrentLinkedDeque<>();

    public ConsoleClient() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(5_000);
        factory.setReadTimeout(10_000);
        this.http = RestClient.builder().requestFactory(factory).build();
    }

    @PostConstruct
    void start() {
        try {
            if (Files.exists(secretFile)) {
                String s = Files.readString(secretFile).trim();
                // 空文件视为未取得密钥(上次落盘中断残留), 走正常注册/重置流程而不是拿空串签名卡死
                if (s.isEmpty()) {
                    log.warn("ConsoleClient 密钥文件 {} 为空, 忽略", secretFile);
                } else {
                    secret = s;
                }
            }
        } catch (Exception e) {
            log.warn("ConsoleClient 读取密钥文件失败 {}: {}", secretFile, e.toString());
        }
        scheduler.execute(this::tick);
    }

    @PreDestroy
    void stop() {
        scheduler.shutdownNow();
    }

    private void tick() {
        long next = RETRY_INTERVAL_S;
        try {
            if (secret == null) {
                if (unsavedSecret == null) {
                    register();
                } else {
                    persistSecret();
                }
            }
            if (secret != null) {
                report();
                next = REPORT_INTERVAL_S;
            }
        } catch (HttpClientErrorException.Unauthorized | HttpClientErrorException.Forbidden e) {
            // 前置代理直接回 HTTP 401/403 同样视为拒绝 (控制台本身恒 HTTP 200 + body code)
            enabled = false;
            log.warn("ConsoleClient 被拒 (HTTP {}), /mcp 进入 503", e.getStatusCode().value());
        } catch (Exception e) {
            // 网络异常不改变放行状态, 下轮重试
            log.warn("ConsoleClient 控制台不可达: {}", e.toString());
        }
        scheduler.schedule(this::tick, next, TimeUnit.SECONDS);
    }

    @SuppressWarnings("unchecked")
    private void register() throws Exception {
        Map<String, Object> resp = http.post().uri(consoleUrl + "/agent/gateway/opt/register")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("code", nodeId))
                .retrieve().body(Map.class);
        if (!isOk(resp)) {
            // 节点未登记/已禁用/控制台已下发过密钥(本地文件丢失需控制台重置密钥)
            enabled = false;
            log.warn("ConsoleClient 注册被拒: {}", resp == null ? null : resp.get("msg"));
            return;
        }
        Map<String, Object> data = (Map<String, Object>) resp.get("data");
        // 控制台只下发一次密钥: 先留住再落盘, 落盘失败下轮只重试落盘不重注册(重注册会被拒)
        unsavedSecret = (String) data.get("authSecret");
        unsavedData = data;
        persistSecret();
    }

    private void persistSecret() throws Exception {
        String s = unsavedSecret;
        Map<String, Object> data = unsavedData;
        Files.createDirectories(secretFile.toAbsolutePath().getParent());
        // 先写同目录临时文件再原子替换, 写一半中断不会留下空/半截密钥文件
        Path tmp = secretFile.resolveSibling(secretFile.getFileName() + ".tmp");
        Files.deleteIfExists(tmp);
        try {
            // 建文件时即 0600, 不留 umask 可读窗口
            Files.createFile(tmp, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } catch (UnsupportedOperationException e) {
            log.warn("ConsoleClient 当前文件系统不支持 POSIX 权限, 密钥文件 {} 未限制为 0600", secretFile);
        }
        Files.writeString(tmp, s);
        Files.move(tmp, secretFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        secret = s;
        unsavedSecret = null;
        unsavedData = null;
        applyAuth(data);
        enabled = "1".equals(data.get("status"));
        log.info("ConsoleClient 注册成功, 密钥已保存 {}", secretFile);
    }

    @SuppressWarnings("unchecked")
    private void report() throws Exception {
        Map<String, Object> body = Map.of(
                "cpu", cpuPercent(),
                "mem", memPercent(),
                "p99Ms", p99Ms(),
                "consoleRttMs", consoleRttMs,
                "inflight", inflight.get(),
                "todayRequests", todayRequests());
        long t0 = System.currentTimeMillis();
        Map<String, Object> resp = signedPost("/agent/gateway/opt/report", body);
        consoleRttMs = System.currentTimeMillis() - t0;
        if (!isOk(resp)) {
            // 403: 节点被禁用/密钥被重置/已删除 → fail-closed
            if (enabled) {
                log.warn("ConsoleClient 心跳被拒, /mcp 进入 503: {}", resp == null ? null : resp.get("msg"));
            }
            enabled = false;
            return;
        }
        applyAuth((Map<String, Object>) resp.get("data"));
        if (!enabled) {
            log.info("ConsoleClient 心跳正常, /mcp 放行");
        }
        enabled = true;
    }

    private void applyAuth(Map<String, Object> data) {
        authType = (String) data.get("authType");
        authToken = (String) data.get("authToken");
    }

    private static boolean isOk(Map<String, Object> resp) {
        return resp != null && Integer.valueOf(200).equals(resp.get("code")) && resp.get("data") != null;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> signedPost(String path, Map<String, Object> body) throws Exception {
        String ts = String.valueOf(System.currentTimeMillis());
        return http.post().uri(consoleUrl + path)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Worker-Id", nodeId)
                .header("X-Timestamp", ts)
                .header("X-Sign", hmac(secret, nodeId + "\n" + ts))
                .body(body)
                .retrieve().body(Map.class);
    }

    /**
     * 虚拟凭据 → 真实连接信息: 缓存命中直接返回, 未命中调控制台 opt/resolve (ttl 由控制台下发)
     *
     * @throws Rejected  控制台拒绝 (原因为中文, 直接回给客户端)
     * @throws Exception 控制台不可达
     */
    @SuppressWarnings("unchecked")
    public Resolved resolve(String agentCode, String token, String userName) throws Exception {
        String key = agentCode + "\n" + token + "\n" + (userName == null ? "" : userName);
        long now = System.currentTimeMillis();
        synchronized (resolveCache) {
            CachedResolved hit = resolveCache.get(key);
            if (hit != null && hit.expireAt() > now) {
                return hit.value();
            }
        }
        Map<String, Object> body = new java.util.HashMap<>();
        body.put("agentCode", agentCode);
        body.put("token", token);
        if (userName != null) {
            body.put("userName", userName);
        }
        Map<String, Object> resp = signedPost("/agent/gateway/opt/resolve", body);
        if (!isOk(resp)) {
            // 仅 400/401/403 是控制台明确拒绝 (回 403); 500/空响应属控制台故障, 抛出走 503
            int code = resp != null && resp.get("code") instanceof Number ? ((Number) resp.get("code")).intValue() : -1;
            if (code == 400 || code == 401 || code == 403) {
                Object msg = resp.get("msg");
                throw new Rejected(msg == null ? "控制台拒绝" : msg.toString());
            }
            throw new IllegalStateException("控制台响应异常 code=" + code);
        }
        Map<String, Object> d = (Map<String, Object>) resp.get("data");
        Resolved r = new Resolved(
                ((Number) d.get("agentId")).longValue(),
                ((Number) d.get("credentialId")).longValue(),
                (String) d.get("category"),
                (String) d.get("dbType"),
                (String) d.get("address"),
                d.get("port") == null ? null : ((Number) d.get("port")).intValue(),
                (String) d.get("dbName"),
                (String) d.get("username"),
                (String) d.get("password"));
        long ttl = d.get("ttlSeconds") == null ? 60 : ((Number) d.get("ttlSeconds")).longValue();
        synchronized (resolveCache) {
            resolveCache.put(key, new CachedResolved(r, now + ttl * 1000));
        }
        return r;
    }

    // -------------------- 供 Filter 调用 --------------------

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * BEARER / TLS_TOKEN 校验 Bearer Token; MTLS 要求容器已验证客户端证书(server.ssl.client-auth=need), 纯 HTTP 下 fail-closed; 缺失/未知类型一律拒绝
     */
    public boolean checkToken(String authorization, boolean clientCertVerified) {
        if ("MTLS".equals(authType)) {
            return clientCertVerified;
        }
        if (!"BEARER".equals(authType) && !"TLS_TOKEN".equals(authType)) {
            return false;
        }
        String token = authToken;
        // 方案名不区分大小写 (RFC 7235), Token 本身精确比较
        if (token == null || authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return false;
        }
        return java.security.MessageDigest.isEqual(
                authorization.substring(7).getBytes(StandardCharsets.UTF_8),
                token.getBytes(StandardCharsets.UTF_8));
    }

    public void requestBegin() {
        inflight.incrementAndGet();
        daily.computeIfAbsent(LocalDate.now(), d -> new LongAdder()).increment();
    }

    public void requestEnd(long costMs) {
        inflight.decrementAndGet();
        samples.addLast(new long[]{System.currentTimeMillis(), costMs});
    }

    // -------------------- 指标 --------------------

    private long todayRequests() {
        LocalDate now = LocalDate.now();
        daily.keySet().removeIf(d -> !d.equals(now));
        LongAdder adder = daily.get(now);
        return adder == null ? 0 : adder.sum();
    }

    private long p99Ms() {
        long cutoff = System.currentTimeMillis() - P99_WINDOW_MS;
        long[] head;
        while ((head = samples.peekFirst()) != null && head[0] < cutoff) {
            samples.pollFirst();
        }
        List<Long> costs = new ArrayList<>();
        for (long[] s : samples) {
            costs.add(s[1]);
        }
        if (costs.isEmpty()) {
            return 0;
        }
        long[] arr = costs.stream().mapToLong(Long::longValue).toArray();
        Arrays.sort(arr);
        return arr[Math.max(0, (int) Math.ceil(arr.length * 0.99) - 1)];
    }

    private static double cpuPercent() {
        OperatingSystemMXBean os = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
        double load = os.getCpuLoad();
        return load < 0 ? 0 : round1(load * 100);
    }

    private static double memPercent() {
        // Linux 的 free 不含 page cache, 与 free/top 口径不符; 优先成对取 /proc/meminfo MemTotal/MemAvailable(宿主机口径),
        // 缺任一项则整体回退 MXBean total/free(容器内为限额口径), 分子分母不混用
        long total = 0, avail = 0;
        try {
            for (String line : Files.readAllLines(Path.of("/proc/meminfo"))) {
                if (line.startsWith("MemTotal:")) {
                    total = Long.parseLong(line.replaceAll("\\D", "")) * 1024;
                } else if (line.startsWith("MemAvailable:")) {
                    avail = Long.parseLong(line.replaceAll("\\D", "")) * 1024;
                }
            }
        } catch (Exception ignore) {
            // 非 Linux
        }
        if (total <= 0 || avail <= 0) {
            OperatingSystemMXBean os = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
            total = os.getTotalMemorySize();
            avail = os.getFreeMemorySize();
        }
        return total <= 0 ? 0 : round1(Math.max(0, total - avail) * 100.0 / total);
    }

    private static double round1(double v) {
        return Math.round(v * 10) / 10.0;
    }

    private static String hmac(String secret, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

}
