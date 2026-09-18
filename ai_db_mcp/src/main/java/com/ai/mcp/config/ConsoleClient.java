package com.ai.mcp.config;

import com.sun.management.OperatingSystemMXBean;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import com.ai.mcp.audit.AuditLog;
import com.ai.mcp.tool.IdleReaper;
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
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.LongSupplier;

/**
 * 控制台对接: 首次匿名注册拿密钥(落本地文件) → 60s 签名心跳; 心跳被拒(403)即 fail-closed
 */
@Component
public class ConsoleClient {

    private static final Logger log = LoggerFactory.getLogger(ConsoleClient.class);
    private static final long REPORT_INTERVAL_S = 30;
    private static final long RETRY_INTERVAL_S = 30;
    private static final long P99_WINDOW_MS = 60_000;
    private static final long SIGN_WINDOW_MS = 5 * 60_000;
    public static final String SRC_CONSOLE = "console";
    public static final String SRC_SPOOL = "spool";

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
    // 控制台下发的单节点 QPS 配额, 0=不限; 秒级固定窗计数器: 高 32 位窗口秒 + 低 32 位计数
    private volatile int maxQps;
    /** 确认超时兜底默认 (字段缺失但从未收到过合法值时 / 首次心跳前) */
    public static final int DEFAULT_CONFIRM_TIMEOUT_SEC = 120;
    /** 值域, 与控制台侧保持一致; 网关不假设控制台一定校验过 (信任边界) */
    public static final int MIN_CONFIRM_TIMEOUT_SEC = 10;
    public static final int MAX_CONFIRM_TIMEOUT_SEC = 300;
    /** 控制台下发的二次确认超时(秒); 心跳线程写、业务线程读, volatile 足够 */
    private volatile int confirmTimeoutSeconds = DEFAULT_CONFIRM_TIMEOUT_SEC;
    private final AtomicLong qpsWindow = new AtomicLong();
    /** 限流窗只做相邻比较, 用单调时钟: 墙钟被 NTP 回拨时按秒差会一直落在旧窗内, 配额耗尽后持续 429 */
    private static final long NANO_BASE = System.nanoTime();
    private volatile long consoleRttMs;
    // 审计 WAL 指标 (AuditSpool 启动时注入), 随心跳上报
    private volatile LongSupplier auditPending = () -> 0;
    private volatile LongSupplier auditDropped = () -> 0;
    // 节点事件回调 (AuditLog 启动时注入) 与按来源的去重键
    private volatile NodeAudit nodeAudit;
    private final Map<String, String> lastNodeEvent = new ConcurrentHashMap<>();
    // 策略快照回调 (PolicyStore 启动时注入): 心跳是策略版本与可用性的唯一来源
    private volatile PolicyHeartbeat policyHeartbeat;
    /** 心跳已经上报过一次策略版本 (版本本身可以是 null, 见 notifyPolicy) */
    private volatile boolean policyReported;
    private volatile String lastPolicyVersion;

    // 身份解析缓存 key = agentCode\ntoken\nuserName; 访问序 LinkedHashMap, 超 1000 条淘汰最久未用; 拒绝不缓存
    private static final int RESOLVE_CACHE_MAX = 1000;
    private final LinkedHashMap<String, CachedResolved> resolveCache = new LinkedHashMap<>(64, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, CachedResolved> eldest) {
            return size() > RESOLVE_CACHE_MAX;
        }
    };

    /**
     * 控制台解析出的连接信息 + 真实凭据 (只在内存, 不落盘不打日志)
     *
     * @param dbType 资源主类型 (primaryType 推导), 同时就是访问控制策略的 hostType 口径
     * @param hostId 目标资源 id, 策略按它定范围; 旧版控制台不下发时为 null → 不按策略放行
     */
    public record Resolved(long agentId, long credentialId, String category, String dbType, String address,
                           Integer port, String dbName, String username, String password,
                           String agentCode, String userName, Long hostId) {
    }

    private record CachedResolved(Resolved value, long expireAt) {
    }

    /** 用户自选模式的可信身份 (来自用户 Token 反查, 不是客户端自称的 X-User-Name) */
    public record ResolvedUser(long agentId, long userId, String userName, String agentCode) {
    }

    /** 可用凭据清单项 (字段白名单: 绝不含密码与虚拟凭据, 内容会进入 LLM 上下文) */
    public record CredentialItem(long credentialId, String name, String address, Integer port,
                                 String username, String category, String dbType, String dbName) {
    }

    /** 控制台明确拒绝 (code=403 + 中文原因) */
    public static class Rejected extends RuntimeException {
        public Rejected(String msg) {
            super(msg);
        }
    }

    // 指标
    private final AtomicInteger inflight = new AtomicInteger();
    /** 活着的 MCP 会话数 (STREAMABLE 传输; 由 McpRequestFilter 记账) */
    private final AtomicInteger sessions = new AtomicInteger();
    /** 已记账的会话 id: 递减只认这里有的 (挡住"随机 id 反复 DELETE 把计数压到 0"的绕过) */
    private final Set<String> countedSessions = ConcurrentHashMap.newKeySet();

    /**
     * STREAMABLE 会话数兜底上限 (固定值, 不配置)
     * <p>
     * 写死而不是做成配置项或表字段: 它是"别把网关内存吃光"的工程兜底, 不是对智能体的业务容量策略,
     * 做成管理面配置反而让人以为需要调优。
     * ponytail: 512 是拍脑袋的, 比正常并发高一个量级。它只防"炸"不防"漏" —— 会话没有空闲超时,
     * 真填满了新客户端进不来, 只能重启。调这个值 = 改常量重新发版
     */
    static final int MAX_SESSIONS = 512;
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
            nodeEvent(SRC_CONSOLE, AuditLog.DENIED, "控制台拒绝 HTTP " + e.getStatusCode().value() + ", /mcp 进入 503");
            log.warn("ConsoleClient 被拒 (HTTP {}), /mcp 进入 503", e.getStatusCode().value());
        } catch (Exception e) {
            // 网络异常不改变放行状态, 下轮重试
            nodeEvent(SRC_CONSOLE, AuditLog.FAILED, "控制台不可达: " + e);
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
            nodeEvent(SRC_CONSOLE, AuditLog.DENIED, "注册被拒: " + (resp == null ? null : resp.get("msg")));
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
        nodeEvent(SRC_CONSOLE, AuditLog.SUCCESS, "注册成功, 密钥已保存");
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
                "todayRequests", todayRequests(),
                "connections", IdleReaper.totalHandles(),
                "auditPending", auditPending.getAsLong(),
                "auditDropped", auditDropped.getAsLong());
        long t0 = System.currentTimeMillis();
        Map<String, Object> resp;
        try {
            resp = signedPost("/agent/gateway/opt/report", body);
        } catch (Exception e) {
            // 连不上也算心跳失败: 否则策略快照会在控制台离线期间被无限期沿用
            failPolicy();
            throw e;
        }
        consoleRttMs = System.currentTimeMillis() - t0;
        if (!isOk(resp)) {
            // 403: 节点被禁用/密钥被重置/已删除 → fail-closed
            nodeEvent(SRC_CONSOLE, AuditLog.DENIED, "心跳被拒, /mcp 进入 503: " + (resp == null ? null : resp.get("msg")));
            if (enabled) {
                log.warn("ConsoleClient 心跳被拒, /mcp 进入 503: {}", resp == null ? null : resp.get("msg"));
            }
            enabled = false;
            failPolicy();
            return;
        }
        try {
            Map<String, Object> data = (Map<String, Object>) resp.get("data");
            applyAuth(data);
            // 必须在 enabled 之前: 拉完快照才放行, 否则「/mcp 已放行但策略还没到」有个窗口期
            notifyPolicy((String) data.get("policyVersion"));
        } catch (Exception e) {
            // 响应结构不对 (data 不是对象 / policyVersion 不是字符串) 也要算心跳失败:
            // 否则它走的是"成功"这条路, fails 永不增加 → 旧策略被无限期沿用, "连失 3 次即全拒"形同虚设
            failPolicy();
            throw e;
        }
        nodeEvent(SRC_CONSOLE, AuditLog.SUCCESS, "心跳正常, /mcp 放行");
        if (!enabled) {
            log.info("ConsoleClient 心跳正常, /mcp 放行");
        }
        enabled = true;
    }

    /** 策略快照版本下发回调 */
    public interface PolicyHeartbeat {
        /** @param version 控制台下发的策略版本; null 表示控制台未配置策略版本 (旧版控制台) */
        void onReport(String version);

        /** 心跳失败 (不可达 / 被拒) */
        void onFail();
    }

    public void policyHeartbeat(PolicyHeartbeat h) {
        this.policyHeartbeat = h;
        // 补发: 心跳是 start() 里异步起的, 首轮完全可能在这个监听器注册之前就跑完 ——
        // 不补的话要再等一个心跳周期, 而这期间策略是 loaded=false, 所有 HOST 命令(包括本该放行的
        // 无策略智能体)都会判「策略源不可用」被拒. 同版本补发是幂等的, 不会多拉一次快照
        if (policyReported) {
            h.onReport(lastPolicyVersion);
        }
    }

    private void notifyPolicy(String version) {
        lastPolicyVersion = version;
        policyReported = true;
        PolicyHeartbeat h = policyHeartbeat;
        if (h != null) {
            h.onReport(version);
        }
    }

    private void failPolicy() {
        PolicyHeartbeat h = policyHeartbeat;
        if (h != null) {
            h.onFail();
        }
    }

    /**
     * 拉取该节点的启用策略快照 (控制台已把 rules 摊平成 ops)
     *
     * @throws Rejected  控制台明确拒绝
     * @throws Exception 控制台不可达
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> policySnapshot() throws Exception {
        return (Map<String, Object>) checkedData(signedPost("/agent/gateway/opt/policy-snapshot", Map.of()));
    }

    /** package-private: 允许同包单测直接灌数据, 不必绕 HTTP */
    void applyAuth(Map<String, Object> data) {
        authType = (String) data.get("authType");
        authToken = (String) data.get("authToken");
        maxQps = intOf(data.get("maxQps"));
        IdleReaper.setMaxConnections(intOf(data.get("maxConnections")));
        IdleReaper.setMaxResourceConnections(intOf(data.get("maxResourceConnections")));
        // 缺字段(旧控制台)保持当前缓存 —— 不能重置为默认值: 新旧控制台实例混部或回滚时,
        // 网关会在"已配置值"和 120 之间来回振荡
        if (data.containsKey("confirmTimeoutSeconds")) {
            Long confirm = exactLong(data.get("confirmTimeoutSeconds"));
            // 字段存在但非法一律回落默认。
            // 顺序是"先确认是无小数、未溢出的整数, 再判范围" —— 不能直接走 intOf 的
            // Number.intValue(): 它会把 10.9 截断成 10、超大整数溢出后落进合法区间,
            // 那样"完整校验"就是假的
            confirmTimeoutSeconds = (confirm != null
                    && confirm >= MIN_CONFIRM_TIMEOUT_SEC && confirm <= MAX_CONFIRM_TIMEOUT_SEC)
                    ? confirm.intValue() : DEFAULT_CONFIRM_TIMEOUT_SEC;
        }
    }

    /** 控制台未配置该限额时下发 null, 统一折成 0 (不限) */
    private static int intOf(Object v) {
        return v instanceof Number n ? n.intValue() : 0;
    }

    /** 只接受 JSON 整数(Jackson 默认映射为 Integer/Long); 小数(Double)与超 long(BigInteger) 一律当非法 */
    private static Long exactLong(Object v) {
        return (v instanceof Integer || v instanceof Long) ? ((Number) v).longValue() : null;
    }

    /** 控制台下发的二次确认超时(秒), 供 {@link com.ai.mcp.policy.PolicyGate} 每次确认时读取 */
    public int confirmTimeoutSeconds() {
        return confirmTimeoutSeconds;
    }

    /**
     * QPS 闸门: 超过单节点配额返回 false, 未配置(0)恒放行.
     * ponytail: 秒级固定窗, 跨窗边界最坏放过 2 倍瞬时量; 要平滑再换滑动窗或令牌桶
     */
    public boolean tryAcquire() {
        int max = maxQps;
        if (max <= 0) {
            return true;
        }
        while (true) {
            long cur = qpsWindow.get();
            // 每轮重读时钟: 重试期间可能已跨秒; 且只在 sec 更大时换窗, 否则被挂起的旧线程能把窗口写回上一秒、
            // 清空已消耗的配额, 让新的一秒再拿一次满额 (旧线程落到 else 分支, 消耗当前窗口的配额)
            long sec = (System.nanoTime() - NANO_BASE) / 1_000_000_000L;
            if (sec > (cur >>> 32)) {
                // 换窗与计数一次 CAS 完成, 并发换窗只有一方成功, 输方重读后走同窗分支
                if (qpsWindow.compareAndSet(cur, (sec << 32) | 1L)) {
                    return true;
                }
            } else if ((int) cur >= max) {
                return false;
            } else if (qpsWindow.compareAndSet(cur, cur + 1)) {
                return true;
            }
        }
    }

    private static boolean isOk(Map<String, Object> resp) {
        return resp != null && Integer.valueOf(200).equals(resp.get("code")) && resp.get("data") != null;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> signedPost(String path, Object body) throws Exception {
        String ts = String.valueOf(System.currentTimeMillis());
        return http.post().uri(consoleUrl + path)
                .contentType(MediaType.APPLICATION_JSON)
                .header("X-Worker-Id", nodeId)
                .header("X-Timestamp", ts)
                .header("X-Sign", hmac(secret, nodeId + "\n" + ts))
                .body(body)
                .retrieve().body(Map.class);
    }

    /** 节点事件回调: 注册/心跳/审计上报的状态变化写进日志环供节点自查 */
    public interface NodeAudit {
        void log(String status, String summary);
    }

    public void nodeAudit(NodeAudit n) {
        this.nodeAudit = n;
    }

    /**
     * 记一条节点事件: 同一来源连续相同的事件只留首条 —— 心跳 30s 一轮, 持续异常否则会刷爆日志环
     *
     * @param source 去重分桶 (console / spool), 各来源互不影响
     */
    public void nodeEvent(String source, String status, String summary) {
        // 启动竞态: 本类的首个 tick 与 AuditLog 注册监听器并发, 未装监听器时直接丢弃且不写去重键,
        // 否则该事件会被记成"已出现过", 之后每轮相同的失败都被当重复抑制, 整个故障期日志环全空
        NodeAudit n = nodeAudit;
        if (n == null) {
            return;
        }
        String key = status + '|' + summary;
        if (!key.equals(lastNodeEvent.put(source, key))) {
            n.log(status, summary);
        }
    }

    public void auditMetrics(LongSupplier pending, LongSupplier dropped) {
        this.auditPending = pending;
        this.auditDropped = dropped;
    }

    /**
     * 批量上报审计事件 (每项已是 JSON 对象文本, 原样拼进 events 数组)
     *
     * @return 控制台 body code (200 成功 / 403 拒绝 / 其余重试); 未注册或网络异常返回 -1
     */
    public int audit(List<String> events) {
        if (secret == null) {
            return -1;
        }
        try {
            Map<String, Object> resp = signedPost("/agent/gateway/opt/audit", "{\"events\":[" + String.join(",", events) + "]}");
            return resp != null && resp.get("code") instanceof Number n ? n.intValue() : -1;
        } catch (HttpClientErrorException.Unauthorized | HttpClientErrorException.Forbidden e) {
            return 403;
        } catch (Exception e) {
            log.warn("ConsoleClient 审计上报失败: {}", e.toString());
            return -1;
        }
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
                (String) d.get("password"),
                agentCode,
                userName,
                d.get("hostId") == null ? null : ((Number) d.get("hostId")).longValue());
        long ttl = d.get("ttlSeconds") == null ? 60 : ((Number) d.get("ttlSeconds")).longValue();
        synchronized (resolveCache) {
            resolveCache.put(key, new CachedResolved(r, now + ttl * 1000));
        }
        return r;
    }

    /**
     * 解析用户身份 (用户自选模式的身份锚点)
     * <p>
     * 不缓存: 缓存会让 Token 重置/删除后仍有 TTL 窗口可用, 与"调用时实时判定"的口径矛盾
     *
     * @throws Rejected  控制台拒绝
     * @throws Exception 控制台不可达
     */
    @SuppressWarnings("unchecked")
    public ResolvedUser resolveUser(String agentCode, String userToken) throws Exception {
        Map<String, Object> body = new java.util.HashMap<>();
        body.put("agentCode", agentCode);
        body.put("userToken", userToken);
        Map<String, Object> d = (Map<String, Object>) checkedData(signedPost("/agent/gateway/opt/resolve-user", body));
        return new ResolvedUser(
                ((Number) d.get("agentId")).longValue(),
                ((Number) d.get("userId")).longValue(),
                (String) d.get("userName"),
                agentCode);
    }

    /**
     * 列出该用户可用凭据 (不含密码与虚拟凭据), 不缓存
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> listCredentials(String agentCode, String userToken, String keyword) throws Exception {
        Map<String, Object> body = new java.util.HashMap<>();
        body.put("agentCode", agentCode);
        body.put("userToken", userToken);
        if (keyword != null && !keyword.isBlank()) {
            body.put("keyword", keyword);
        }
        return (Map<String, Object>) checkedData(signedPost("/agent/gateway/opt/list-credentials", body));
    }

    /**
     * 按 credentialId 换取真实凭据; 控制台会重新校验该凭据在此用户授权范围内, 不缓存
     * <p>
     * 建连与后续每次操作已有连接都调它: 撤权/过期/禁用即刻生效
     */
    @SuppressWarnings("unchecked")
    public Resolved resolveCredential(String agentCode, String userToken, long credentialId, String userName) throws Exception {
        Map<String, Object> body = new java.util.HashMap<>();
        body.put("agentCode", agentCode);
        body.put("userToken", userToken);
        body.put("credentialId", credentialId);
        Map<String, Object> d = (Map<String, Object>) checkedData(signedPost("/agent/gateway/opt/resolve-credential", body));
        return new Resolved(
                ((Number) d.get("agentId")).longValue(),
                ((Number) d.get("credentialId")).longValue(),
                (String) d.get("category"),
                (String) d.get("dbType"),
                (String) d.get("address"),
                d.get("port") == null ? null : ((Number) d.get("port")).intValue(),
                (String) d.get("dbName"),
                (String) d.get("username"),
                (String) d.get("password"),
                agentCode,
                userName,
                d.get("hostId") == null ? null : ((Number) d.get("hostId")).longValue());
    }

    /**
     * 风险审批闸门 (第二部分, 设计文档 §4.1): 试消费凭证 / 查在途冷却 / 建新单, 由 PolicyGate.approval() 调用。
     * id 字段业务逻辑用不上, 但按 action 校验必填字段做 fail-closed 判定 (设计文档 §4.1 结尾) 需要解析出来
     * （对本轮评审的修订：此前不解析 id, 导致 PolicyGate 端无法判断 ALLOW/PENDING/REJECTED 是否缺字段）
     * <p>
     * expireTimeMillis 是 Long 不是 String（对 Codex 评审的修订）：控制台 VO 里这是 Date 字段，按这个项目
     * 既有接口约定统一序列化成毫秒数（前端 AgentApprovalQueryResponse.expireTime 同样是 number，非
     * ISO 字符串），(String) 强转在 PENDING 场景每次都会 ClassCastException——那恰好是最常见的首次建单
     * 结果，等于整条"建单成功"路径必炸。照本类里其余数字字段（如 d.get("hostId")）同款 Number 解析
     *
     * @throws Rejected  控制台明确拒绝 (理论上验签已在 Filter 层挡过, 这里只是与其余接口同一分流口径保持一致)
     * @throws Exception 控制台不可达
     */
    public record ApprovalGateResult(String action, Long id, String approvalNo, Long expireTimeMillis, String comment, String approvedBy) {
    }

    @SuppressWarnings("unchecked")
    public ApprovalGateResult approvalGate(Map<String, Object> body) throws Exception {
        Map<String, Object> d = (Map<String, Object>) checkedData(signedPost("/agent/approval/gate", body));
        return new ApprovalGateResult(
                (String) d.get("action"),
                d.get("id") instanceof Number idNum ? idNum.longValue() : null,
                (String) d.get("approvalNo"),
                d.get("expireTime") instanceof Number n ? n.longValue() : null,
                (String) d.get("comment"),
                (String) d.get("approvedBy"));
    }

    /** 本节点 code, 用于拼接完整 CK 格式的调用事件 id (nodeCode-裸id, 第二部分设计文档结论 22) */
    public String nodeId() {
        return nodeId;
    }

    /**
     * 与 resolve 同款错误分流: 400/401/403 是控制台明确拒绝 (回 403), 其余属故障 (走 503)
     */
    private static Object checkedData(Map<String, Object> resp) {
        if (!isOk(resp)) {
            int code = resp != null && resp.get("code") instanceof Number ? ((Number) resp.get("code")).intValue() : -1;
            if (code == 400 || code == 401 || code == 403) {
                Object msg = resp.get("msg");
                throw new Rejected(msg == null ? "控制台拒绝" : msg.toString());
            }
            throw new IllegalStateException("控制台响应异常 code=" + code);
        }
        return resp.get("data");
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

    /**
     * 控制台 → 节点 的反向签名 (拉审计日志): hmac(secret, "console\n" + nodeId + "\n" + ts), 前缀区别于节点 → 控制台方向防互放
     */
    public boolean verifyConsoleSign(String ts, String sign) {
        String s = secret;
        if (s == null || ts == null || sign == null) {
            return false;
        }
        try {
            if (Math.abs(System.currentTimeMillis() - Long.parseLong(ts)) > SIGN_WINDOW_MS) {
                return false;
            }
            return java.security.MessageDigest.isEqual(
                    hmac(s, "console\n" + nodeId + "\n" + ts).getBytes(StandardCharsets.UTF_8),
                    sign.trim().toLowerCase(java.util.Locale.ROOT).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    public void requestBegin() {
        inflight.incrementAndGet();
        daily.computeIfAbsent(LocalDate.now(), d -> new LongAdder()).increment();
    }

    public void requestEnd(long costMs) {
        inflight.decrementAndGet();
        samples.addLast(new long[]{System.currentTimeMillis(), costMs});
    }

    /**
     * 新建了一个 MCP 会话 (initialize 成功)
     * <p>
     * STREAMABLE 的会话只在客户端发 DELETE 时被回收 —— SDK 0.18.2 既没有空闲超时也没有数量上限
     * (整个 provider 里 {@code sessions.remove} 只出现在 {@code handleDelete})。客户端崩溃、断网、
     * 直接重连都不会发 DELETE, 每次都留下一条, 所以必须自己记账 + {@link #sessionLimitReached()} 兜底。
     * 别用开 keep-alive 来"解决": 本版本的 KeepAliveScheduler 失败只打日志、不驱逐, 会把内存问题换成
     * CPU/线程池问题 (上游 issue #1022, 驱逐逻辑在后续 PR #1028 才加)
     */
    public void sessionOpened(String sessionId) {
        if (sessionId == null) {
            return;
        }
        if (countedSessions.add(sessionId)) {
            sessions.incrementAndGet();
        }
    }

    /**
     * 客户端 DELETE 回收了一个会话
     * <p>
     * <b>只对真建过的会话 id 递减</b>: 拿随机 id 反复 DELETE 就能把计数压到 0,
     * 再随便建会话 —— 上限等于不存在 (绕过兜底的现成办法)
     */
    public void sessionClosed(String sessionId) {
        if (sessionId != null && countedSessions.remove(sessionId)) {
            sessions.updateAndGet(n -> n > 0 ? n - 1 : 0);
        }
    }

    /**
     * 一次请求结束后的会话记账
     * <p>
     * 判据只能是头: initialize 的响应带着新会话 id 而请求里没有该头; DELETE 按方法判 (它的响应不带会话头)。
     * 建过哪些 id 记在 {@code countedSessions} 里, 递减必须对得上号。
     *
     * @param status DELETE 的响应码: 只有真删成功才还额度 —— 传输层回 405/500/404 时那条会话还在
     *               SDK 的表里 (例如配了 disallow-delete), 客户可以"建一个再发一个必然失败的 DELETE"
     *               循环, 把额度刷回来把上限变成摆设
     */
    public void accountSession(String method, String requestSessionId, String responseSessionId, int status) {
        if ("DELETE".equalsIgnoreCase(method)) {
            if (status >= 200 && status < 300) {
                sessionClosed(requestSessionId);
            }
        } else if (!Objects.equals(requestSessionId, responseSessionId)) {
            // 响应里的会话 id 和请求里的不一样 (或请求没带) → SDK 这次建了新会话.
            // 不能只看"请求没带 id": 客户端在 initialize 上塞一个任意/过期的 id 时 SDK 照样新建,
            // 判据写成"请求没带 id"就漏计了那一条, 上限被绕过
            sessionOpened(responseSessionId);
        }
    }

    /**
     * 这个请求有没有可能新建会话 —— 上限预检用
     * <p>
     * <b>不能按"带的会话 id 是否已知"来豁免</b>: SDK 判断"这是不是 initialize"看的是请求体里的
     * JSON-RPC method 字段, 跟 Mcp-Session-Id 头完全无关 —— initialize 请求上哪怕带一个已经在用的
     * 真实 id, SDK 照样无视它、新建一个会话 (v0.18.2 WebMvcStreamableServerTransportProvider#handlePost:
     * 先判 method=="initialize" 才看头). 按"已知 id 就不算新建"来放过预检, 攻击者反复带着第一次拿到
     * 的合法 id 发 initialize 就能绕过 512 上限, 且门槛比"带假 id"更低——真实 id 唾手可得。
     * 要精确识别只能解析请求体 (在 Filter 里包一层可重读的 request), 收益(达到上限那个窄窗口里
     * 少拒几个在飞调用)配不上这个复杂度: 512 本来就是"填满了只能重启"的应急阈值, 顺带多拒
     * 几个在飞调用可以接受, 所以只按方法判, 不再看会话 id
     */
    public boolean mayCreateSession(String method) {
        return "POST".equalsIgnoreCase(method);
    }

    /** 会话数是否已达上限 */
    public boolean sessionLimitReached() {
        return sessions.get() >= MAX_SESSIONS;
    }

    /** 当前会话数 (恢复靠重启: 没有别的回收路径) */
    public int sessionCount() {
        return sessions.get();
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
