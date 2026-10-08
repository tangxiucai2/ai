package com.ai.mcp.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 心跳被控制台拒绝 (body 403) 后同轮匿名注册试探: 成功即落盘切换并用新密钥再发签名心跳 (设计 §4 U1–U6)
 */
class ConsoleClientReregisterTest {

    private static final String NODE = "gw-1";
    private static final String OLD = "old-secret";
    private static final String NEW = "new-secret";

    @TempDir
    Path dir;

    private Path secretFile;
    /** 心跳/注册按序取的桩响应, 取空即测试写错 */
    private final Deque<Supplier<Map<String, Object>>> reports = new ArrayDeque<>();
    private final Deque<Supplier<Map<String, Object>>> registers = new ArrayDeque<>();
    /** 每次心跳: [签名, 期望签名(按发出时的 secret 算), 发出时 enabled, 发出时 authType] */
    private final List<Object[]> sent = new ArrayList<>();
    private final List<String> events = new ArrayList<>();
    private int registerCalls;
    private int rebaseCalls;
    private ConsoleClient client;

    @BeforeEach
    void setUp() throws Exception {
        secretFile = dir.resolve("gateway.secret");
        client = new ConsoleClient() {
            @Override
            Map<String, Object> send(String path, String ts, String sign, Object body) {
                try {
                    sent.add(new Object[]{sign, hmac(get("secret"), NODE + "\n" + ts), get("enabled"), get("authType"), get("secret")});
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
                return reports.remove().get();
            }

            @Override
            Map<String, Object> sendRegister() {
                registerCalls++;
                return registers.remove().get();
            }
        };
        set("nodeId", NODE);
        set("secretFile", secretFile);
        set("tls", new TlsManager(secretFile) {
            @Override
            public synchronized void rebase() {
                rebaseCalls++;
                super.rebase();
            }
        });
        client.nodeAudit((status, summary) -> events.add(status + "|" + summary));
    }

    private void set(String name, Object v) throws Exception {
        var f = ConsoleClient.class.getDeclaredField(name);
        f.setAccessible(true);
        f.set(client, v);
    }

    @SuppressWarnings("unchecked")
    private <T> T get(String name) throws Exception {
        var f = ConsoleClient.class.getDeclaredField(name);
        f.setAccessible(true);
        return (T) f.get(client);
    }

    /** 已注册在线的节点: 文件与内存均为旧密钥, 认证字段为旧值 */
    private void registered() throws Exception {
        Files.writeString(secretFile, OLD);
        set("secret", OLD);
        set("enabled", true);
        set("authType", "OLD_TYPE");
        set("authToken", "old-token");
    }

    private static String hmac(String secret, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private static Map<String, Object> resp(int code, Map<String, Object> data) {
        Map<String, Object> m = new HashMap<>();
        m.put("code", code);
        m.put("msg", code == 200 ? "ok" : "拒绝");
        m.put("data", data);
        return m;
    }

    private static Map<String, Object> heartbeatOk() {
        return resp(200, new HashMap<>());
    }

    private static Map<String, Object> registerOk(String secret, String status) {
        Map<String, Object> d = new HashMap<>();
        d.put("authSecret", secret);
        d.put("status", status);
        d.put("authType", "REG_TYPE");
        d.put("authToken", "reg-token");
        return resp(200, d);
    }

    private long countEvents(String part) {
        return events.stream().filter(e -> e.contains(part)).count();
    }

    @Test
    void u1RejectedThenReregisterSwitchesSecretAndSignsWithNewOne() throws Exception {
        registered();
        reports.add(() -> resp(403, null));
        registers.add(() -> registerOk(NEW, "1"));
        reports.add(ConsoleClientReregisterTest::heartbeatOk);
        client.runOnce();

        assertEquals(NEW, Files.readString(secretFile));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(secretFile)));
        assertFalse(Files.exists(dir.resolve("gateway.secret.tmp")));
        assertEquals(NEW, get("secret"));
        assertEquals(1, rebaseCalls);
        assertEquals(2, sent.size());
        assertEquals(OLD, sent.get(0)[4]);
        // 第二次心跳用新密钥签名
        assertEquals(NEW, sent.get(1)[4]);
        assertEquals(sent.get(1)[1], sent.get(1)[0]);
        assertTrue((boolean) get("enabled"));
        // 日志环: 心跳被拒 → 自动重新注册成功 → 心跳正常, 各一条
        assertEquals(3, events.size());
        assertTrue(events.get(0).contains("心跳被拒"));
        assertTrue(events.get(1).contains("自动重新注册成功"));
        assertTrue(events.get(2).contains("心跳正常, /mcp 放行"));
    }

    @Test
    void u2ReregisterRejectedKeepsOldSecretSilently() throws Exception {
        registered();
        reports.add(() -> resp(403, null));
        registers.add(() -> resp(403, null));
        client.runOnce();

        assertEquals(OLD, Files.readString(secretFile));
        assertEquals(OLD, get("secret"));
        assertFalse((boolean) get("enabled"));
        assertEquals(1, sent.size());
        assertEquals(0, countEvents("注册被拒"));
        assertEquals(1, events.size());
    }

    @Test
    void u3OnlyBody403TriggersReregister() throws Exception {
        List<Supplier<Map<String, Object>>> cases = List.of(
                () -> {
                    throw new IllegalStateException("connect refused");
                },
                () -> resp(500, null),
                () -> resp(200, null),
                () -> {
                    throw HttpClientErrorException.create(HttpStatus.FORBIDDEN, "Forbidden", HttpHeaders.EMPTY, null, null);
                });
        registered();
        for (Supplier<Map<String, Object>> c : cases) {
            reports.add(c);
            client.runOnce();
        }
        assertEquals(4, sent.size());
        assertEquals(0, registerCalls);
        assertEquals(OLD, get("secret"));
    }

    @Test
    void u4ReregisterResponseNotAppliedWhenNewHeartbeatRejected() throws Exception {
        registered();
        reports.add(() -> resp(403, null));
        registers.add(() -> registerOk(NEW, "1"));
        reports.add(() -> resp(403, null));
        client.runOnce();

        assertEquals(NEW, get("secret"));
        assertFalse((boolean) get("enabled"));
        assertEquals("OLD_TYPE", get("authType"));
        assertEquals("old-token", get("authToken"));
        // 新密钥心跳发出时 enabled 仍为 false
        assertEquals(false, sent.get(1)[2]);
    }

    @Test
    void u5PersistFailureRetriedNextTickWithoutReregister() throws Exception {
        registered();
        // 目标路径换成非空目录: 原子替换必然失败
        Path blocked = dir.resolve("blocked");
        Files.createDirectories(blocked.resolve("x"));
        set("secretFile", blocked);
        reports.add(() -> resp(403, null));
        registers.add(() -> registerOk(NEW, "1"));
        client.runOnce();

        assertEquals(OLD, get("secret"));
        assertEquals(NEW, get("unsavedSecret"));
        assertNull(get("unsavedData"));
        assertEquals(1, sent.size());

        Files.delete(blocked.resolve("x"));
        Files.delete(blocked);
        reports.add(ConsoleClientReregisterTest::heartbeatOk);
        client.runOnce();

        assertEquals(1, registerCalls);
        assertEquals(NEW, Files.readString(blocked));
        assertEquals(NEW, get("secret"));
        assertNull(get("unsavedSecret"));
        assertEquals(2, sent.size());
        // 补偿落盘后、心跳前: 仍 fail-closed, 认证字段未被注册响应改写
        assertEquals(false, sent.get(1)[2]);
        assertEquals("OLD_TYPE", sent.get(1)[3]);
        assertEquals(NEW, sent.get(1)[4]);
        assertEquals(sent.get(1)[1], sent.get(1)[0]);
        assertTrue((boolean) get("enabled"));
    }

    @Test
    void u6FirstRegisterPersistFailureRetriesOnlyPersist() throws Exception {
        Path blocked = dir.resolve("blocked");
        Files.createDirectories(blocked.resolve("x"));
        set("secretFile", blocked);
        registers.add(() -> registerOk(NEW, "1"));
        client.runOnce();

        assertNull(get("secret"));
        assertEquals(NEW, get("unsavedSecret"));
        assertTrue(sent.isEmpty());

        Files.delete(blocked.resolve("x"));
        Files.delete(blocked);
        reports.add(ConsoleClientReregisterTest::heartbeatOk);
        client.runOnce();

        assertEquals(1, registerCalls);
        assertEquals(NEW, Files.readString(blocked));
        // 落盘后、心跳前: enabled 按注册响应 status, 认证字段取自注册响应 (原有行为)
        assertEquals(true, sent.get(0)[2]);
        assertEquals("REG_TYPE", sent.get(0)[3]);
        assertEquals(sent.get(0)[1], sent.get(0)[0]);
    }
}
