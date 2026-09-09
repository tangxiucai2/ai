package com.ai.mcp.tool;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * 句柄空闲回收: 凭据删除/过期后客户端再也无法调用关闭工具, 由服务端按最后使用时间兜底关闭.
 * 该凭据有在途请求 (Filter 进出计数) 时一律不回收, 长时命令/事务不被中断.
 * ponytail: 固定 30 分钟空闲, 每分钟扫一次, acquire/sweep 共用实例锁 (句柄数少, 无争用); 需按凭据 TTL 联动再加
 */
public final class IdleReaper<T> {

    static final long IDLE_MS = TimeUnit.MINUTES.toMillis(30);

    /** 全部句柄表 (SshTool/DatabaseTool 各一个 reaper), 用于连接数统计与总量限额 */
    private static final List<IdleReaper<?>> ALL = new CopyOnWriteArrayList<>();

    /** 控制台心跳下发的连接数上限, 0=不限 */
    private static volatile int maxConnections;

    public static void setMaxConnections(int max) {
        maxConnections = max;
    }

    /** 当前持有的后端句柄总数 (SSH Session + JDBC Connection), 上报控制台作「当前连接数」 */
    public static int totalHandles() {
        int n = 0;
        for (IdleReaper<?> r : ALL) {
            n += r.handles.size();
        }
        return n;
    }

    /**
     * 建连前的总量闸门: 已达上限返回 true.
     * ponytail: 读-判-建非原子, 并发建连最多超出并发数个句柄, 空闲回收会收敛; 需要硬上限再加信号量
     */
    public static boolean atLimit() {
        int max = maxConnections;
        return max > 0 && totalHandles() >= max;
    }

    /** credentialId → 在途请求数 */
    private static final Map<Long, AtomicInteger> IN_FLIGHT = new ConcurrentHashMap<>();

    /** credentialId → 最近一次请求结束时间: 长任务空闲窗从结束时算, 不从 acquire 时算 */
    private static final Map<Long, Long> LAST_END = new ConcurrentHashMap<>();

    public static void begin(long credentialId) {
        // compute 与 purge 的 computeIfPresent 同桶互斥, 不会给已被清理的计数器加一
        IN_FLIGHT.compute(credentialId, (k, v) -> {
            AtomicInteger c = v == null ? new AtomicInteger() : v;
            c.incrementAndGet();
            return c;
        });
    }

    public static void end(long credentialId) {
        AtomicInteger c = IN_FLIGHT.get(credentialId);
        if (c != null) {
            c.decrementAndGet();
        }
        LAST_END.put(credentialId, System.currentTimeMillis());
    }

    /** connectionId = credentialId:uuid; 有在途请求或最近请求结束未满空闲窗即视为活跃 */
    private static boolean active(String id, long deadline) {
        int i = id.indexOf(':');
        if (i <= 0) {
            return false;
        }
        try {
            long cid = Long.parseLong(id.substring(0, i));
            AtomicInteger c = IN_FLIGHT.get(cid);
            Long end = LAST_END.get(cid);
            return (c != null && c.get() > 0) || (end != null && end >= deadline);
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /** 清理无在途且空闲窗已过的凭据记录, 两张表不随历史凭据无界增长 */
    private static void purge(long deadline) {
        LAST_END.forEach((cid, end) -> {
            if (end >= deadline) {
                return;
            }
            IN_FLIGHT.computeIfPresent(cid, (k, v) -> v.get() == 0 ? null : v);
            if (!IN_FLIGHT.containsKey(cid)) {
                LAST_END.remove(cid, end);
            }
        });
    }

    private final Map<String, T> handles;
    private final Consumer<T> close;
    /** guarded by this */
    private final Map<String, Long> lastUsed = new HashMap<>();

    IdleReaper(String name, Map<String, T> handles, Consumer<T> close) {
        this.handles = handles;
        this.close = close;
        ALL.add(this);
        Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, name);
            t.setDaemon(true);
            return t;
        }).scheduleWithFixedDelay(this::sweep, 1, 1, TimeUnit.MINUTES);
    }

    synchronized void touch(String id) {
        lastUsed.put(id, System.currentTimeMillis());
    }

    /** 刷新使用时间并取句柄, 与 sweep 互斥: 取到的句柄不会被同一轮扫描关闭 */
    synchronized T acquire(String id) {
        lastUsed.put(id, System.currentTimeMillis());
        return handles.get(id);
    }

    void sweep() {
        long deadline = System.currentTimeMillis() - IDLE_MS;
        List<T> expired = new ArrayList<>();
        synchronized (this) {
            lastUsed.entrySet().removeIf(e -> {
                String id = e.getKey();
                if (!handles.containsKey(id)) {
                    return true;
                }
                if (e.getValue() >= deadline || active(id, deadline)) {
                    return false;
                }
                expired.add(handles.remove(id));
                return true;
            });
        }
        purge(deadline);
        // 锁外关闭: close 可能阻塞, 不能拖住其他凭据的 acquire
        for (T h : expired) {
            try {
                close.accept(h);
            } catch (Exception ignore) {
                // 回收失败不影响其余句柄
            }
        }
    }
}
