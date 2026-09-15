package com.ai.mcp.policy;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 策略级频率限制: 固定窗口 + 每策略一个桶
 * <p>
 * 与节点级 QPS 闸门 ({@code ConsoleClient.tryAcquire}) 同一套写法, 三条铁律照搬:
 * <ul>
 *   <li>时钟取 {@link System#nanoTime()} 单调源 —— 用 currentTimeMillis 的话 NTP 回拨会把窗口钉死在旧秒, 持续拒绝</li>
 *   <li>窗口只许前进 (只在新窗口号更大时换窗), 否则被挂起的旧线程能把窗口写回去、清空已消耗的配额</li>
 *   <li>换窗与计数一次 CAS 完成, 并发换窗只有一方成功, 输方重读走同窗分支</li>
 * </ul>
 * <p>
 * 检查与计数分成两步 ({@link #exceeded} 只读 / {@link #record} 累加), 因为只对**放行执行**的调用计数:
 * 被黑名单拦下、弹窗没过、超限的调用都不该占配额 (设计文档结论 16)。
 * 代价是并发下可能多放行"同一刻通过检查"的那几个, 可接受; 用"检查时原子+1、未执行再回退"能消掉,
 * 但会引入"预留了却没执行"的配额泄漏, 不值。
 * <p>
 * 桶不主动清理: 策略删除或窗口配置改动后留下一个 AtomicLong (几十字节), 非增长型, 重启即消失。
 * 为它引一条 PolicyStore → limiter 的依赖不值。
 * <p>
 * <b>桶键必须带窗口长度</b>: 窗口号是 {@code 已运行秒数 / windowSeconds}, 按旧长度算出来的窗口号
 * 跟按新长度算的根本不可比。管理员把窗口从 1 秒改成 1 小时时, 旧桶里的窗口号 (可能上千) 会让
 * "换窗"判断长期不成立 —— 计数只增不减, 配额攒满后命令被拒数小时。
 */
public class PolicyRateLimiter {

    /** 与节点级限流器同源: 进程启动时刻, 只用于算相对的窗口号 */
    private static final long NANO_BASE = System.nanoTime();

    /** 低位计数掩码; 高位是窗口号 */
    private static final long COUNT_MASK = 0xFFFF_FFFFL;

    /** 桶键: 策略 id + 窗口长度 (窗口配置一改就换桶, 从新窗口重新计数) */
    private record Key(long policyId, long windowSeconds) {
    }

    private final ConcurrentHashMap<Key, AtomicLong> buckets = new ConcurrentHashMap<>();

    /**
     * 本次调用是否已超限 (只读, 不改状态)
     *
     * @param limit         窗口内次数上限; {@code <= 0} 表示不限 (旧控制台不下发时按不限处理)
     * @param windowSeconds 窗口长度 (秒); {@code <= 0} 表示不限
     */
    public boolean exceeded(long policyId, long limit, long windowSeconds) {
        if (limit <= 0 || windowSeconds <= 0) {
            return false;
        }
        AtomicLong bucket = buckets.get(new Key(policyId, windowSeconds));
        if (bucket == null) {
            return false;
        }
        long cur = bucket.get();
        long win = window(windowSeconds);
        // 桶还停在旧窗口 → 本窗计数为 0 (时钟是单调源, 桶的窗口不会比当前新)
        if (win > (cur >>> 32)) {
            return false;
        }
        return (cur & COUNT_MASK) >= limit;
    }

    /** 记一次放行执行的调用 */
    public void record(long policyId, long windowSeconds) {
        if (windowSeconds <= 0) {
            return;
        }
        AtomicLong bucket = buckets.computeIfAbsent(new Key(policyId, windowSeconds), k -> new AtomicLong());
        while (true) {
            long cur = bucket.get();
            // 每轮重读时钟: 重试期间可能已跨窗
            long win = window(windowSeconds);
            if (win > (cur >>> 32)) {
                if (bucket.compareAndSet(cur, (win << 32) | 1L)) {
                    return;
                }
            } else if (bucket.compareAndSet(cur, (cur & ~COUNT_MASK) | ((cur & COUNT_MASK) + 1))) {
                // 计数+1 只落在低位: 直接 cur+1 在低位全 1 时会进位污染窗口号
                return;
            }
        }
    }

    /** 相对进程启动的窗口号; nanoTime 单调, 窗口号只增不减 */
    private static long window(long windowSeconds) {
        return (System.nanoTime() - NANO_BASE) / 1_000_000_000L / windowSeconds;
    }
}
