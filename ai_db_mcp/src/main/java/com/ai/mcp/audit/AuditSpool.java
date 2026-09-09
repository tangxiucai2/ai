package com.ai.mcp.audit;

import com.ai.mcp.config.ConsoleClient;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

/**
 * 审计事件 WAL: 内存队列 → 追加 jsonl 文件(fsync) → 按批上报控制台, 成功才推进 offset; 控制台不可达期间本地累积, 恢复后按序补发
 * <p>
 * 文件 data/audit-spool/audit-&lt;startMs&gt;.jsonl (50MB 滚动, 目录超 500MB 删最旧), offset 文件记 "文件名\n字节偏移"
 * <p>
 * ponytail: 单 writer + 单 sender 线程, 同一把锁串行化文件读写删; 每批 ≤200 行 / ≤1s 一刷
 */
@Component
public class AuditSpool {

    private static final Logger log = LoggerFactory.getLogger(AuditSpool.class);
    private static final int QUEUE_MAX = 10_000;
    private static final int BATCH = 200;
    private static final long FLUSH_MS = 1000;
    private static final long ROLL_BYTES = 50L << 20;
    private static final long CAP_BYTES = 500L << 20;
    private static final long BACKOFF_MIN_MS = 1000;
    private static final long BACKOFF_MAX_MS = 30_000;
    private static final String PREFIX = "audit-";
    private static final String SUFFIX = ".jsonl";

    private final ConsoleClient console;
    private final Path dir;
    private final ArrayBlockingQueue<String> queue = new ArrayBlockingQueue<>(QUEUE_MAX);
    private final Object fileLock = new Object();
    private final AtomicLong written = new AtomicLong();
    private final AtomicLong sent = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private volatile boolean running = true;
    private Path current;
    private Thread writer;
    private Thread sender;

    public AuditSpool(ConsoleClient console, @Value("${console.audit-dir:./data/audit-spool}") Path dir) {
        this.console = console;
        this.dir = dir;
    }

    /** 入队一行 JSON (无换行); 队列满即丢并计数, 永不阻塞调用方 */
    public void offer(String json) {
        if (!queue.offer(json)) {
            dropped.incrementAndGet();
        }
    }

    /** 未上报条数 (内存 + 磁盘) */
    public long pending() {
        return queue.size() + Math.max(0, written.get() - sent.get());
    }

    public long dropped() {
        return dropped.get();
    }

    @PostConstruct
    void start() throws IOException {
        Files.createDirectories(dir);
        // 磁盘残留未上报行计入 pending
        Offset off = readOffset();
        long backlog = 0;
        for (Path f : files()) {
            long skip = f.equals(off.file) ? off.pos : 0;
            backlog += countLines(f, skip);
        }
        written.set(backlog);
        console.auditMetrics(this::pending, this::dropped);
        writer = daemon("audit-writer", this::writeLoop);
        sender = daemon("audit-sender", this::sendLoop);
        log.info("AuditSpool 启动 dir={} 待补发 {} 条", dir.toAbsolutePath(), backlog);
    }

    @PreDestroy
    void stop() throws InterruptedException {
        running = false;
        writer.interrupt();
        sender.interrupt();
        // writer 退出前把队列残余落盘; 再给 sender 最多 5s 发完
        writer.join(5000);
        sender.join(5000);
    }

    private static Thread daemon(String name, Runnable r) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        t.start();
        return t;
    }

    // -------------------- writer --------------------

    private void writeLoop() {
        List<String> batch = new ArrayList<>(BATCH);
        while (running || !queue.isEmpty()) {
            try {
                String first = running ? queue.poll(FLUSH_MS, TimeUnit.MILLISECONDS) : queue.poll();
                if (first == null) {
                    continue;
                }
                batch.add(first);
                queue.drainTo(batch, BATCH - 1);
                append(batch);
            } catch (InterruptedException e) {
                // 停机: 循环条件转为清空队列
            } catch (Exception e) {
                dropped.addAndGet(batch.size());
                log.warn("AuditSpool 落盘失败, 丢弃 {} 条: {}", batch.size(), e.toString());
            } finally {
                batch.clear();
            }
        }
    }

    private void append(List<String> lines) throws IOException {
        StringBuilder sb = new StringBuilder();
        for (String l : lines) {
            sb.append(l).append('\n');
        }
        byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);
        synchronized (fileLock) {
            if (current == null || !Files.exists(current) || Files.size(current) >= ROLL_BYTES) {
                current = dir.resolve(PREFIX + System.currentTimeMillis() + SUFFIX);
            }
            try (FileChannel ch = FileChannel.open(current, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
                ch.write(ByteBuffer.wrap(bytes));
                ch.force(true);
            }
            written.addAndGet(lines.size());
            enforceCap();
        }
    }

    /** 目录超上限删最旧文件 (不删当前写入文件), 删掉的未发行数计 dropped */
    private void enforceCap() throws IOException {
        List<Path> all = files();
        long total = 0;
        for (Path f : all) {
            total += Files.size(f);
        }
        Offset off = readOffset();
        for (Path f : all) {
            if (total <= CAP_BYTES || f.equals(current)) {
                break;
            }
            long size = Files.size(f);
            long lost = countLines(f, f.equals(off.file) ? off.pos : 0);
            Files.delete(f);
            total -= size;
            dropped.addAndGet(lost);
            sent.addAndGet(lost);
            log.warn("AuditSpool 目录超 {}MB, 删除最旧 {} 丢失 {} 条", CAP_BYTES >> 20, f.getFileName(), lost);
        }
    }

    // -------------------- sender --------------------

    private void sendLoop() {
        long backoff = BACKOFF_MIN_MS;
        while (running) {
            try {
                Batch b = next();
                if (b == null) {
                    Thread.sleep(FLUSH_MS);
                    continue;
                }
                int code = console.audit(b.lines);
                if (code == 200) {
                    commit(b);
                    backoff = BACKOFF_MIN_MS;
                    continue;
                }
                // 403 (节点被禁用/密钥重置): 暂停 30s; 其余 (503/网络) 指数退避
                long wait = code == 403 ? BACKOFF_MAX_MS : backoff;
                backoff = Math.min(backoff * 2, BACKOFF_MAX_MS);
                log.warn("AuditSpool 上报失败 code={} 待补发 {} 条, {}s 后重试", code, pending(), wait / 1000);
                Thread.sleep(wait);
            } catch (InterruptedException e) {
                // 停机
            } catch (Exception e) {
                log.warn("AuditSpool 发送异常: {}", e.toString());
                try {
                    Thread.sleep(backoff);
                } catch (InterruptedException ignore) {
                    // 停机
                }
                backoff = Math.min(backoff * 2, BACKOFF_MAX_MS);
            }
        }
    }

    private record Batch(Path file, long from, long to, List<String> lines) {
    }

    private record Offset(Path file, long pos) {
    }

    /** 最旧文件 offset 之后最多 BATCH 个完整行; 已读尽的旧文件顺手删除 */
    private Batch next() throws IOException {
        synchronized (fileLock) {
            Offset off = readOffset();
            for (Path f : files()) {
                long pos = f.equals(off.file) ? off.pos : 0;
                long size = Files.size(f);
                if (pos >= size) {
                    if (!f.equals(current)) {
                        Files.delete(f);
                    }
                    continue;
                }
                byte[] buf;
                try (FileChannel ch = FileChannel.open(f, StandardOpenOption.READ)) {
                    ByteBuffer bb = ByteBuffer.allocate((int) Math.min(size - pos, 4L << 20));
                    ch.read(bb, pos);
                    buf = new byte[bb.position()];
                    bb.flip();
                    bb.get(buf);
                }
                List<String> lines = new ArrayList<>(BATCH);
                int start = 0;
                for (int i = 0; i < buf.length && lines.size() < BATCH; i++) {
                    if (buf[i] == '\n') {
                        if (i > start) {
                            lines.add(new String(buf, start, i - start, StandardCharsets.UTF_8));
                        }
                        start = i + 1;
                    }
                }
                if (lines.isEmpty()) {
                    // 只有半行 (writer 写入中) 或 4MB 内无换行的坏行: 后者跳过
                    if (buf.length >= (4 << 20)) {
                        writeOffset(f, pos + buf.length);
                    }
                    return null;
                }
                return new Batch(f, pos, pos + start, lines);
            }
            return null;
        }
    }

    private void commit(Batch b) throws IOException {
        synchronized (fileLock) {
            writeOffset(b.file, b.to);
            sent.addAndGet(b.lines.size());
            if (Files.exists(b.file) && b.to >= Files.size(b.file) && !b.file.equals(current)) {
                Files.delete(b.file);
            }
        }
    }

    // -------------------- 文件工具 --------------------

    private List<Path> files() throws IOException {
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> p.getFileName().toString().startsWith(PREFIX) && p.getFileName().toString().endsWith(SUFFIX))
                    .sorted().toList();
        }
    }

    private Path offsetFile() {
        return dir.resolve("offset");
    }

    private Offset readOffset() {
        try {
            if (Files.exists(offsetFile())) {
                String[] p = Files.readString(offsetFile()).trim().split("\n");
                if (p.length == 2) {
                    return new Offset(dir.resolve(p[0].trim()), Long.parseLong(p[1].trim()));
                }
            }
        } catch (Exception e) {
            log.warn("AuditSpool offset 文件损坏, 从头补发: {}", e.toString());
        }
        return new Offset(null, 0);
    }

    private void writeOffset(Path file, long pos) throws IOException {
        Path tmp = dir.resolve("offset.tmp");
        Files.writeString(tmp, file.getFileName() + "\n" + pos);
        Files.move(tmp, offsetFile(), java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    private static long countLines(Path f, long skip) throws IOException {
        long n = 0;
        try (FileChannel ch = FileChannel.open(f, StandardOpenOption.READ)) {
            ByteBuffer bb = ByteBuffer.allocate(1 << 16);
            long pos = skip;
            int read;
            while ((read = ch.read(bb, pos)) > 0) {
                pos += read;
                bb.flip();
                while (bb.hasRemaining()) {
                    if (bb.get() == '\n') {
                        n++;
                    }
                }
                bb.clear();
            }
        }
        return n;
    }

}
