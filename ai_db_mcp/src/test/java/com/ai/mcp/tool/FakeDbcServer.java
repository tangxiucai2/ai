package com.ai.mcp.tool;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 测试用 DBC: 挂在 /dbc/api/agent/* 下, 记录收到的请求 (路径/头/体), 按接口依次回预置的响应
 */
public class FakeDbcServer implements AutoCloseable {

    /** 收到的一次请求 */
    public record Req(String method, String path, Map<String, String> headers, byte[] body, Map<String, Object> json) {
        public String action() {
            return path.substring(path.lastIndexOf('/') + 1);
        }
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpServer server;
    public final List<Req> requests = new CopyOnWriteArrayList<>();
    private final Map<String, Deque<String>> replies = new ConcurrentHashMap<>();
    private final Map<String, Long> delays = new ConcurrentHashMap<>();
    /** 处理放到独立线程: 慢响应不堵 dispatcher, close() 时中断未完成的处理 */
    private final ExecutorService pool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "fake-dbc");
        t.setDaemon(true);
        return t;
    });

    public FakeDbcServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/dbc/api/agent/", ex -> {
            byte[] body = ex.getRequestBody().readAllBytes();
            Map<String, String> headers = new ConcurrentHashMap<>();
            for (String h : new String[]{"X-Dbc-Ticket", "X-Ts", "X-Nonce", "X-Sign", "Content-Type", "Upgrade"}) {
                String v = ex.getRequestHeaders().getFirst(h);
                if (v != null) {
                    headers.put(h, v);
                }
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> json = JSON.readValue(body, Map.class);
            Req req = new Req(ex.getRequestMethod(), ex.getRequestURI().getRawPath(), headers, body, json);
            requests.add(req);
            Long delay = delays.get(req.action());
            if (delay != null) {
                try {
                    Thread.sleep(delay);
                } catch (InterruptedException e) {
                    ex.close();
                    return;
                }
            }
            Deque<String> q = replies.get(req.action());
            String reply = q == null || q.isEmpty() ? "{\"ok\":true,\"data\":{}}" : q.poll();
            byte[] out = reply.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json;charset=UTF-8");
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        server.setExecutor(pool);
        server.start();
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/dbc/api";
    }

    /** 为某个接口排一条响应 (JSON 原文) */
    public void reply(String action, String json) {
        replies.computeIfAbsent(action, k -> new ArrayDeque<>()).add(json);
    }

    /** 让某个接口每次都延迟这么久才响应 (模拟 DBC 卡住) */
    public void delay(String action, long millis) {
        delays.put(action, millis);
    }

    public List<Req> of(String action) {
        return requests.stream().filter(r -> r.action().equals(action)).toList();
    }

    @Override
    public void close() {
        server.stop(0);
        pool.shutdownNow();
    }
}
