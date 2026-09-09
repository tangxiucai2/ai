package com.ai.mcp.audit;

import com.ai.mcp.config.ConsoleClient;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 控制台拉取本节点审计日志: 用节点密钥 HMAC 签名 (X-Timestamp + X-Sign), 与认证方式无关
 */
@RestController
public class AuditController {

    private static final int LIMIT_MAX = 1000;

    private final AuditLog audit;
    private final ConsoleClient console;

    public AuditController(AuditLog audit, ConsoleClient console) {
        this.audit = audit;
        this.console = console;
    }

    @GetMapping("/audit/logs")
    public ResponseEntity<Map<String, Object>> logs(
            @RequestHeader(value = "X-Timestamp", required = false) String ts,
            @RequestHeader(value = "X-Sign", required = false) String sign,
            @RequestParam(required = false) String agent,
            @RequestParam(required = false) String user,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String keyword,
            @RequestParam(defaultValue = "200") int limit) {
        if (!console.verifyConsoleSign(ts, sign)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("code", 401, "msg", "签名校验失败"));
        }
        List<AuditLog.Entry> list = audit.query(agent, user, type, status, keyword, Math.max(1, Math.min(limit, LIMIT_MAX)));
        return ResponseEntity.ok(Map.of("total", audit.size(), "list", list));
    }
}
