package com.ai.mcp.tool;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import io.modelcontextprotocol.common.McpTransportContext;
import org.springaicommunity.mcp.annotation.McpTool;
import org.springaicommunity.mcp.annotation.McpToolParam;
import org.springframework.stereotype.Component;

import com.ai.mcp.audit.AuditLog;
import com.ai.mcp.config.ConsoleClient;
import com.ai.mcp.config.McpRequestFilter;

@Component
public class DatabaseTool {

    private final AuditLog audit;
    private final Map<String, Connection> connections = new ConcurrentHashMap<>();
    private final IdleReaper<Connection> reaper = new IdleReaper<>("db-idle-reaper", connections, c -> {
        try {
            c.close();
        } catch (Exception ignore) {
        }
    });

    public DatabaseTool(AuditLog audit) {
        this.audit = audit;
    }

    @McpTool(name = "db_create_connection", description = "Create a new database connection using the credential bound to this request (no parameters needed)")
    public Map<String, Object> db_create_connection(McpTransportContext ctx) {
        return audit.run(ctx, "db_create_connection", null, "connect", () -> db_create_connection0(ctx));
    }

        private Map<String, Object> db_create_connection0(McpTransportContext ctx) {
        Map<String, Object> result = new HashMap<>();
        ConsoleClient.Resolved cred = McpRequestFilter.credential(ctx);
        if (cred == null || !"DATABASE".equals(cred.category())) {
            result.put("success", false);
            result.put("error", "当前虚拟凭据不是数据库资源");
            return result;
        }
        // 节点句柄总量闸门 (控制台下发 maxConnections, 未配置不限)
        if (IdleReaper.atLimit()) {
            result.put("success", false);
            result.put("error", "节点连接数已达上限, 请稍后重试或释放空闲连接");
            return result;
        }
        String url = jdbcUrl(cred);
        if (url == null) {
            result.put("success", false);
            result.put("error", "不支持的数据库类型: " + cred.dbType());
            return result;
        }
        try {
            // 句柄按凭据隔离: credentialId 前缀, 其他凭据的 connectionId 一律"不存在"
            String connectionId = cred.credentialId() + ":" + UUID.randomUUID();
            Connection conn = java.sql.DriverManager.getConnection(url, cred.username(), cred.password());
            connections.put(connectionId, conn);
            reaper.touch(connectionId);
            result.put("success", true);
            result.put("connectionId", connectionId);
            result.put("dbType", cred.dbType());
            result.put("message", "Connection created successfully");
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", "Failed to create connection: " + e.getMessage());
        }
        return result;
    }

    /** aisDriver 内置 mysql/postgresql/oracle/db2/gbase 驱动 */
    static String jdbcUrl(ConsoleClient.Resolved c) {
        String hp = c.address() + ":" + c.port();
        String db = c.dbName() == null ? "" : c.dbName();
        return switch (c.dbType() == null ? "" : c.dbType()) {
            // 不强制 useSSL=false: 由驱动协商 TLS, 兼容 require_secure_transport=ON 的实例
            case "MYSQL" -> "jdbc:mysql://" + hp + "/" + db + "?allowPublicKeyRetrieval=true";
            case "POSTGRESQL" -> "jdbc:postgresql://" + hp + "/" + db;
            case "ORACLE" -> "jdbc:oracle:thin:@" + hp + "/" + db;
            case "DB2" -> "jdbc:db2://" + hp + "/" + db;
            // GBASE8S 走 Informix 协议 (jdbc:gbasedbt-sqli), aisDriver 未打包该驱动, 归入不支持
            case "GBASE", "GBASE8A" -> "jdbc:gbase://" + hp + "/" + db;
            default -> null;
        };
    }

    /** 只允许操作当前请求凭据前缀下的句柄 */
    private Connection lookup(String connectionId, McpTransportContext ctx) {
        ConsoleClient.Resolved cred = McpRequestFilter.credential(ctx);
        if (cred == null || connectionId == null || !connectionId.startsWith(cred.credentialId() + ":")) {
            return null;
        }
        return reaper.acquire(connectionId);
    }

    @McpTool(name = "db_close_connection", description = "Close an existing database connection")
    public Map<String, Object> db_close_connection(
            @McpToolParam(description = "Connection ID to close") String connectionId, McpTransportContext ctx) {
        return audit.run(ctx, "db_close_connection", connectionId, "disconnect", () -> db_close_connection0(connectionId, ctx));
    }

        private Map<String, Object> db_close_connection0(String connectionId, McpTransportContext ctx) {
        Map<String, Object> result = new HashMap<>();
        
        Connection conn = lookup(connectionId, ctx) == null ? null : connections.remove(connectionId);
        if (conn != null) {
            try {
                conn.close();
                result.put("success", true);
                result.put("message", "Connection closed successfully");
            } catch (SQLException e) {
                result.put("success", false);
                result.put("error", "Error closing connection: " + e.getMessage());
            }
        } else {
            result.put("success", false);
            result.put("error", "Connection not found: " + connectionId);
        }
        
        return result;
    }

    @McpTool(name = "db_list_connections", description = "List all valid database connections")
    public Map<String, Object> db_list_connections(McpTransportContext ctx) {
        Map<String, Object> result = new HashMap<>();
        List<String> validConnections = new ArrayList<>();
        List<String> invalidConnections = new ArrayList<>();
        ConsoleClient.Resolved cred = McpRequestFilter.credential(ctx);
        String prefix = cred == null ? null : cred.credentialId() + ":";

        for (Map.Entry<String, Connection> entry : connections.entrySet()) {
            String connectionId = entry.getKey();
            if (prefix == null || !connectionId.startsWith(prefix)) {
                continue;
            }
            Connection conn = entry.getValue();
            try {
                if (conn.isValid(2)) {
                    validConnections.add(connectionId);
                } else {
                    invalidConnections.add(connectionId);
                    connections.remove(connectionId);
                }
            } catch (SQLException e) {
                invalidConnections.add(connectionId);
                connections.remove(connectionId);
            }
        }

        result.put("success", true);
        result.put("connections", validConnections);
        result.put("count", validConnections.size());
        if (!invalidConnections.isEmpty()) {
            result.put("invalidConnectionsRemoved", invalidConnections);
            result.put("invalidCount", invalidConnections.size());
        }
        return result;
    }

    @McpTool(name = "db_execute", description = "Execute a SQL query or update statement")
    public Map<String, Object> db_execute(
            @McpToolParam(description = "Connection ID") String connectionId,
            @McpToolParam(description = "SQL statement to execute") String sql, McpTransportContext ctx) {
        return audit.run(ctx, "db_execute", connectionId, sql, () -> db_execute0(connectionId, sql, ctx));
    }

        private Map<String, Object> db_execute0(String connectionId, String sql, McpTransportContext ctx) {
        Map<String, Object> result = new HashMap<>();
        
        Connection conn = lookup(connectionId, ctx);
        if (conn == null) {
            result.put("success", false);
            result.put("error", "Connection not found: " + connectionId);
            return result;
        }

        try {
            sql = sql.trim();
            boolean isSelect = sql.toLowerCase().startsWith("select") ||
                              sql.toLowerCase().startsWith("with");

            if (isSelect) {
                return executeSelect(conn, sql);
            } else {
                return executeUpdate(conn, sql);
            }
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", "SQL execution error: " + e.getMessage());
            return result;
        }
    }

    @McpTool(name = "db_execute_transaction", description = "Execute multiple SQL statements in a transaction")
    public Map<String, Object> db_execute_transaction(
            @McpToolParam(description = "Connection ID") String connectionId,
            @McpToolParam(description = "List of SQL statements") List<String> sqlList, McpTransportContext ctx) {
        return audit.run(ctx, "db_execute_transaction", connectionId, sqlList == null ? "" : String.join("; ", sqlList),
                () -> db_execute_transaction0(connectionId, sqlList, ctx));
    }

        private Map<String, Object> db_execute_transaction0(String connectionId, List<String> sqlList, McpTransportContext ctx) {
        Map<String, Object> result = new HashMap<>();
        
        Connection conn = lookup(connectionId, ctx);
        if (conn == null) {
            result.put("success", false);
            result.put("error", "Connection not found: " + connectionId);
            return result;
        }

        boolean originalAutoCommit = true;

        try {
            originalAutoCommit = conn.getAutoCommit();
            conn.setAutoCommit(false);

            List<Map<String, Object>> results = new ArrayList<>();

            for (String sql : sqlList) {
                Map<String, Object> stmtResult = new HashMap<>();
                try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                    long affectedRows = stmt.executeUpdate();
                    stmtResult.put("sql", sql);
                    stmtResult.put("affectedRows", affectedRows);
                    stmtResult.put("success", true);
                } catch (Exception e) {
                    stmtResult.put("sql", sql);
                    stmtResult.put("success", false);
                    stmtResult.put("error", e.getMessage());
                    throw e;
                }
                results.add(stmtResult);
            }

            conn.commit();
            result.put("success", true);
            result.put("message", "Transaction committed successfully");
            result.put("results", results);

        } catch (Exception e) {
            try {
                conn.rollback();
            } catch (SQLException se) {
                result.put("rollbackError", se.getMessage());
            }
            result.put("success", false);
            result.put("error", "Transaction failed: " + e.getMessage());
        } finally {
            try {
                conn.setAutoCommit(originalAutoCommit);
            } catch (SQLException e) {
                result.put("cleanupError", e.getMessage());
            }
        }

        return result;
    }

    private Map<String, Object> executeSelect(Connection conn, String sql) throws SQLException {
        Map<String, Object> result = new HashMap<>();
        
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {
            
            ResultSetMetaData metaData = rs.getMetaData();
            int columnCount = metaData.getColumnCount();

            List<String> columns = new ArrayList<>();
            for (int i = 1; i <= columnCount; i++) {
                columns.add(metaData.getColumnLabel(i));
            }

            List<List<Object>> rows = new ArrayList<>();
            while (rs.next()) {
                List<Object> row = new ArrayList<>();
                for (int i = 1; i <= columnCount; i++) {
                    row.add(rs.getObject(i));
                }
                rows.add(row);
            }

            result.put("success", true);
            result.put("type", "query");
            result.put("columns", columns);
            result.put("rows", rows);
            result.put("rowCount", rows.size());
        }
        
        return result;
    }

    private Map<String, Object> executeUpdate(Connection conn, String sql) throws SQLException {
        Map<String, Object> result = new HashMap<>();
        
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            long affectedRows = stmt.executeUpdate();
            result.put("success", true);
            result.put("type", "update");
            result.put("affectedRows", affectedRows);
            result.put("message", "Successfully updated " + affectedRows + " rows");
        }
        
        return result;
    }
}
