package com.aidb.mcp.tool;

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

import org.springaicommunity.mcp.annotation.McpTool;
import org.springaicommunity.mcp.annotation.McpToolParam;
import org.springframework.stereotype.Component;

@Component
public class DatabaseTool {

    private final Map<String, Connection> connections = new ConcurrentHashMap<>();

    @McpTool(name = "create_connection", description = "Create a new database connection")
    public Map<String, Object> create_connection(
            @McpToolParam(description = "Database connection string") String connectionString,
            @McpToolParam(description = "Database username") String username,
            @McpToolParam(description = "Database password") String password) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            String connectionId = UUID.randomUUID().toString();
            Connection conn = java.sql.DriverManager.getConnection(connectionString, username, password);
            connections.put(connectionId, conn);
            
            result.put("success", true);
            result.put("connectionId", connectionId);
            result.put("message", "Connection created successfully");
            
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", "Failed to create connection: " + e.getMessage());
        }
        
        return result;
    }

    @McpTool(name = "close_connection", description = "Close an existing database connection")
    public Map<String, Object> close_connection(
            @McpToolParam(description = "Connection ID to close") String connectionId) {
        Map<String, Object> result = new HashMap<>();
        
        Connection conn = connections.remove(connectionId);
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

    @McpTool(name = "list_connections", description = "List all valid database connections")
    public Map<String, Object> list_connections() {
        Map<String, Object> result = new HashMap<>();
        List<String> validConnections = new ArrayList<>();
        List<String> invalidConnections = new ArrayList<>();

        for (Map.Entry<String, Connection> entry : connections.entrySet()) {
            String connectionId = entry.getKey();
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

    @McpTool(name = "execute", description = "Execute a SQL query or update statement")
    public Map<String, Object> execute(
            @McpToolParam(description = "Connection ID") String connectionId,
            @McpToolParam(description = "SQL statement to execute") String sql) {
        Map<String, Object> result = new HashMap<>();
        
        Connection conn = connections.get(connectionId);
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

    @McpTool(name = "execute_transaction", description = "Execute multiple SQL statements in a transaction")
    public Map<String, Object> execute_transaction(
            @McpToolParam(description = "Connection ID") String connectionId,
            @McpToolParam(description = "List of SQL statements") List<String> sqlList) {
        Map<String, Object> result = new HashMap<>();
        
        Connection conn = connections.get(connectionId);
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
