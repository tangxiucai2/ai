package com.ai.mcp.tool;

import com.ai.mcp.audit.AuditLog;
import com.ai.mcp.config.ConsoleClient;
import com.ai.mcp.config.McpRequestFilter;
import com.jcraft.jsch.*;
import io.modelcontextprotocol.common.McpTransportContext;
import org.springaicommunity.mcp.annotation.McpTool;
import org.springaicommunity.mcp.annotation.McpToolParam;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class SshTool {

    private final AuditLog audit;
    private final Map<String, Conn<Session>> sessions = new ConcurrentHashMap<>();
    private final IdleReaper<Session> reaper = new IdleReaper<>("ssh-idle-reaper", sessions, Session::disconnect);
    private final Map<String, ChannelExec> activeChannels = new ConcurrentHashMap<>();

    public SshTool(AuditLog audit) {
        this.audit = audit;
    }

    @McpTool(name = "ssh_connect", description = "Create a new SSH connection. "
            + "When the request carries a virtual credential the target is fixed and credentialId is ignored; "
            + "otherwise pass a credentialId obtained from list_credentials")
    public Map<String, Object> ssh_connect(
            @McpToolParam(description = "Credential ID from list_credentials (omit when the request is bound to a fixed credential)", required = false) Long credentialId,
            McpTransportContext ctx) {
        return audit.run(ctx, "ssh_connect", null, "connect", () -> ssh_connect0(credentialId, ctx));
    }

        private Map<String, Object> ssh_connect0(Long credentialId, McpTransportContext ctx) {
        Map<String, Object> result = new HashMap<>();
        ConsoleClient.Resolved cred;
        try {
            // 固定资源模式忽略入参; 用户自选模式按 credentialId 回控制台换凭据 (服务端重新校验授权)
            cred = ToolAuth.resolveForTools(ctx, credentialId);
        } catch (ConsoleClient.Rejected e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            return result;
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", "控制台不可达, 无法校验凭据授权");
            return result;
        }
        if (cred == null) {
            result.put("success", false);
            // 给 LLM 看的引导, 不是给人看的报错: 读到这句它会自己去调列表工具
            result.put("error", "未指定凭据, 请先调用 list_credentials 获取可用凭据列表, 再用其中的 credentialId 重试");
            return result;
        }
        if (!"HOST".equals(cred.category())) {
            result.put("success", false);
            result.put("error", "该凭据不是主机资源");
            return result;
        }
        // 节点句柄总量闸门 (控制台下发 maxConnections, 未配置不限)
        if (IdleReaper.atLimit()) {
            result.put("success", false);
            result.put("error", "节点连接数已达上限, 请稍后重试或释放空闲连接");
            return result;
        }
        String host = cred.address();
        Integer port = cred.port();
        String username = cred.username();
        String password = cred.password();
        int sshPort = port != null ? port : 22;
        // 单资源闸门 (跨凭据合并计数: 同一台机器不论哪个账号登录都算在一起)
        String resource = host + ":" + sshPort;
        if (IdleReaper.atResourceLimit(resource)) {
            result.put("success", false);
            result.put("error", "该资源连接数已达上限, 请稍后重试或释放空闲连接");
            return result;
        }
        
        JSch jsch = new JSch();
        Session session = null;
        
        try {
            session = jsch.getSession(username, host, sshPort);
            
            session.setPassword(password);
            
            session.setConfig("StrictHostKeyChecking", "no");
            session.setConfig("PreferredAuthentications", "password");
            session.setTimeout(30000);
            
            session.connect(30000);
            
            if (!session.isConnected()) {
                result.put("success", false);
                result.put("error", "Failed to establish SSH connection: Connection not established");
                return result;
            }
            
            // 句柄按凭据隔离: credentialId 前缀; 归属元数据与句柄一次 put, 不留「有句柄无归属」的窗口
            String connectionId = cred.credentialId() + ":" + UUID.randomUUID();
            sessions.put(connectionId, new Conn<>(session, ToolAuth.metaOf(ctx, cred, resource)));
            reaper.register(connectionId);
            ToolAuth.markInFlight(ctx, cred.credentialId());
            
            result.put("success", true);
            result.put("connectionId", connectionId);
            result.put("host", host);
            result.put("port", sshPort);
            result.put("username", username);
            result.put("authType", "password");
            result.put("message", "SSH connection established successfully");
            
        } catch (JSchException e) {
            String errorMessage = e.getMessage();
            if (errorMessage != null && errorMessage.contains("Auth fail")) {
                result.put("success", false);
                result.put("error", "SSH authentication failed: Invalid username or password");
            } else if (errorMessage != null && errorMessage.contains("Connection refused")) {
                result.put("success", false);
                result.put("error", "SSH connection failed: Connection refused - host or port may be incorrect");
            } else if (errorMessage != null && errorMessage.contains("timeout")) {
                result.put("success", false);
                result.put("error", "SSH connection failed: Connection timed out");
            } else {
                result.put("success", false);
                result.put("error", "SSH connection failed: " + errorMessage);
            }
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", "Failed to establish SSH connection: " + e.getMessage());
        } finally {
            if (!result.containsKey("success") || !(Boolean) result.get("success")) {
                if (session != null) {
                    try {
                        session.disconnect();
                    } catch (Exception ignored) {}
                }
            }
        }
        
        return result;
    }

    /**
     * 连接取不到时的报错: 若是授权重校验拒绝, 报真实原因而非笼统的「连接不存在」,
     * 否则撤权后的越权尝试在审计里看不出是谁、对哪台机器、为什么被拒
     */
    private static String notFound(String connectionId, McpTransportContext ctx) {
        String reason = McpRequestFilter.denyReason(ctx);
        return reason != null ? reason : "Connection not found: " + connectionId;
    }

    /**
     * 归属校验: 先比本地四元组 (模式/智能体/用户), 用户模式再回控制台按连接元数据里的 credentialId 重校验授权
     * <p>
     * 只比前缀是不够的: 老模式持同一 credentialId 的虚拟凭据会摸到用户模式建的连接
     */
    private Session lookup(String connectionId, McpTransportContext ctx) {
        if (connectionId == null) {
            return null;
        }
        // 先只读校验, 校验通过才 acquire 续期: 被拒的调用不能给连接续命
        Conn<Session> conn = reaper.peek(connectionId);
        if (conn == null || !conn.meta().accessibleBy(ctx)) {
            return null;
        }
        if (!ToolAuth.recheck(ctx, conn.meta())) {
            return null;
        }
        Conn<Session> live = reaper.acquire(connectionId);
        if (live == null) {
            return null;
        }
        // 用句柄前进入在途保护: 超过空闲阈值的长命令不会被回收器掐断
        ToolAuth.markInFlight(ctx, live.meta().credentialId());
        return live.handle();
    }

    @McpTool(name = "ssh_disconnect", description = "Close an existing SSH connection")
    public Map<String, Object> ssh_disconnect(
            @McpToolParam(description = "Connection ID to close") String connectionId, McpTransportContext ctx) {
        return audit.run(ctx, "ssh_disconnect", connectionId, "disconnect", () -> ssh_disconnect0(connectionId, ctx));
    }

        private Map<String, Object> ssh_disconnect0(String connectionId, McpTransportContext ctx) {
        
        Map<String, Object> result = new HashMap<>();
        
        // 以原子 remove 的返回值决定谁负责关闭: 与 sweep/异常清理并发时不会重复关
        Conn<Session> removed = lookup(connectionId, ctx) == null ? null : sessions.remove(connectionId);
        Session session = removed == null ? null : removed.handle();
        ChannelExec channel = session == null ? null : activeChannels.remove(connectionId);
        if (channel != null && channel.isConnected()) {
            channel.disconnect();
        }

        if (session != null) {
            if (session.isConnected()) {
                session.disconnect();
            }
            result.put("success", true);
            result.put("connectionId", connectionId);
            result.put("message", "SSH connection closed successfully");
        } else {
            result.put("success", false);
            result.put("error", notFound(connectionId, ctx));
        }
        
        return result;
    }

    @McpTool(name = "ssh_list_connections", description = "List all active SSH connections")
    public Map<String, Object> ssh_list_connections(McpTransportContext ctx) {
        Map<String, Object> result = new HashMap<>();
        
        List<String> validConnections = new ArrayList<>();
        List<String> invalidConnections = new ArrayList<>();

        // 本工具不走 lookup, 归属过滤必须自己做一遍 (否则可枚举他人连接)
        for (Map.Entry<String, Conn<Session>> entry : sessions.entrySet()) {
            String connectionId = entry.getKey();
            Conn<Session> conn = entry.getValue();
            if (!conn.meta().accessibleBy(ctx)) {
                continue;
            }
            // 明确撤权才跳过; 校验故障整体报错, 否则客户端会把"授权服务挂了"当成"没有连接"而重复建连
            ToolAuth.Verdict v = ToolAuth.verdict(ctx, conn.meta());
            if (v == ToolAuth.Verdict.UNAVAILABLE) {
                result.put("success", false);
                result.put("error", ToolAuth.CONSOLE_UNAVAILABLE);
                return result;
            }
            if (v != ToolAuth.Verdict.ALLOW) {
                continue;
            }
            Session session = conn.handle();
            try {
                if (session.isConnected()) {
                    validConnections.add(connectionId);
                } else {
                    invalidConnections.add(connectionId);
                    sessions.remove(connectionId);
                }
            } catch (Exception e) {
                invalidConnections.add(connectionId);
                sessions.remove(connectionId);
            }
        }
        
        result.put("success", true);
        result.put("connections", validConnections);
        result.put("connectionCount", validConnections.size());
        
        if (!invalidConnections.isEmpty()) {
            result.put("invalidConnectionsRemoved", invalidConnections);
            result.put("invalidCount", invalidConnections.size());
        }
        
        return result;
    }

    @McpTool(name = "ssh_execute", description = "Execute a command on the remote host (supports continuous output)")
    public Map<String, Object> ssh_execute(
            @McpToolParam(description = "Connection ID") String connectionId,
            @McpToolParam(description = "Command to execute") String command, McpTransportContext ctx) {
        return audit.run(ctx, "ssh_execute", connectionId, command, () -> ssh_execute0(connectionId, command, ctx));
    }

        private Map<String, Object> ssh_execute0(String connectionId, String command, McpTransportContext ctx) {
        
        Map<String, Object> result = new HashMap<>();
        
        Session session = lookup(connectionId, ctx);
        if (session == null) {
            result.put("success", false);
            result.put("error", notFound(connectionId, ctx));
            return result;
        }
        
        if (!session.isConnected()) {
            result.put("success", false);
            result.put("error", "Connection is not active: " + connectionId);
            sessions.remove(connectionId);
            return result;
        }
        
        ChannelExec channel = null;
        
        try {
            channel = (ChannelExec) session.openChannel("exec");
            channel.setCommand(command);
            
            InputStream in = channel.getInputStream();
            InputStream err = channel.getErrStream();
            
            channel.connect(10000);
            
            StringBuilder output = new StringBuilder();
            StringBuilder error = new StringBuilder();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            BufferedReader errReader = new BufferedReader(new InputStreamReader(err));
            
            long startTime = System.currentTimeMillis();
            long timeout = 60000;
            
            char[] buffer = new char[1024];
            int len;
            
            while (!channel.isClosed()) {
                if (System.currentTimeMillis() - startTime > timeout) {
                    result.put("success", false);
                    result.put("error", "Command execution timeout");
                    result.put("partialOutput", output.toString());
                    if (error.length() > 0) {
                        result.put("partialError", error.toString());
                    }
                    return result;
                }
                
                while (reader.ready()) {
                    len = reader.read(buffer);
                    if (len > 0) {
                        output.append(buffer, 0, len);
                    }
                }
                
                while (errReader.ready()) {
                    len = errReader.read(buffer);
                    if (len > 0) {
                        error.append(buffer, 0, len);
                    }
                }
                
                Thread.sleep(50);
            }
            
            while (reader.ready()) {
                len = reader.read(buffer);
                if (len > 0) {
                    output.append(buffer, 0, len);
                }
            }
            
            while (errReader.ready()) {
                len = errReader.read(buffer);
                if (len > 0) {
                    error.append(buffer, 0, len);
                }
            }
            
            int exitCode = channel.getExitStatus();
            
            result.put("success", true);
            result.put("connectionId", connectionId);
            result.put("exitCode", exitCode);
            result.put("output", output.toString());
            if (error.length() > 0) {
                result.put("errorOutput", error.toString());
            }
            
        } catch (Exception e) {
            result.put("success", false);
            result.put("connectionId", connectionId);
            result.put("error", "Failed to execute command: " + e.getMessage());
        } finally {
            if (channel != null && channel.isConnected()) {
                channel.disconnect();
            }
        }
        
        return result;
    }

    @McpTool(name = "ssh_execute_long_running", description = "Execute a long-running command with continuous output streaming")
    public Map<String, Object> ssh_execute_long_running(
            @McpToolParam(description = "Connection ID") String connectionId,
            @McpToolParam(description = "Command to execute") String command,
            @McpToolParam(description = "Timeout in milliseconds (0 for no timeout)") Long timeout, McpTransportContext ctx) {
        return audit.run(ctx, "ssh_execute_long_running", connectionId, command, () -> ssh_execute_long_running0(connectionId, command, timeout, ctx));
    }

        private Map<String, Object> ssh_execute_long_running0(String connectionId, String command, Long timeout, McpTransportContext ctx) {
        
        Map<String, Object> result = new HashMap<>();
        
        Session session = lookup(connectionId, ctx);
        if (session == null) {
            result.put("success", false);
            result.put("error", notFound(connectionId, ctx));
            return result;
        }
        
        if (!session.isConnected()) {
            result.put("success", false);
            result.put("error", "Connection is not active: " + connectionId);
            sessions.remove(connectionId);
            return result;
        }
        
        ChannelExec channel = null;
        
        try {
            channel = (ChannelExec) session.openChannel("exec");
            channel.setCommand(command);
            
            InputStream in = channel.getInputStream();
            InputStream err = channel.getErrStream();
            
            channel.connect(10000);
            
            StringBuilder output = new StringBuilder();
            StringBuilder error = new StringBuilder();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            BufferedReader errReader = new BufferedReader(new InputStreamReader(err));
            
            long startTime = System.currentTimeMillis();
            boolean timeoutOccurred = false;
            
            char[] buffer = new char[1024];
            int len;
            
            while (!channel.isClosed()) {
                if (timeout != null && timeout > 0 && System.currentTimeMillis() - startTime > timeout) {
                    timeoutOccurred = true;
                    break;
                }
                
                while (reader.ready()) {
                    len = reader.read(buffer);
                    if (len > 0) {
                        output.append(buffer, 0, len);
                    }
                }
                
                while (errReader.ready()) {
                    len = errReader.read(buffer);
                    if (len > 0) {
                        error.append(buffer, 0, len);
                    }
                }
                
                Thread.sleep(100);
            }
            
            while (reader.ready()) {
                len = reader.read(buffer);
                if (len > 0) {
                    output.append(buffer, 0, len);
                }
            }
            
            while (errReader.ready()) {
                len = errReader.read(buffer);
                if (len > 0) {
                    error.append(buffer, 0, len);
                }
            }
            
            if (timeoutOccurred) {
                result.put("success", false);
                result.put("connectionId", connectionId);
                result.put("error", "Command execution timeout");
                result.put("partialOutput", output.toString());
                if (error.length() > 0) {
                    result.put("partialError", error.toString());
                }
            } else {
                int exitCode = channel.getExitStatus();
                
                result.put("success", true);
                result.put("connectionId", connectionId);
                result.put("exitCode", exitCode);
                result.put("output", output.toString());
                if (error.length() > 0) {
                    result.put("errorOutput", error.toString());
                }
            }
            
        } catch (Exception e) {
            result.put("success", false);
            result.put("connectionId", connectionId);
            result.put("error", "Failed to execute command: " + e.getMessage());
        } finally {
            if (channel != null && channel.isConnected()) {
                channel.disconnect();
            }
        }
        
        return result;
    }
}