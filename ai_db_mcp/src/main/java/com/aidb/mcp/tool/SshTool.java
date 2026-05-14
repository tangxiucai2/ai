package com.aidb.mcp.tool;

import com.jcraft.jsch.*;
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

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Map<String, ChannelExec> activeChannels = new ConcurrentHashMap<>();

    @McpTool(name = "ssh_connect", description = "Create a new SSH connection to a remote host. Either password or privateKey must be provided, not both.")
    public Map<String, Object> ssh_connect(
            @McpToolParam(description = "Remote host address") String host,
            @McpToolParam(description = "SSH port (default: 22)") Integer port,
            @McpToolParam(description = "Username for authentication") String username,
            @McpToolParam(description = "Password for password-based authentication") String password,
            @McpToolParam(description = "Private key content for key-based authentication") String privateKey,
            @McpToolParam(description = "Passphrase for encrypted private key") String passphrase) {
        
        Map<String, Object> result = new HashMap<>();
        
        if (host == null || host.isEmpty()) {
            result.put("success", false);
            result.put("error", "Host is required");
            return result;
        }
        
        if (username == null || username.isEmpty()) {
            result.put("success", false);
            result.put("error", "Username is required");
            return result;
        }
        
        boolean hasPassword = password != null && !password.isEmpty();
        boolean hasPrivateKey = privateKey != null && !privateKey.isEmpty();
        
        if (!hasPassword && !hasPrivateKey) {
            result.put("success", false);
            result.put("error", "Either password or privateKey must be provided");
            return result;
        }
        
        if (hasPassword && hasPrivateKey) {
            result.put("success", false);
            result.put("error", "Cannot use both password and privateKey authentication at the same time");
            return result;
        }
        
        JSch jsch = new JSch();
        Session session = null;
        
        try {
            if (hasPrivateKey) {
                jsch.addIdentity("mcp-ssh-key", privateKey.getBytes(), null, 
                    passphrase != null ? passphrase.getBytes() : null);
            }
            
            int sshPort = port != null ? port : 22;
            session = jsch.getSession(username, host, sshPort);
            
            if (hasPassword) {
                session.setPassword(password);
            }
            
            session.setConfig("StrictHostKeyChecking", "no");
            session.setConfig("PreferredAuthentications", "password");
            session.setTimeout(30000);
            
            session.connect(30000);
            
            if (!session.isConnected()) {
                result.put("success", false);
                result.put("error", "Failed to establish SSH connection: Connection not established");
                return result;
            }
            
            String connectionId = UUID.randomUUID().toString();
            sessions.put(connectionId, session);
            
            result.put("success", true);
            result.put("connectionId", connectionId);
            result.put("host", host);
            result.put("port", sshPort);
            result.put("username", username);
            result.put("authType", hasPassword ? "password" : "privateKey");
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

    @McpTool(name = "ssh_disconnect", description = "Close an existing SSH connection")
    public Map<String, Object> ssh_disconnect(
            @McpToolParam(description = "Connection ID to close") String connectionId) {
        
        Map<String, Object> result = new HashMap<>();
        
        ChannelExec channel = activeChannels.remove(connectionId);
        if (channel != null && channel.isConnected()) {
            channel.disconnect();
        }
        
        Session session = sessions.remove(connectionId);
        if (session != null) {
            if (session.isConnected()) {
                session.disconnect();
            }
            result.put("success", true);
            result.put("connectionId", connectionId);
            result.put("message", "SSH connection closed successfully");
        } else {
            result.put("success", false);
            result.put("error", "Connection not found: " + connectionId);
        }
        
        return result;
    }

    @McpTool(name = "ssh_list_connections", description = "List all active SSH connections")
    public Map<String, Object> ssh_list_connections() {
        Map<String, Object> result = new HashMap<>();
        
        List<String> validConnections = new ArrayList<>();
        List<String> invalidConnections = new ArrayList<>();

        for (Map.Entry<String, Session> entry : sessions.entrySet()) {
            String connectionId = entry.getKey();
            Session session = entry.getValue();
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
            @McpToolParam(description = "Command to execute") String command) {
        
        Map<String, Object> result = new HashMap<>();
        
        Session session = sessions.get(connectionId);
        if (session == null) {
            result.put("success", false);
            result.put("error", "Connection not found: " + connectionId);
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
            @McpToolParam(description = "Timeout in milliseconds (0 for no timeout)") Long timeout) {
        
        Map<String, Object> result = new HashMap<>();
        
        Session session = sessions.get(connectionId);
        if (session == null) {
            result.put("success", false);
            result.put("error", "Connection not found: " + connectionId);
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