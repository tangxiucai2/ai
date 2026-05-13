# AI DB MCP Service Specification

## 1. Project Overview

**Project Name:** ai_db_mcp  
**Project Type:** Java MCP (Model Context Protocol) Server based on Spring AI  
**Core Functionality:** A Spring AI-based MCP server that provides database access interfaces to AI models/clients, internally using a custom driver (`aisDriver-1.0-SNAPSHOT.jar`) for multi-database connectivity.  
**Target Users:** AI agents, LLM applications, and any MCP-compatible clients requiring database access.

---

## 2. Technical Stack

- **Language:** Java 21
- **Framework:** Spring Boot 3.2.0 + Spring AI 1.1.6
- **MCP Protocol:** JSON-RPC over HTTP (STATELESS mode)
- **Database Driver:** Custom driver at `lib/aisDriver-1.0-SNAPSHOT.jar`
- **Build Tool:** Maven

---

## 3. Functionality Specification

### 3.1 Core Features

#### 3.1.1 Database Connection Management
- Load and initialize the custom `aisDriver-1.0-SNAPSHOT.jar`
- Support connection configuration via connection string
- Connection pooling using ConcurrentHashMap for efficient resource usage
- Graceful connection cleanup on shutdown

#### 3.1.2 Execute Interface (Primary Tool)

**Tool Name:** `execute`

**Query Operations:**
- Input Parameters:
  - `connectionId` (string, required): Connection identifier
  - `sql` (string, required): SQL SELECT query

- Output:
```json
{
  "success": true,
  "type": "query",
  "columns": ["col1", "col2", ...],
  "rows": [[val1, val2, ...], ...],
  "rowCount": 100
}
```

**Non-Query Operations (INSERT/UPDATE/DELETE):**
- Input Parameters:
  - `connectionId` (string, required): Connection identifier
  - `sql` (string, required): SQL statement

- Output:
```json
{
  "success": true,
  "type": "update",
  "affectedRows": 5,
  "message": "Successfully updated 5 rows"
}
```

#### 3.1.3 Transaction Support

**Tool Name:** `execute_transaction`

- Input Parameters:
  - `connectionId` (string, required): Connection identifier
  - `sqlList` (array, required): Array of SQL statements to execute atomically

- Output (Success):
```json
{
  "success": true,
  "message": "Transaction committed successfully",
  "results": [
    {"sql": "...", "affectedRows": 1, "success": true},
    {"sql": "...", "affectedRows": 5, "success": true}
  ]
}
```

- Output (Failure - automatic rollback):
```json
{
  "success": false,
  "error": "Transaction failed: ..."
}
```

#### 3.1.4 Connection Management Tools

**Tool Name:** `create_connection`
- Input: `connectionString`, `username`, `password`
- Output: Connection ID for subsequent operations

**Tool Name:** `close_connection`
- Input: `connectionId`
- Output: Success/failure status

**Tool Name:** `list_connections`
- Output: List of active connection IDs

---

### 3.2 MCP Protocol Implementation

#### 3.2.1 Transport
- **HTTP Mode (STATELESS):** Primary transport using HTTP POST for JSON-RPC communication
- **Endpoint:** `/mcp`
- **Message Format:** JSON-RPC 2.0

#### 3.2.2 Server Capabilities
- Tools: `execute`, `execute_transaction`, `create_connection`, `close_connection`, `list_connections`
- No resources (initially)
- No prompts (initially)

#### 3.2.3 JSON-RPC Request/Response Handling
- Parse incoming JSON-RPC requests from HTTP POST body
- Send responses with appropriate HTTP status codes
- Log errors to standard logging framework

---

### 3.3 Error Handling

| Error Code | Description |
|------------|-------------|
| -32700 | Parse error - Invalid JSON |
| -32600 | Invalid Request |
| -32601 | Method not found |
| -32602 | Invalid parameters |
| -32603 | Internal error |
| -32001 | Database connection error |
| -32002 | SQL execution error |
| -32003 | Transaction error |

---

## 4. Project Structure

```
ai_db_mcp/
├── pom.xml
├── lib/
│   └── aisDriver-1.0-SNAPSHOT.jar
├── src/
│   └── main/
│       ├── java/
│       │   └── com/
│       │       └── aidb/
│       │           └── mcp/
│       │               ├── AiDbMcpApplication.java    # Main entry point (Spring Boot)
│       │               ├── config/
│       │               │   └── CorsConfig.java       # CORS configuration
│       │               └── tool/
│       │                   └── DatabaseTool.java     # MCP Tools implementation
│       └── resources/
│           └── application.yml                       # Application configuration
└── target/
    └── ai_db_mcp-1.0.0-SNAPSHOT.jar                 # Fat JAR output
```

---

## 5. Acceptance Criteria

### 5.1 Functional Criteria
- [x] Server starts successfully and listens on HTTP port 9090
- [x] `create_connection` establishes database connection and returns connection ID
- [x] `execute` runs SELECT queries and returns JSON results with column names
- [x] `execute` runs INSERT/UPDATE/DELETE and returns affected row count
- [x] `execute_transaction` executes multiple statements atomically with rollback on failure
- [x] `close_connection` properly closes database connection
- [x] `list_connections` returns list of active connection IDs

### 5.2 MCP Protocol Criteria
- [x] All requests/responses conform to JSON-RPC 2.0 specification
- [x] Server advertises correct capabilities
- [x] Tool definitions include proper input/output schemas
- [x] Error responses include appropriate error codes and messages

### 5.3 Non-Functional Criteria
- [x] No hardcoded database credentials
- [x] Proper resource cleanup on shutdown
- [x] Comprehensive error handling with actionable messages
- [x] Code compiles without errors
- [x] System dependencies packaged into fat JAR

---

## 6. Configuration

### 6.1 Application Configuration (application.yml)
```yaml
server:
  port: 9090

spring:
  application:
    name: ai_db_mcp
  ai:
    mcp:
      server:
        protocol: STATELESS
        annotation-scanner:
          enabled: true
          base-packages:
            - com.aidb.mcp
        capabilities:
          tool: true

logging:
  level:
    com.aidb.mcp: DEBUG
    org.springframework.ai: DEBUG
```

### 6.2 Connection Configuration (per connection)
- `connectionString`: JDBC connection string
- `username`: Database username
- `password`: Database password

---

## 7. MCP Tool Definitions

### 7.1 create_connection
```json
{
  "name": "create_connection",
  "description": "Create a new database connection",
  "inputSchema": {
    "type": "object",
    "properties": {
      "connectionString": {"type": "string", "description": "Database connection string"},
      "username": {"type": "string", "description": "Database username"},
      "password": {"type": "string", "description": "Database password"}
    },
    "required": ["connectionString", "username", "password"]
  }
}
```

### 7.2 close_connection
```json
{
  "name": "close_connection",
  "description": "Close an existing database connection",
  "inputSchema": {
    "type": "object",
    "properties": {
      "connectionId": {"type": "string", "description": "Connection ID to close"}
    },
    "required": ["connectionId"]
  }
}
```

### 7.3 list_connections
```json
{
  "name": "list_connections",
  "description": "List all active database connections",
  "inputSchema": {
    "type": "object",
    "properties": {}
  }
}
```

### 7.4 execute
```json
{
  "name": "execute",
  "description": "Execute a SQL query or update statement against the database",
  "inputSchema": {
    "type": "object",
    "properties": {
      "connectionId": {"type": "string", "description": "Database connection ID"},
      "sql": {"type": "string", "description": "SQL statement to execute"}
    },
    "required": ["connectionId", "sql"]
  }
}
```

### 7.5 execute_transaction
```json
{
  "name": "execute_transaction",
  "description": "Execute multiple SQL statements as an atomic transaction",
  "inputSchema": {
    "type": "object",
    "properties": {
      "connectionId": {"type": "string", "description": "Database connection ID"},
      "sqlList": {"type": "array", "items": {"type": "string"}, "description": "List of SQL statements"}
    },
    "required": ["connectionId", "sqlList"]
  }
}
```

---

## 8. Deployment

### 8.1 Build
```bash
mvn clean package
```

### 8.2 Run (Normal Mode)
```bash
java -jar target/ai_db_mcp-1.0.0-SNAPSHOT.jar
```

### 8.3 Run (Debug Mode)
```bash
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -jar target/ai_db_mcp-1.0.0-SNAPSHOT.jar
```

### 8.4 MCP Inspector Connection
- **URL:** `http://localhost:9090/mcp`
- **Transport Type:** HTTP
- **Connection Type:** Direct

---

## 9. CORS Configuration

The server includes CORS configuration to allow MCP Inspector to access the endpoint from any origin.
