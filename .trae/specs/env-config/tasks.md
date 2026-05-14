# MCP服务环境信息配置 - 实现计划

## [x] Task 1: 创建McpRequestFilter过滤器
- **Priority**: P0
- **Depends On**: None
- **Description**: 
  - 创建Servlet Filter用于捕获HTTP请求
  - 提供从header中读取数据库连接参数的方法
  - 支持的header: X-AIDB-CONNECTION-STRING, X-AIDB-USERNAME, X-AIDB-PASSWORD
- **Acceptance Criteria Addressed**: AC-2
- **Test Requirements**:
  - `programmatic` TR-1.1: Filter能够正确捕获HTTP请求
  - `programmatic` TR-1.2: 能够从header中正确读取连接参数
- **Notes**: 使用ThreadLocal存储请求，确保线程安全

## [x] Task 2: 注册Filter并配置CORS
- **Priority**: P0
- **Depends On**: Task 1
- **Description**: 
  - 在CorsConfig中注册McpRequestFilter
  - 配置CORS允许自定义header
- **Acceptance Criteria Addressed**: AC-2, NFR-3
- **Test Requirements**:
  - `programmatic` TR-2.1: Filter被正确注册
  - `human-judgment` TR-2.2: CORS配置正确允许自定义header
- **Notes**: 设置Filter顺序为1，确保在其他Filter之前执行

## [x] Task 3: 修改DatabaseTool使用环境配置
- **Priority**: P0
- **Depends On**: Task 1, Task 2
- **Description**: 
  - 修改 `create_connection` 方法，添加McpMeta参数
  - 将connectionString、username、password参数改为可选（允许为null）
  - 实现参数优先级逻辑：方法参数 > McpMeta > HTTP header
- **Acceptance Criteria Addressed**: AC-1, AC-3, AC-4, AC-5
- **Test Requirements**:
  - `programmatic` TR-3.1: McpMeta参数能够被正确注入
  - `programmatic` TR-3.2: 不传参数时使用McpMeta或HTTP header中的配置创建连接
  - `programmatic` TR-3.3: 传入参数时优先使用传入的参数
  - `programmatic` TR-3.4: McpMeta优先于HTTP header
- **Notes**: 需要注意参数优先级顺序

## [x] Task 4: 验证实现
- **Priority**: P1
- **Depends On**: Task 1, Task 2, Task 3
- **Description**: 
  - 编译并启动应用
  - 测试create_connection方法在各种参数来源情况下的行为
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-3, AC-4, AC-5
- **Test Requirements**:
  - `programmatic` TR-4.1: 应用能够正常启动
  - `programmatic` TR-4.2: 无参数调用create_connection使用McpMeta或HTTP header配置
  - `programmatic` TR-4.3: 有参数调用create_connection优先使用传入参数
  - `programmatic` TR-4.4: McpMeta优先于HTTP header
- **Notes**: 需要确认测试环境有可用的数据库连接