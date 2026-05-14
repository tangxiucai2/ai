# MCP服务环境信息配置 - 产品需求文档

## Overview
- **Summary**: 为MCP服务增加环境信息配置功能，使得在创建数据库连接时，如果环境配置中已经包含了连接参数，可以直接使用而无需每次都传入。支持通过MCP请求元数据（McpMeta）和HTTP header两种方式配置。
- **Purpose**: 简化数据库连接的创建过程，支持通过多种方式预设数据库连接参数，提高使用便利性。
- **Target Users**: 使用该MCP服务的开发者和AI应用

## Goals
- [x] 支持从MCP请求的元数据（McpMeta）中读取数据库连接参数
- [x] 支持从HTTP header中读取数据库连接参数
- [x] 修改create_connection方法，使其能够使用环境配置中的默认值
- [x] 当调用时未传入参数时，自动使用环境配置中的值

## Non-Goals (Out of Scope)
- 不支持多种数据库连接的环境配置（只支持一套默认配置）
- 不涉及数据库连接池的管理
- 不修改现有的数据库操作逻辑（execute, close_connection等）

## Background & Context
- 当前的create_connection方法需要用户每次调用时都传入connectionString、username和password参数
- 用户希望能够预设这些参数，简化调用流程
- Spring AI MCP框架支持通过McpMeta参数自动注入请求元数据
- 由于MCP框架不直接支持从HTTP header获取元数据，需要通过Servlet Filter实现

## Functional Requirements
- **FR-1**: 系统应支持从McpMeta中读取数据库连接参数（connectionString, username, password）
- **FR-2**: 系统应支持从HTTP header中读取数据库连接参数（X-AIDB-CONNECTION-STRING, X-AIDB-USERNAME, X-AIDB-PASSWORD）
- **FR-3**: create_connection方法的参数应改为可选，如果未传入则使用环境配置中的默认值
- **FR-4**: 参数优先级：方法参数 > McpMeta中的值 > HTTP header中的值

## Non-Functional Requirements
- **NFR-1**: 支持通过MCP客户端注册时设置的环境元数据
- **NFR-2**: McpMeta参数应自动注入，不影响工具的JSON schema生成
- **NFR-3**: HTTP header配置应支持CORS跨域访问

## Constraints
- **Technical**: Java 21, Spring Boot 3.x, Spring AI MCP框架
- **Dependencies**: 依赖Spring AI MCP的McpMeta自动注入机制和Servlet Filter机制

## Assumptions
- [x] 用户通过MCP客户端注册时传递环境元数据
- [x] 元数据中的键名为：connectionString, username, password
- [x] HTTP header名称为：X-AIDB-CONNECTION-STRING, X-AIDB-USERNAME, X-AIDB-PASSWORD

## Acceptance Criteria

### AC-1: McpMeta参数自动注入
- **Given**: create_connection方法包含McpMeta参数
- **When**: 调用create_connection方法
- **Then**: McpMeta参数被自动注入
- **Verification**: `programmatic`

### AC-2: HTTP header参数可访问
- **Given**: 请求中包含X-AIDB-CONNECTION-STRING等header
- **When**: 调用create_connection方法
- **Then**: 系统能够从header中读取连接参数
- **Verification**: `programmatic`

### AC-3: create_connection使用环境配置
- **Given**: McpMeta或HTTP header中包含数据库连接参数
- **When**: 调用create_connection方法且不传入参数
- **Then**: 使用环境配置中的参数创建连接
- **Verification**: `programmatic`

### AC-4: 方法参数优先于环境配置
- **Given**: 方法参数、McpMeta和HTTP header都提供了连接信息
- **When**: 调用create_connection方法并传入参数
- **Then**: 使用方法传入的参数而不是环境配置
- **Verification**: `programmatic`

### AC-5: McpMeta优先于HTTP header
- **Given**: McpMeta和HTTP header都提供了连接信息
- **When**: 调用create_connection方法且不传入方法参数
- **Then**: 使用McpMeta中的参数而不是HTTP header
- **Verification**: `programmatic`

## Open Questions
- [ ] 无