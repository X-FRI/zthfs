# ZTHFS - 零信任医疗文件系统

[![License](https://img.shields.io/badge/license-BSD3--Clause-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-blue.svg)](https://www.rust-lang.org)

## 概述

ZTHFS 是一个面向医疗数据保护的透明加密文件系统项目。项目实现了构建 HIPAA/GDPR 合规存储系统所需的密码学原语和安全机制。

**当前状态**: 项目提供安全库和文件系统操作辅助函数。FUSE 集成尚未完成，因此文件系统无法实际挂载使用。

## 系统架构

系统由八个核心模块构成。加密模块和完整性模块构成密码学基础。安全模块实现访问控制和审计日志。事务管理模块提供原子操作和崩溃恢复。密钥管理模块负责密钥的安全存储和轮转。

文件操作在 `operations.rs` 中实现为独立函数。这些函数支持大文件分块存储、部分写入操作和基于 inode 的文件追踪。但 FUSE 文件系统 trait 未实现，因此这些操作无法通过挂载的文件系统访问。

## 密码学安全

加密采用 AES-256-GCM，每文件使用唯一 nonce。nonce 通过 BLAKE3(path || nonce_seed) 派生，确保文件间 nonce 既确定又不可预测。该构造防止 nonce 重用，同时保持文件恢复的可重现性。

完整性验证支持两种算法。BLAKE3 通过密钥哈希提供密码学消息认证。CRC32c 为非关键数据提供轻量级替代方案。校验和存储为扩展属性，支持不解密验证。

时序攻击防护模块使用 `subtle` crate 的常量时间比较。认证失败触发指数退避延迟，从 100ms 开始，每次失败翻倍，上限 5 秒。失败尝试计数跨请求持久化，锁定时长计算为 2^(attempt_count - 1) 秒，上限 1 小时。

## 访问控制

安全验证器实现 POSIX 权限检查，配合用户和组白名单。文件访问要求 `allowed_users` 或 `allowed_groups` 成员资格。权限检查器从文件元数据提取所有者、组和权限位，然后应用标准 POSIX rwx 逻辑。

零信任模式通过 `with_zero_trust_root()` 启用，移除传统 root 绕过机制。该模式下 uid 0 必须通过与其他用户相同的权限检查，且必须出现在允许用户列表中。root 访问尝试生成 High 级别的审计日志条目。

## 事务管理

预写日志 (WAL) 确保原子操作和崩溃恢复。每个事务在执行前记录到独立的 WAL 文件。事务生命周期经历三个状态：InProgress、Committed 和 RolledBack。启动时 WAL 扫描未完成的事务并自动回滚。

写时复制 (COW) 原语实现原子文件更新。`atomic_write` 函数将数据写入临时文件，同步到磁盘，然后重命名覆盖目标。POSIX 保证原子重命名操作，防止部分写入。

## 密钥管理

密钥管理系统提供可插拔存储接口。`InMemoryKeyStorage` 服务于测试场景。`FileKeyStorage` 使用主密钥加密密钥存储，主密钥派生自系统特定熵（主机名、machine-id、用户名）。每个密钥附带元数据存储，包括版本号、创建时间戳和过期时间。

密钥轮换生成新版本并递增版本计数器。旧版本保持可用直到手动删除，支持渐进式密钥迁移。默认密钥保护机制防止意外删除主加密密钥。

## 使用方式

### 库 API

核心模块暴露 Rust API 供应用集成：

```rust
use zthfs::{
    core::encryption::EncryptionHandler,
    core::integrity::IntegrityHandler,
    config::EncryptionConfig,
};

let config = EncryptionConfig::random()?;
let handler = EncryptionHandler::new(&config);
let encrypted = handler.encrypt(data, "/path/to/file")?;

let checksum = IntegrityHandler::compute_checksum(
    &encrypted, "blake3", &config.key,
)?;
```

### 命令行界面

二进制文件提供七个子命令：

- `init` 生成带随机密钥的配置文件
- `validate` 检查配置文件语法和安全设置
- `mount` 尝试 FUSE 挂载（当前不可用）
- `unmount` 卸载已挂载的文件系统
- `health` 显示组件状态
- `demo` 运行加密操作演示
- `info` 显示版本和构建信息

## 测试

测试套件包含 103 个单元测试，覆盖加密操作、安全验证、密钥管理和事务处理。主分支所有测试通过。

执行 `cargo test --lib` 运行测试。集成测试和 FUSE 文件系统测试尚未实现。

## 实现状态

已完成模块：加密、完整性、日志、配置、安全验证、事务、密钥管理。

部分实现：文件系统操作以函数形式存在，但缺少 FUSE 集成。

未实现：FUSE 文件系统 trait、HSM/KMS 后端（feature flag 存在但为空）、性能监控、集成测试。

## 开发路线图

短期优先级包括完成 FUSE 文件系统集成和添加集成测试。中期目标覆盖 HSM/KMS 后端和生产部署工具。长期目标指向分布式存储和多租户隔离。

## 许可证

```
Copyright (c) 2025 Somhairle H. Marisol

All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * Neither the name of ZTHFS nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
