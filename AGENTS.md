---
type: guide
status: Accepted
updated: 2026-11-21
---

# 文件模块工程约定

遵循[StuHelper 工作区工程约定](https://github.com/StuHelper/stuhelper/blob/develop/AGENTS.md)。media 拥有逻辑文件、版本、上传会话、引用、恢复任务、请求重放、审计、outbox 和迁移。独立数据库身份只访问 media 数据。

storage 是 `module.json` 登记的必需依赖。副本与共享内容通过 storage 公开接口访问。装配方注入当前授权和源文件保留规则，所属业务模块提供保留决定。

维护 `contracts/media.openapi.json` 后执行 `make generate`，同步 Go 与 TypeScript SDK。Handler → Service → Repository。用途定义和保护分类由服务端配置，审核必须使用当前授权。

使用独立 PostgreSQL 验证持久化、权限和失败路径。将已实现场景及实际测试函数登记在 `module.json` 的 `scenario_tests`。本地检查入口见[README](README.md#本地检查)，场景预期见[模块规格](docs/spec/media.md)。
