# 文件模块工程约定

遵循 Next 工作区 AGENTS.md。media 拥有逻辑文件、版本、上传会话、引用、恢复任务、审计和迁移。存储副本通过 storage 公开接口管理，不读写 storage 或业务模块的数据表。

先维护 contracts/media.openapi.json，再生成 Go 与 TypeScript SDK。Handler → Service → Repository；业务授权由装配方提供，客户端不能自行指定密级或声明审核通过。

关键失败路径使用真实 PostgreSQL 验证。供应商和业务授权夹具仅用于隔离测试，不开放演示身份。受限文件加密、在线阅读器和用户贡献不属于本模块。
