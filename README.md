---
type: index
status: Accepted
updated: 2026-11-21
---

# StuHelper Media

media 管理逻辑文件、不可变版本、上传会话和业务引用。backend 装配授权器、数据库与 storage 服务身份。storage 管理物理副本和供应商接入，resources 等业务模块决定资料审核、发布和访问资格。

## 使用入口

- 查询可用上传用途后创建会话，使用整包上传或按偏移分片续传。服务端核对实际文件类型、长度和摘要，再将文件交给业务审核。本人重复内容满足当前用途、保护要求和读取权限时，可以免传输，仍使用独立版本和审核。
- 经业务批准的版本达到两份健康副本后，当前获准的请求可发布业务引用。storage 将目标补齐到三份副本。具备审核权限的审核员可读取已校验的待审文件。
- 通过有效引用下载，支持 HEAD、ETag、Range 和白名单类型内联。文件清单按当前权限分页。打包支持自定义 ZIP 文件名，并在传输时复核权限。
- 释放引用后停止该入口的交付。所属业务需要恢复时可以保留源文件，并使用新引用再次发布。后台提供任务恢复、积压观测、阻塞重试、有界清理和就绪检查。

接口规则与场景见[模块规格](docs/spec/media.md)。当前验证和正式组合见[实施状态](docs/development/media.md)。

## 本地检查

安装仓库声明的 Go、Node.js 和 pnpm，准备 PostgreSQL 服务端工具，并在仓库根目录运行：

```bash
make setup
bash scripts/check-with-postgres.sh
```

脚本启动仅监听本地 socket 的临时数据库，执行完整 `make check` 后清理。默认从 `pg_config`、PATH 和 `dpkg-query` 查找二进制。可用 `STUHELPER_TEST_PG_BIN` 显式指定安装目录。正式构建与检查默认使用 `GOWORK=off`。

修改 OpenAPI 时用 `make generate` 更新 Go 服务端、Go 客户端和 TypeScript SDK。源码与文档使用 [AGPL-3.0-only](LICENSE) 许可。
