# 治理功能本地验收记录（2026-10-01）

五仓库功能分支均为 `codex/wiki-invitation-moderation`，尚未提交、推送或部署。既有 analytics/client-info 工作区改动保留。后续提交按约定先汇入 `developing`，再 PR 合并 `main`。

| 仓库 / 组件 | 验证结果 |
| --- | --- |
| NetHub-Accounts | 86 passed |
| NetHub-Campus-Wiki | 166 passed，4 skipped，17 subtests passed |
| Codex-CAS-Web | 58 passed，4 skipped |
| TechX-Shude-Mood-Barometer | 79 passed |
| To-do-list | 125 passed，18 subtests passed |
| Wiki 媒体 Worker | 21 Node tests passed |

测试使用独立临时 SQLite、测试 OIDC 密钥及明确的测试层服务替身，没有发送真实邮件、调用真实 AI 或修改生产数据库。合计 514 个 Python 用例通过，额外 35 个 subtest 通过。新核心模块 Ruff I/F 检查通过；全部现存新增或修改 Python/JavaScript 文件的语法检查、五仓库 `git diff --check` 通过。

重点覆盖：邀请每日额度并发、撤销不返额度、验证/72 小时限制、7 天过期和重复兑换、验证 GET 不消费/POST 一次性、无邀请注册回滚、客户端凭证和成员权限、中央封禁会话撤销与服务故障 503、JSON 审核结果及发布时作者资格、撤回后的迟到审核、图片顺序与私有访问、人工审核及审计、清理失败重试、旧动态迁移与损坏 JSON 原子回滚、CAS 评论接口及旧库数据移除。

Accounts 实际运行 Alembic 从空库升级到 head，验证单一 head 为 `b147ae690c32`，包含头像和账号治理字段，外键检查通过。演练发现并修正了新迁移错误的前置 revision，防止发布时出现多个 head。

浏览器验收使用回环地址和一次性测试账号：Accounts 登录、个人页、邮箱邀请页、账号处罚入口；Wiki 用户页保存简介后的待审提示与自动刷新、撤回入口、管理页内容审核及提交者信息。Wiki 手机宽度布局已检查。审核状态过滤器显示选中状态；本站限制表单显示本页处理反馈并刷新用户列表。

8 个 skip：Wiki 1 项缺少仓库外真实生产镜像模块、1 项缺少 PATH 上的 FFmpeg、2 项 Windows 符号链接权限不足；CAS 4 项 Windows 符号链接权限不足。保留现有 FastAPI 收集提示及 TechX 依赖弃用提示，不以测试替身掩盖这些限制。

上线前仍需完成：核实生产实际镜像机制，使用真实镜像工具在备份副本演练 SQLite/D1 对齐；验证 Resend 发件域、真实邮箱投递与真实 AI 图文审核；配置管理员微信、仅 Wiki 的审核站点、私有媒体 Worker 开关与清理定时器。R2 未入库上传孤儿的清理由运维对象核对承担。发布次序与回滚窗口见各站治理文档。

## 2026-10-10 同步核验

本次仅同步邀请注册、邮箱验证、账号限制和内容治理的改动。既有流量分析、设备信息采集、测试生成文件及本地环境配置留在工作区，不纳入本次提交。先更新五仓库 `developing` 与远端 `main`，保留 CAS 和 TechX 新增的 MIT LICENSE，再从暂存区导出独立代码副本测试；副本不含本地 `.env`。

Accounts 84 passed；Wiki 166 passed、4 skipped、17 subtests passed；CAS 58 passed、4 skipped；TechX 79 passed；Todo 125 passed、18 subtests passed。合计 512 个 Python 用例通过，35 个 subtest 通过。Accounts Ruff 与 TechX 的 CI Ruff 检查通过；Accounts 导航 4 项、Wiki 媒体 Worker 21 项、Wiki 消息滚动 1 项、Todo ManageBac Helper 5 项 Node 测试通过。Wiki 与 Todo 的 CI 改用 pytest，使中央状态 fixture 和新增治理测试都能执行。

修复 Accounts 注册失败未计入限流的回归，新增无效邀请重试到达额度后返回 429 的测试。迁移测试显式使用隔离的本地头像目录，不依赖开发机的 R2 配置。管理员限制表单已在浏览器验证暂停/恢复提交、纯空白原因拦截及窄屏布局。

Resend API 认证通过，`mail.nethub.wiki` 状态为 verified；在独立测试数据库中使用真实邮件队列发送一封经用户授权的验证邮件，首次发送成功，供应商返回 delivered。未修改生产数据库，未调用真实 AI；API Key 和收件邮箱不写入仓库。原 2026-10-01 记录中的“未发送真实邮件”仅描述当时验收结果。
