# NetHub 统一访问分析

生产 Caddy 配置见 `config/Caddyfile.production`。服务器使用已验证的 Caddy 2.11.4
或更新版本；先以 `caddy validate --config ... --adapter caddyfile` 检查配置，再原子替换
`/etc/caddy/Caddyfile` 并 reload。保留旧二进制和配置用于回滚。

入口防火墙须继续仅允许 Cloudflare 公布的网段访问 80/443。采集器只在 TCP 对端
位于 `config/cloudflare-ips.txt` 的网段内时采信 `CF-Connecting-IP`。定期从
Cloudflare 官方 IP 列表更新 `/etc/nethub/cloudflare-ips.txt`，同步检查防火墙网段。

将 `config/nethub-analytics-ingest.{service,timer}` 安装到 systemd，将
`config/nethub-analytics-accounts.conf` 安装到
`/etc/systemd/system/nethub-accounts.service.d/analytics.conf`。数据库放在持久目录
`/srv/nethub/data/analytics.sqlite3`，由 `nethub` 用户拥有。运行 `systemctl
daemon-reload`、启用 timer、重启 Accounts，再检查 `/admin/analytics/status`。

Caddy 是唯一访问事件源。请求索引保留 30 天，小时与日汇总保留 365 天；Caddy
原始文件按 30 天轮转。报表默认过滤静态资源、健康检查和常见机器人。CSV 默认掩码
IP；完整 IP 仅在管理员主动展开时显示。请求头中的会话及授权凭据不落盘，URL
和 Referer 的查询参数在 Caddy 写日志前清除。

Todo 的旧表清理须等待一个完整并行校验周期。完成五站请求数、用户数、错误数和趋势
比对后，运行 Todo 仓库的 `scripts/remove_legacy_ip_records.py --apply`；此前仅运行
无 `--apply` 的预览模式。

## 客户端环境快照

五站通过同源 `/__nethub/client.js` 和 `/__nethub/client` 使用 Accounts 统一采集器。
Caddy 在服务端追加经过白名单与长度校验的快照，客户端提交体不直接落日志。
新增索引列为 `browser_id`、`accept_language`、`client_hints`、`client_info`；连接时以
SQLite 写锁执行幂等的增量迁移，不改动业务库。上线前备份 analytics.sqlite3。

请求头与随机浏览器 ID 均属关联线索，不是身份凭据。nethub.wiki 子站共享 30 天随机
Cookie，sdgj.tech 独立；不记录会话 Cookie。所有浏览器环境值可能被伪装，缺失值不猜补。
快照属于统计噪声，管理员勾选“显示全部请求”后查看客户端信息，也可按浏览器 ID 查询
或导出 CSV。明细沿用 30 天保留期。已有索引不回填新字段；部署后开始采集。

采集脚本只查询无需弹窗的 API，异步能力查询限时 1.8 秒，不阻塞页面；不读取表单输入。
Canvas 与离线音频只处理固定合成样本，字体只测量通用字体，不调用本地字体枚举。
权限查询只检查状态，不申请权限。公开说明在 `/__nethub/privacy`。

发布顺序：先 Accounts、Caddy 路由与日志字段，再四个客户端站点。验证 Caddy 配置，
检查正文与 Cookie 不泄漏，确认快照能进入索引。回滚顺序为客户端、Caddy、Accounts；
新增索引列可保留，不需要破坏性回退数据库。
