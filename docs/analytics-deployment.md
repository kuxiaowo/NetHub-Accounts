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
