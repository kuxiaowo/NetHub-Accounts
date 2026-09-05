# NetHub Accounts

NetHub Accounts 是 TodoList、TechX、Campus Wiki 和 Codex CAS 的独立统一账号中心。
它只负责身份、登录和网站使用关系；各网站继续独立保存角色、隐私同意及业务资料。

## 技术结构

- Python 3.12、Flask、Jinja、Authlib
- SQLite + SQLAlchemy + Alembic
- OIDC Authorization Code + PKCE S256
- Argon2 密码哈希、RS256 ID Token
- Conda + Gunicorn 单 worker + systemd 用户服务
- 无 Node、无外部数据库服务

默认仅监听 `127.0.0.1:3400`，生产 Issuer 为 `https://auth.nethub.wiki`。

## 本地开发

```powershell
conda create -n nethub-accounts python=3.12 pip -y
conda activate nethub-accounts
python -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
```

在 `.env` 中填写至少 32 字节的 `ACCOUNTS_SECRET_KEY`，并生成开发 RSA 密钥：

```powershell
python -c "from pathlib import Path; from cryptography.hazmat.primitives.asymmetric import rsa; from cryptography.hazmat.primitives import serialization; k=rsa.generate_private_key(public_exponent=65537,key_size=3072); Path('data/oidc-rs256.pem').write_bytes(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))"
python -m app.cli db-upgrade
python -m app.cli bootstrap-admin
python -m app
```

开发环境使用 HTTP 时，把 `SESSION_COOKIE_SECURE=false`。生产环境必须恢复为 `true`。

## Linux 一键初始化

```bash
cp .env.example .env
# 先检查 Issuer、端口和注册开关
chmod +x scripts/init_linux.sh
./scripts/init_linux.sh
python -m app.cli bootstrap-admin
```

脚本会幂等完成：

1. 创建或复用 `nethub-accounts` Conda 环境；
2. 安装依赖；
3. 生成会话密钥和 3072 位 RSA 私钥；
4. 执行 Alembic 数据库升级；
5. 安装并启动 `nethub-accounts.service` 用户服务。

可用 `--no-systemd` 只初始化应用，或用 `--no-start` 创建服务但暂不启动。
服务故意使用一个 Gunicorn worker，因为内置退出通知重试线程只应运行一份。

Caddy 示例见 [`docs/Caddyfile.example`](docs/Caddyfile.example)。

## 创建 OIDC 客户端

```bash
python -m app.cli register-client \
  --client-id todo \
  --name TodoList \
  --redirect-uri https://todolist.nethub.wiki/auth/callback \
  --launch-uri https://todolist.nethub.wiki/ \
  --backchannel-logout-uri https://todolist.nethub.wiki/auth/backchannel-logout
```

命令只显示一次客户端密钥。再次使用同一 `client-id` 会轮换密钥；应在同一维护窗口更新业务网站。
回调地址精确匹配，禁止通配符。

## 迁移 TodoList 和 TechX

只对停机后复制出的数据库备份操作，不要把正在运行的 SQLite 文件交给迁移器。

```bash
python -m app.cli migration-dry-run \
  --todo-db /backup/todo-list.db \
  --techx-db /backup/mood_barometer.sqlite3 \
  --output migration-output/plan.json
```

计划文件不会包含密码哈希。`unresolved` 中的同名账号必须人工判断：

- 同一个人：建立一项 identity，把两个 source 放入其 `sources`；
- 不同的人：建立两项 identity，其中一人使用新中央用户名；发生登录别名冲突的一方设置
  `keep_login_alias` 为 `false`；
- 所有来源必须恰好出现一次；处理后清空 `unresolved` 和 `invalid_accounts`。

确认计划后执行：

```bash
python -m app.cli migration-apply \
  --todo-db /backup/todo-list.db \
  --techx-db /backup/mood_barometer.sqlite3 \
  --plan migration-output/plan.json \
  --mapping-output migration-output/app-user-mapping.json
```

应用过程是事务化和可重复执行的。旧哈希只保留到首次成功登录；随后转成 Argon2 并删除该用户
全部旧凭据。TechX 的实名、年级、项目和隐私同意不会导入账号中心。

### 迁移旧头像

先在 `NetHub-Campus-Wiki` 目录用只读导出脚本生成头像清单：

```bash
python scripts/export_avatar_migration.py \
  --database /backup/campus_wiki.db \
  --output /backup/wiki-avatars.json
```

然后回到 `NetHub-Accounts`，同时读取 TodoList 备份和 Wiki 清单：

```bash
python -m app.cli avatar-migration-dry-run \
  --mapping migration-output/app-user-mapping.json \
  --todo-db /backup/todo-list.db \
  --todo-avatar-dir /backup/todo-avatars \
  --wiki-manifest /backup/wiki-avatars.json \
  --output migration-output/avatar-plan.json
```

检查 `errors`（必须为空）和 `conflicts` 后执行：

```bash
python -m app.cli avatar-migration-apply --plan migration-output/avatar-plan.json
```

冲突固定选择 Wiki 图片，其次 TodoList 图片和文字头像颜色。所有图片都由 Accounts
重新解码压缩；重复执行不会覆盖用户已经在 Accounts 主动设置或删除的头像。

## 备份与恢复

升级或切换前停止账号服务，然后复制以下文件：

- `data/accounts.sqlite3` 及存在时的 `-wal`、`-shm`；
- `data/oidc-rs256.pem`；
- `.env`；
- `data/uploads/avatars/`；
- 四个客户端的密钥保管记录。

恢复时保持数据库、RSA 私钥和 Issuer 成套一致，权限设为 `600`，执行
`python -m app.cli db-upgrade` 后再启动服务。丢失 RSA 私钥会让尚未完成验证的 ID Token 全部失效；
丢失会话密钥会使匿名 CSRF Cookie 失效，但不会删除账号。

## 测试

```bash
ruff check app tests migrations scripts
pytest --cov=app --cov-report=term-missing
bash -n scripts/init_linux.sh
```

Windows 上若系统临时目录权限异常，可运行：

```powershell
python -m pytest -p no:cacheprovider --basetemp data/pytest-tmp
```

## 已实现的边界

- Scope 只有 `openid profile`，不发送网站角色或邮箱；
- 授权码、Access Token 和 ID Token 均为 5 分钟，不发 Refresh Token；
- 普通退出只退出账号中心；“退出所有网站”会向已使用网站发送 Back-Channel Logout；
- 通知失败会持久化重试，可在管理后台或 `retry-backchannel` 命令中查看和重试；
- 用户名不可自行修改；管理员可停用账号、重置临时密码和人工合并重复账号；
- 网站只在成功换取 Token 后出现在该用户的应用关系中。
