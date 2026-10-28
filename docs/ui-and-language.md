# Accounts 界面与语言

本轮页面使用共享 Linked N 标识、浅灰背景、清晰卡片边框和轻阴影。主页、登录、注册、个人资料、邮箱邀请、验证/邀请结果与管理页共用浅色/深色主题。重要邮箱、邀请和会话规则仍由原有服务器逻辑决定。

## 语言

- 默认中文。页头的 EN / 中文切换通过 `lang=zh|en` 参数选择语言，服务器以 `nethub-language` cookie 保存一年；浏览器同时记录同名 localStorage 键。
- `app/i18n.py` 为 Jinja 提供 `t()`；中文原文是键，英文在 `app/translations/en.json`。传给页面的用户姓名、邮箱、邀请凭证、用户内容均保持原样。
- 页面语言链接保留原始查询参数，包括嵌套的 `next`、OAuth 参数与邀请凭证。
- 动态头像、管理对话框与访问分析使用 `app/static/ui-translations.js`。新增文案时同步两个字典；不要遍历 DOM 替换用户内容。
- 普通页面错误保留原 HTTP 状态及安全响应头；OAuth、API 与分析数据端点保留原协议响应。

## 主题

- `preferences.js` 在首屏绘制前读取 `nethub-theme`，支持 `light`、`dark`、`system`，默认跟随系统。页头按钮在浅色与深色之间切换。
- `refresh.css` 保存共享颜色、边框、阴影与响应式布局。使用语义变量，避免在深色界面继承浅色硬编码底色。
- 表单名称、CSRF 字段、验证码、授权目标与原验证规则不变。

## 本地验证

在 `nethub-accounts` conda 环境执行：

```powershell
python scripts/preview_ui.py --port 8793
python -m pytest
node --test tests/continue.test.cjs
```

预览只绑定 `127.0.0.1`，使用临时数据库、临时签名密钥与合成账号，不读取项目 `.env`，没有邮件凭据。打开 `/preview/sign-in` 查看未验证账号，或 `/preview/sign-in?user=verified` 查看已验证账号。`/preview/phone?page=/account/community` 用于 390px 布局检查。

预览脚本单独允许同源 iframe；应用本身的 `X-Frame-Options: DENY` 保持不变。预览数据位于系统临时目录，每次启动重新生成。预览与测试不代表生产登录、真实邮件投递或外部应用退出通知已验收。
