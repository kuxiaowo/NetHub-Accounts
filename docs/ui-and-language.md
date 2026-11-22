# Accounts 界面与语言

首次访问默认显示旧版界面，包含蓝色渐变首页和横向应用卡片。页头的“切换新版”启用 Linked N 标识和新版布局。“切回旧版”可随时恢复。两版共用表单、账号操作和中英文翻译。

## 语言

- 默认中文。页头的 EN / 中文切换通过 `lang=zh|en` 参数选择语言，服务器以 `nethub-language` cookie 保存一年；浏览器同时记录同名 localStorage 键。
- `app/i18n.py` 为 Jinja 提供 `t()`；中文原文是键，英文在 `app/translations/en.json`。传给页面的用户姓名、邮箱、邀请凭证、用户内容均保持原样。
- 页面语言链接保留原始查询参数，包括嵌套的 `next` 与 OAuth 参数。邀请生成结果页通过只读展示操作切换语言，继续显示同一份邀请。
- 动态头像、管理对话框与访问分析使用 `app/static/ui-translations.js`。新增文案时同步两个字典；不要遍历 DOM 替换用户内容。
- 普通页面错误保留原 HTTP 状态及安全响应头；OAuth、API 与分析数据端点保留原协议响应。

## 主题

- 浏览器用 `nethub-layout` 保存旧版（`classic`）或新版（`modern`）。切换在当前页面生效，已填表单与一次性邀请结果都保留。
- 旧版使用原有浅色配色。新版默认跟随系统，可用独立的深浅色按钮调整，颜色偏好保存在 `nethub-theme`。
- `preferences.css` 定义共享切换控件，`refresh.css` 只在新版启用。
- 新版与 Campus Wiki 共用蓝青渐变、弧线、点阵和卡片配色。深色页头与页脚统一使用石青色（`#142D34`）。鼠标悬停在应用卡片、已使用网站和统计指标上时会轻微上浮，表单保持静止。

## 本地验证

在 `nethub-accounts` conda 环境执行：

```powershell
python scripts/preview_ui.py --port 8793
python -m pytest
node --test tests/continue.test.cjs
```

预览只绑定 `127.0.0.1`，使用临时数据库、临时签名密钥与合成账号，不读取项目 `.env`，没有邮件凭据。打开 `/preview/sign-in` 查看未验证账号，或 `/preview/sign-in?user=verified` 查看已验证账号。`/preview/phone?page=/account/community` 用于 390px 布局检查。

预览脚本单独允许同源 iframe；应用本身的 `X-Frame-Options: DENY` 保持不变。预览数据位于系统临时目录，每次启动重新生成。预览与测试不代表生产登录、真实邮件投递或外部应用退出通知已验收。
