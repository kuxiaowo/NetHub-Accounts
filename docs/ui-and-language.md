# Accounts 界面与语言

所有页面使用 Linked N 标识和统一布局。首页通过应用卡片连接各站，登录后可以从右上角头像菜单进入个人资料。

## 语言

- 默认中文。页头的 EN / 中文切换通过 `lang=zh|en` 参数选择语言，服务器以 `nethub-language` cookie 保存一年；浏览器同时记录同名 localStorage 键。
- `app/i18n.py` 为 Jinja 提供 `t()`；中文原文是键，英文在 `app/translations/en.json`。传给页面的用户姓名、邮箱、邀请凭证、用户内容均保持原样。
- 页面语言链接保留原始查询参数，包括嵌套的 `next` 与 OAuth 参数。邀请生成结果页通过只读展示操作切换语言，继续显示同一份邀请。
- 动态头像、管理对话框与访问分析使用 `app/static/ui-translations.js`。新增文案时同步两个字典；不要遍历 DOM 替换用户内容。
- 普通页面错误保留原 HTTP 状态及安全响应头；OAuth、API 与分析数据端点保留原协议响应。

## 主题

- 默认跟随系统，可用页头开关调整深浅主题，颜色偏好保存在 `nethub-theme`。切换在当前页面生效，表单输入会保留。
- 布局样式由 HTML 直接加载，首次绘制前应用已保存的主题。
- Accounts 与 Campus Wiki 共用蓝青渐变、弧线、点阵和卡片配色。页头和页脚在浅色模式下都使用浅灰（`#F5F5F5`），在深色模式下都使用炭灰（`#212222`）。首页应用卡片和统计指标在悬停时轻微上浮。个人中心的资料面板和已使用网站卡片使用固定阴影。

## 本地验证

在 `nethub-accounts` conda 环境执行：

```powershell
python scripts/preview_ui.py --port 8793
python -m pytest
node --test tests/continue.test.cjs
```

预览只绑定 `127.0.0.1`，使用临时数据库、临时签名密钥与合成账号，不读取项目 `.env`，没有邮件凭据。打开 `/preview/sign-in` 查看未验证账号，或 `/preview/sign-in?user=verified` 查看已验证账号。`/preview/phone` 用于检查个人账号管理页在 390px 宽度下的布局。

预览脚本单独允许同源 iframe；应用本身的 `X-Frame-Options: DENY` 保持不变。预览数据位于系统临时目录，每次启动重新生成。预览与测试不代表生产登录、真实邮件投递或外部应用退出通知已验收。
