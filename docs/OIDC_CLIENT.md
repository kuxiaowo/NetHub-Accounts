# OIDC 客户端接入契约

业务网站必须使用服务端 Authorization Code Flow，并实现 PKCE S256、`state` 和 `nonce`。

## 固定端点

- Discovery：`https://auth.nethub.wiki/.well-known/openid-configuration`
- Authorization：`/oauth/authorize`
- Token：`/oauth/token`
- UserInfo：`/oauth/userinfo`
- Revocation：`/oauth/revoke`
- JWKS：`/.well-known/jwks.json`

## 登录步骤

1. 网站生成随机 `state`、`nonce` 和 PKCE verifier，存入服务器端短期会话。
2. 浏览器跳转 `/oauth/authorize`，请求 `openid profile`。
3. 回调必须先比较 `state`，再用 verifier 和 HTTP Basic 客户端认证兑换 Token。
4. 根据 Discovery/JWKS 验证 ID Token 的签名、`iss`、`aud`、`exp` 和 `nonce`。
5. 使用不可变 `sub` 查找或即时创建本地用户；只在创建时复制用户名与显示名称。
6. 创建网站自己的不透明 HttpOnly 会话，保存中央 `sub` 和 `sid`。

不能把中央用户名作为业务数据外键，也不能从中央 Token 推导网站管理员权限。

## Back-Channel Logout

客户端提供只接受 `POST logout_token=...` 的 HTTPS 地址。处理器必须：

1. 使用账号中心 JWKS 验证 RS256、Issuer、Audience、时间和 `events`；
2. 使用 `jti` 做短期去重；
3. 有 `sid` 时删除对应网站会话，否则删除该 `sub` 的全部网站会话；
4. 成功或重复通知均返回 `200/204`，验证失败返回 `400/401`；
5. 不删除本地用户或业务数据。

