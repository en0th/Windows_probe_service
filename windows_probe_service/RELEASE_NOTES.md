# 发布说明

## v1.6.4

- **首次登录改密提示不再当作登录失败**：K01 在"首次登录建议修改密码"时返回 `success:false`、`error_code:999`、`status:"change"`，但响应体里已经下发了可用的 `access_token`。以前一律按 `api_login_failed` 放弃，导致能登录的账号在情报链路里全部失败。现在以令牌是否可用为准：拿到有效 `access_token` 就继续查询，同时把该提示记录为 `k01-api-login result=ok-with-notice` 并随结果返回 `loginNotice`（`status` / `errorCode` / `message`，脱敏）。
- 真正的拒登（无可用令牌，例如"用户名或密码错误"）行为不变，仍返回 `K01_FRONTEND_REQUIRED` + `diagnosticCode:login_rejected`。
- 工作台脚本 v25.2：情报面板在计数下方显示 `K01 提示：首次登录建议修改密码！`，明确标注"情报已通过令牌获取"，不再需要靠日志判断到底是密码错还是改密提示。

## v1.6.3

- **登录被拒给出上游原因**：K01 `/api/cms/user/login` 返回 HTTP 200 但 `success:false`（或 400/401/403）时，错误诊断新增 `diagnosticCode`（`login_rejected` / `login_http_rejected`）、`diagnostic.errorCode`、`diagnostic.message`，对端提示文本经脱敏后同时拼进用户可见消息，例如"API 账号登录被拒（上游返回：登录用户失败：用户名或密码错误）"。以前只能看到笼统的 `api_login_failed`。
- 密码、令牌与配对令牌继续在诊断文本中脱敏。

## v1.6.2

- **启动即显示版本**：进程启动第一行打印 `SOARProbe v<版本> (API v1)`（走 stderr，保持 `--self-test` 的 stdout 为纯 JSON），控制台窗口标题显示 `SOARProbe v<版本> · 127.0.0.1:<端口>`，启动失败提示也带版本号；新增 `--version`，仅打印版本后退出，不读取配置、不占用端口。
- **K01 响应带构建版本**：`/v1/intelligence/trace` 的成功结果与全部错误 payload 都带 `serviceVersion`，脚本日志、导出 JSON 与抽屉面板据此显示 `probe v<版本>`；出现“版本未知”即表示该机器仍在运行旧 EXE。
- 工作台脚本同步调整：会话兜底被关闭时保留上游真实原因（`stage`、`diagnosticCode`、`traceId`、`serviceVersion`、`diagnostic`），不再只剩 `K01_SESSION_FALLBACK_DISABLED` 一条笼统消息。

## v1.6.1

- 网关 TLS 重协商导致连接被关闭时（`RemoteDisconnected` / `ConnectionResetError(10054)` / `SSLEOFError`），改用系统 TLS 栈（`curl.exe`）重放一次同一请求，请求头与 body 经临时文件以 0600 传递并在调用结束删除；诊断新增 `diagnostic.transport`（`urllib` / `os-tls`），`SOAR_K01_CURL_FALLBACK=0` 可关闭重放。
- 认证阶段的分阶段诊断（`stage`、`upstreamStatus`、`diagnosticCode`）透传到错误 payload。

## v1.6.0

- 新增 K01 威胁情报接口与全链路 traceId（脚本 `X-Trace-Id`、响应头、服务日志同源）。
