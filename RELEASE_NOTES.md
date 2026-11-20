# SOARProbe v1.6.15

- Fix the Windows build smoke payload so it keeps the special IPv4 target skipped while still exercising the new skip switches. Functional changes are those of v1.6.14.

# SOARProbe v1.6.14

- All skip categories are now explicit per-job switches: `skipPrivate`, `skipDns`, `skipSafety`, and `skipCdn`; defaults remain `true` for compatibility.
- Built-in CDN suffix/CIDR rules no longer cause probe skips. CDN skipping uses only request-level `cdnCidrs`; built-in/custom policy CDN entries are ignored by the probe path.
- `cdnCidrs`, all skip switches, attempt counts, timeout, DNS list, and exclusions participate in cache/share/inflight isolation. `/health` and `--self-test` advertise `skipOptionsConfigurable: true` and `cdnOnlyCidrs: true`.
- Workstation script v25.25 exposes checkboxes for private/special-address skip, DNS-server/port skip, built-in safety-list skip, and custom CDN skip. Offline tests: 198.

# 发布说明

# SOARProbe v1.6.13

- **新增请求级 CDN 跳过网段**：`/v1/probes` 增加可选字段 `cdnCidrs`，接受最多 2048 条规范 IPv4 地址或 CIDR；在 `skipCdn:true` 时，命中这些网段的 IP 返回 `skipped_cdn`，来源为 `request.cdnCidrs`，不再执行 Ping/TCP。
- `cdnCidrs` 与内置 CDN 判定叠加，但仍让安全过滤、私网、DNS 和自定义排除规则优先；`skipCdn:false` 时内置和请求级 CDN 跳过都关闭。
- 字段参与缓存、共享任务和 inflight 隔离；`/health` 与 `--self-test` 增加 `cdnCidrsSupported: true`，Windows 构建 smoke test 覆盖该字段。
- 工作台脚本 v25.23：网络探测配置新增“CDN 跳过网段”文本框，每行一个 IPv4/CIDR；最多 2048 条。
- 离线测试增至 195 项。

# SOARProbe v1.6.12

- **新增 CDN 跳过的显性开关**：`/v1/probes` 增加可选布尔字段 `skipCdn`，默认 `true`，保持原来的 CDN/WAF 跳过行为；显式传 `false` 时忽略 CDN 域名、CNAME 和 CDN IP 网段判定，继续对目标执行 Ping/TCP，但安全过滤、私网、DNS、自定义排除等规则仍然生效。
- `/health` 和 `--self-test` 新增 `cdnSkipConfigurable: true`；字段参与缓存、共享任务和 inflight 隔离。Windows 构建 smoke test 同时校验该能力。
- 工作台脚本 v25.22：网络探测配置新增“命中 CDN/WAF 时跳过 Ping/TCP 探测”复选框，默认勾选；设置随任务下发。
- 离线测试增至 192 项。

# SOARProbe v1.6.11

- 修复 v1.6.10 的 Windows 构建自检：构建脚本中的默认 DNS 校验同步为 `8.8.8.8,223.5.5.5,223.6.6.6,180.76.76.76`。v1.6.10 的功能代码不变。
- 工作台脚本保持 v25.12：移除 DNS 场景下拉框，DNS 直接自定义；默认包含 Google、阿里和百度公共 DNS。

# SOARProbe v1.6.10

- **默认 DNS 回退列表加入阿里和百度公共 DNS**：默认顺序为 `8.8.8.8`、阿里 `223.5.5.5`、阿里 `223.6.6.6`、百度 `180.76.76.76`。系统 DNS 之后依次尝试，首次成功即停止。
- 工作台脚本 v25.12 移除“DNS 场景”下拉框，DNS 直接在文本框中编辑；旧的 `8.8.8.8/223.5.5.5` 两项目标会自动迁移为新的四项默认列表。
- 百度和阿里 DNS 地址仍属于内置 DNS 排除清单，不会被当作 Ping/TCP 探测目标；它们只参与域名解析。
- 离线测试保持 189 项通过。

# SOARProbe v1.6.9

- **Ping/Telnet 改为固定次数采样并返回逐次记录**：配置 `pingCount:5` 时每个 IPv4 固定执行 5 次 ICMP Echo，不再在第一次成功后提前停止；`tcpAttempts:3` 时每个端口固定连接 3 次。任一 Ping 成功或任一 TCP 连接成功即判定目标连通。
- Ping/TCP 结果新增 `attempts`、`configuredAttempts`、`successCount` 和 `attemptDetails`。前端脚本 v25.10 会逐条显示“第 N 次”的结果、耗时和错误，因此不会再只看到一条汇总记录。
- 所有尝试仍分别经过全局限流和超时控制，参数继续参与缓存、共享任务和 inflight 隔离。
- 工作台脚本升级到 v25.10；Windows probe 升级到 v1.6.9。

# SOARProbe v1.6.8

- **Ping/Telnet 重试和超时可配置**：默认每个 IPv4 Ping 最多 5 次、每个 TCP 端口最多连接 3 次、单次操作超时 3000 ms。Ping 成功即停止；TCP 成功或明确拒绝即停止，只有超时/错误才继续重试。
- `/v1/probes` 新增可选字段 `pingCount`（1–10）、`tcpAttempts`（1–10）、`timeoutMs`（200–10000），省略时使用上述默认值。字段参与缓存和共享任务隔离，避免不同探测参数复用旧结果；结果中的 `attempts` 和 `configuredAttempts` 可直接查看实际次数。
- `/health` 新增 `probeSettings: true`、`defaultPingCount: 5`、`defaultTcpAttempts: 3`、`defaultProbeTimeoutMs: 3000`。
- 工作台脚本 v25.9：网络探测配置可设置 Ping 次数、Telnet 次数和单次超时；DNS 场景新增百度 `180.76.76.76`、阿里 `223.5.5.5/223.6.6.6`，并保留默认、仅系统 DNS 和自定义。
- 离线测试增至 189 项。

# SOARProbe v1.6.7

- **修复 K01 改密请求兼容性与诊断**：改密请求只使用 K01 API 文档约定的 `Authorization: Bearer`，不再额外发送浏览器前端的 `access_token` 头，避免被前端签名中间件误判；成功判定兼容 `error_code` 为整数 `0` 或字符串 `"0"` 的 K01 版本。
- 新增 `k01-password-change-start` / `k01-password-change-response` 日志，记录上游状态、`success`、`error_code`、`changepwd_err_count` 和脱敏后的上游消息；失败诊断也包含 `changepwdErrCount`。
- 工作台脚本 v25.5：改密接口返回 404 时明确提示当前 SOARProbe 版本过低，需要替换并重启 v1.6.7 或更新版本；改密失败时提示旧密码可能已变化，应先更新本地 K01 配置。`/health` 新增 `k01PasswordChange: true`。
- 注意：v1.6.6 的改密基础流程保留；本次只修正改密边界的头部、成功判定和现场诊断。

# SOARProbe v1.6.6

- **脚本内修改 K01 初始密码并自动重查**：情报接口返回 `diagnosticCode:initial_password_not_changed` 时，工作台情报面板显示“修改初始密码”入口。用户只需输入并确认新密码，不再需要手工拼装带 `X-Sign` 的浏览器请求。
- 本地新增 `POST /v1/intelligence/change-password`，正文 `{newPassword,confirmPassword}`，仅接受本机配对令牌。服务使用 `config.json` 中已保存的旧 API 密码作为 `oldpwd`，携带登录取得的 `Authorization: Bearer` 调用 K01 `/api/v1/account/changepwd`；成功后保存新密码、清空旧令牌和缓存，再由脚本重新发送原情报查询。
- 新密码限制 8–16 位且两次一致；新密码、旧密码、访问令牌和配对令牌不进入响应、错误消息或日志。若 K01 已改密但本地保存失败，会明确返回 `K01_PASSWORD_CHANGED_CONFIG_SAVE_FAILED`。
- **恢复脚本详情页工具**：重新合入 `/soar/scripts/script` 页面的“JSON 参数”编辑器与“清空变量”按钮，支持跨页读取参数表、保留原生类型、合并预览、幂等应用和页面草稿回滚；不改后台脚本、不自动保存、不发请求。
- 改密弹窗复用 `k01_website_resources` 中 Ant Design `ant-modal`、`ant-form`、`ant-input`、`ant-btn` 的 DOM/样式契约并做局部作用域隔离；脚本详情工具继续基于 `website_resources` 中实际页面的 `.formily-qaxd-array-table` 和原生输入事件写入。
- 工作台脚本升级到 v25.4。

# SOARProbe v1.6.5

- **初始密码未修改的查询拒绝给出可操作指引**：K01 溯源接口返回 HTTP 200、`success:false`、`error_code:10140`（`The initial password has not been changed`）时，不再只显示笼统的“K01 未返回成功的情报结果”。现在返回 `K01_FRONTEND_REQUIRED`、`reason:api_initial_password_required`、`diagnosticCode:initial_password_not_changed`，提示先在 K01 网页端修改该 API 账号的初始密码并更新本地服务保存的密码；同时 `fallbackAllowed:true`，已启用且已登录的 K01 页面仍可会话兜底。
- **其他情报业务拒绝也会附带上游原因**：K01 溯源接口的 HTTP 200 业务拒绝会把经脱敏、限长的上游 `msg` 追加到用户可见消息，同时保留结构化诊断；密码、访问令牌和配对令牌仍不会进入消息或诊断。
- 工作台脚本 v25.3：改密提示触发会话兜底但兜底被关闭或失败时，保留原始可操作原因，不再只显示“已关闭 K01 页面会话兜底”。

# SOARProbe v1.6.4

- **首次登录改密提示不再当作登录失败**：K01 在"首次登录建议修改密码"时返回 `success:false`、`error_code:999`、`status:"change"`，但响应体里已经下发了可用的 `access_token`。以前一律按 `api_login_failed` 放弃，导致能登录的账号在情报链路里全部失败。现在以令牌是否可用为准：拿到有效 `access_token` 就继续查询，同时把该提示记录为 `k01-api-login result=ok-with-notice` 并随结果返回 `loginNotice`（`status` / `errorCode` / `message`，脱敏）。
- 真正的拒登（无可用令牌，例如"用户名或密码错误"）行为不变，仍返回 `K01_FRONTEND_REQUIRED` + `diagnosticCode:login_rejected`。
- 工作台脚本 v25.2：情报面板在计数下方显示 `K01 提示：首次登录建议修改密码！`，明确标注"情报已通过令牌获取"，不再需要靠日志判断到底是密码错还是改密提示。

# SOARProbe v1.6.3

- **登录被拒给出上游原因**：K01 `/api/cms/user/login` 返回 HTTP 200 但 `success:false`（或 400/401/403）时，错误诊断新增 `diagnosticCode`（`login_rejected` / `login_http_rejected`）、`diagnostic.errorCode`、`diagnostic.message`，对端提示文本经脱敏后同时拼进用户可见消息，例如"API 账号登录被拒（上游返回：登录用户失败：用户名或密码错误）"。以前只能看到笼统的 `api_login_failed`。
- 密码、令牌与配对令牌继续在诊断文本中脱敏。

# SOARProbe v1.6.2

- **启动即显示版本**：进程启动第一行打印 `SOARProbe v<版本> (API v1)`（走 stderr，保持 `--self-test` 的 stdout 为纯 JSON），控制台窗口标题显示 `SOARProbe v<版本> · 127.0.0.1:<端口>`，启动失败提示也带版本号；新增 `--version`，仅打印版本后退出，不读取配置、不占用端口。
- **K01 响应带构建版本**：`/v1/intelligence/trace` 的成功结果与全部错误 payload 都带 `serviceVersion`，脚本日志、导出 JSON 与抽屉面板据此显示 `probe v<版本>`；出现“版本未知”即表示该机器仍在运行旧 EXE。
- 工作台脚本同步调整：会话兜底被关闭时保留上游真实原因（`stage`、`diagnosticCode`、`traceId`、`serviceVersion`、`diagnostic`），不再只剩 `K01_SESSION_FALLBACK_DISABLED` 一条笼统消息。

# SOARProbe v1.6.1

修复 K01 情报登录在要求 TLS 重协商的网关后 31 ms 断连的问题，情报查询可正常返回。

- 服务端在收到请求体后发起 TLS 重协商时，OpenSSL 3.x 客户端（CPython 3.11 自带）无法完成，对端随即断开，表现为 `K01_CONNECTION_ERROR`、`stage=login`、`diagnosticCode=socket_error`，且与证书、超时和 UA 无关。
- 服务识别这类请求后断连（`RemoteDisconnected`、连接重置、`BrokenPipe`、`SSLEOF` 及含 renegotiation 的错误），改用系统 TLS 栈重放同一请求一次；Windows 上即 schannel，通过系统自带 `curl.exe` 完成重协商后正常拿到响应。超时、连接被拒、证书错误不进入该重放，错误码语义不变。
- 重放时请求头与请求体经仅本进程可读的临时文件传递，令牌与密码不进入命令行，调用结束立即删除临时目录。重放结果复用原有 JSON 校验、大小上限与错误页取证逻辑。
- 诊断新增 `diagnostic.transport`，取值 `urllib` 或 `os-tls`，可直接在 `probe.jsonl` 与错误 payload 中确认本次是否走了系统 TLS 栈；重放失败时 `osError` 保留 curl 退出码与摘要。
- 需要时可设置环境变量 `SOAR_K01_CURL_FALLBACK=0` 关闭该重放。173 项离线测试覆盖断连识别、重放触发、关闭开关后的错误码、命令行不含密钥与响应解析。

**推荐下载 `SOARProbe-Windows-x64-portable.zip`。** 关闭旧服务，将 ZIP 完整解压到新目录，双击 `SOARProbe\Start-SOARProbe.cmd`，保留 `_internal` 及其他文件。也提供单文件 `SOARProbe.exe` 与 `SOARProbe-Windows-x64.zip`。Windows x64 无需安装 Python、依赖或 Telnet 客户端。

# SOARProbe v1.6.0

新增 K01 威胁情报查询链路与端到端 trace 诊断。此版本首次把 K01 情报接口、登录会话兜底与 32 位十六进制 traceId 带到 Windows 构建产物。

- 新增 `/v1/intelligence/status`、`/v1/intelligence/config`、`/v1/intelligence/trace` 三组接口，支持情报配置读写与按需 trace 查询；配置中的口令字段只写不读，响应中始终为 `null`。
- 全链路统一 trace：脚本、`X-Trace-Id` 响应头与服务日志使用同一 32 位 traceId，错误 payload 附带 `stage`、`upstreamStatus`、`diagnosticCode`、`diagnostic`、`traceId`，可直接按 ID 跨层检索。
- 按阶段区分 `tls`、`upstream`、`transport` 失败，非 200 上游响应回传诊断详情；重定向识别为独立错误码，不再退化为裸失败。
- 未开启前端会话兜底时 `trace` 返回 409 `K01_FRONTEND_REQUIRED` 并标记 `fallbackAllowed`，便于脚本判断是否切换到页面会话通道。
- 166 项离线测试覆盖配置校验、trace 诊断、证书与重定向错误分流；Windows 构建额外自检情报接口与健康信息，不对真实告警目标发起探测。

**推荐下载 `SOARProbe-Windows-x64-portable.zip`。** 关闭旧服务，将 ZIP 完整解压到新目录，双击 `SOARProbe\Start-SOARProbe.cmd`，保留 `_internal` 及其他文件。也提供单文件 `SOARProbe.exe` 与 `SOARProbe-Windows-x64.zip`。Windows x64 无需安装 Python、依赖或 Telnet 客户端。

# SOARProbe v1.4.0

支持在脚本 v24.0 的探测配置中自定义备用 DNS。域名始终先用系统 DNS，解析失败或没有 A 记录时再按保存顺序尝试备用服务器；成功后先做过滤，再 Ping 和 TCP 检测，不会因结果被过滤或探测不通而更换 DNS。

- 默认备用列表仍为 `8.8.8.8`、`223.5.5.5`；最多 8 个规范 IPv4，去重并保序。清空列表表示仅系统 DNS。可配置单位内网 DNS，拒绝未指定、回环、链路本地、多播和特殊保留地址。
- 配置保存在浏览器 localStorage，随每批任务传递。所配置的 DNS 地址自动排除为 Ping/TCP 目标；每个任务拥有独立配置，不修改全局过滤清单。
- 有序 DNS 列表纳入任务共享和缓存标识，避免不同解析配置复用旧结果。各次解析的服务器、结果及耗时继续记录在 `nslookup.attempts` 和日志中。
- API v1 新增可选 `dnsServers` 数组；省略时兼容原默认行为，明确传 `[]` 为仅系统 DNS。`/health` 增加 `customDnsServers: true` 和默认 `dnsServers`，便于脚本检查兼容性。已有 v21.0 及更新脚本可继续使用默认 DNS。
- 134 项服务离线测试覆盖自定义顺序、仅系统模式、严格 IPv4 校验、DNS 自身排除、并发/缓存隔离、配置快照和原有鉴权、限流、过滤与探测行为。Windows 构建还检查实际 EXE 自检、健康与认证接口，以及最终 ZIP 解压后的运行状态；不向真实告警目标发起 CI 探测。

**推荐下载 `SOARProbe-Windows-x64-portable.zip`。** 关闭旧服务，将 ZIP 完整解压到新目录，双击 `SOARProbe\Start-SOARProbe.cmd`，保留 `_internal` 及其他文件。也提供单文件 `SOARProbe.exe` 与 `SOARProbe-Windows-x64.zip`。Windows x64 无需安装 Python、依赖或 Telnet 客户端。

配对令牌、服务配置和日志继续保存在 `%LOCALAPPDATA%\SOARProbe\`；浏览器模板、自动处理状态和设置继续保存在 localStorage。升级无需清理存储。首次配对按 **C** 复制令牌，在脚本中填写 `http://127.0.0.1:8765`；按 **L** 打开日志，按 **Q** 退出。浏览器与服务需在同一台 Windows 电脑运行。

本版本继续使用 Starlette 和纯 Python 请求校验，不包含 FastAPI、Pydantic 或 `_pydantic_core`。仍有 CPython 和必要的 DLL/PYD，未提供保证 Smart App Control 放行的代码签名；普通 Windows CI 没有复现用户 SAC 策略。程序不修改防护设置。[微软说明](https://support.microsoft.com/en-us/windows/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003)指出目前没有单应用 SAC 排除功能。服务发布附件不包含油猴脚本。
