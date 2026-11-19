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
