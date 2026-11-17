# SOARProbe v1.3.0

移除引发当前启动错误的 `_pydantic_core` 依赖。HTTP 服务从 FastAPI 改为 Starlette 0.49.3，请求校验改用 Python 标准库；发布包不再包含 FastAPI、Pydantic 或 Pydantic Core。此次调整解决程序仍需加载这一被阻止扩展的问题，未在用户开启 Smart App Control 的实机上验证，不能保证其他 EXE/DLL 已获系统允许。

**推荐下载 `SOARProbe-Windows-x64-portable.zip`。** 完整解压后双击 `SOARProbe\Start-SOARProbe.cmd`，也可双击同目录 `SOARProbe.exe`，无需安装 Python、依赖或 Telnet 客户端。

- 便携 ZIP 包含 EXE、`_internal` 运行时、启动脚本、说明、许可证和文件校验清单。保留整个 `SOARProbe` 文件夹；不能只复制 EXE，也不要混用新旧版本依赖。
- 保留单文件 `SOARProbe.exe` 与 `SOARProbe-Windows-x64.zip`。单文件版仍会将运行时解压到临时目录；推荐便携版从完整解压后的固定目录运行。
- API v1 与 v21.0 及更新脚本（当前 v23.0）兼容。域名按系统 DNS、8.8.8.8、223.5.5.5 顺序回退；公网 IPv4、DNS/CDN/特殊地址过滤、Ping、明确端口 TCP、域名默认 80/443 和详细日志行为继续沿用。
- 服务配置、配对令牌及日志保存在 `%LOCALAPPDATA%\SOARProbe\`；浏览器模板、自动处理状态和设置继续保存在 `localStorage`。升级无需清理配置或重装油猴脚本。
- 请求继续执行本机来源、Host、Bearer 认证和 2 MiB 正文限制。新增离线 HTTP 校验覆盖认证顺序、严格 JSON/类型、未知字段、重复目标 ID 和非法游标；错误响应不回显提交内容或令牌。
- Windows 构建检查两种布局的 PE x64、CPython 运行时及冻结资源，检查无 FastAPI/Pydantic/Pydantic Core 残留，并启动健康与令牌认证测试。最终便携 ZIP 还会解压到带空格目录后再次检查；CI 不向真实告警目标发起探测。

## Smart App Control

新包仍包含 CPython 运行时和其他必要的 DLL/PYD。移除 `_pydantic_core` 不是系统信任批准；固定目录与校验哈希也不会使其他未知文件自动受信任。本版本未提供保证 Smart App Control 放行的受信任代码签名。微软说明个人 Smart App Control 目前不支持对单个应用手动放行：[Smart App Control 常见问题](https://support.microsoft.com/en-us/windows/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003)。

普通 GitHub Actions Windows 构建没有复现用户电脑的 Smart App Control 环境，测试通过不代表该策略允许程序运行。如果仍被阻止，请保留完整启动错误、具体文件路径、版本和包内 `SHA256SUMS.txt`，不要提供含令牌的 `config.json`。启动脚本只保留错误窗口，不修改安全策略；本次更新不要求关闭防护、添加整目录排除或以管理员身份运行。

## 升级使用

1. 关闭旧服务，将 v1.3.0 便携包完整解压到新的固定目录，保留 EXE 与 `_internal` 的相对位置；不要从 ZIP 预览窗口直接运行。
2. 双击 `Start-SOARProbe.cmd`，保持窗口打开。首次使用按 **C** 复制令牌，在脚本中填写 `http://127.0.0.1:8765` 和令牌；已有配置会继续保留。
3. 按 **L** 打开日志，按 **Q** 退出。若仍出现 `_pydantic_core` 错误，确认运行的是新包中的 EXE，没有启动旧版本或混用旧 `_internal`。

浏览器和服务需在同一台 Windows 电脑运行。服务发布附件不包含油猴脚本，已有 v21.0 及更新脚本可直接继续使用。
