# SOAR Windows 本地连通性服务

本服务 v1.6.9 配合当前工作台脚本使用，支持 K01 威胁情报查询。原有 IPv4、域名 DNS/Ping/TCP 探测继续兼容 v21.0 及更新脚本。查询成功后，探测结果显示在已有表格中；情报查询通过目标旁独立图标打开详情抽屉。网络探测和情报查询均独立于告警处置判断。

**仅探测公网 IPv4，排除已知 CDN/WAF、DNS 服务器、内网和特殊地址。** IPv6、`0.0.0.0`、回环、链路本地、组播、保留和特殊用途地址直接跳过。域名只查询 A 记录并检查 CNAME，服务端逐个检查解析出的 IPv4，随后只向已检查的数字 IPv4 发起检测；不会再次解析域名后直接连接。

## 免安装 EXE 使用

发布版已包含 Python 运行时、Starlette、依赖和默认 CDN 规则。v1.3.0 改用 Starlette 0.49.3 与 Python 标准库校验请求，移除 FastAPI、Pydantic 和 `pydantic_core`，不再包含本次被拦截的 `_pydantic_core.pyd`。API v1、DNS 回退、Ping/TCP、过滤规则和持久配置继续沿用。运行电脑无须安装 Python、运行 `Install.cmd` 或安装 Telnet 客户端；现有 v21.0 及更新脚本无须为本次服务升级重新修改。

在 [GitHub Releases](https://github.com/en0th/Windows_probe_service/releases/latest) 下载：

| 发布附件 | 使用方式 |
| --- | --- |
| **`SOARProbe-Windows-x64-portable.zip`（推荐）** | 完整解压后运行 `SOARProbe` 文件夹中的程序；运行时依赖保留在 `_internal` 子目录 |
| `SOARProbe.exe` | 单文件版，启动时将运行依赖解压到临时目录；适合允许这种加载方式的电脑 |
| `SOARProbe-Windows-x64.zip` | 单文件版 EXE、说明、许可证和校验文件的压缩包；与上一个 EXE 的运行方式相同 |

1. 先关闭旧服务。将推荐便携包**完整解压**到允许安装软件的固定本地目录，保留 `SOARProbe.exe`、`_internal` 和其他文件的相对位置。不要直接在压缩包内运行，也不要只复制 EXE。
2. 打开解压后的 `SOARProbe` 文件夹，双击 **`Start-SOARProbe.cmd`**。它会在启动失败时保留窗口，方便复制完整错误；也可直接双击同目录的 `SOARProbe.exe`。启动后保持窗口打开。
3. 窗口显示本地地址后，按 **C** 复制配对令牌。在原站表格上方“配置”中填写地址和令牌，确认自动探测已开启。
4. 按 **L** 打开日志文件夹，按 **Q** 或 `Ctrl+C` 停止服务；直接关闭窗口也会停止。

首次启动自动创建 `%LOCALAPPDATA%\SOARProbe\config.json`。换目录、升级发布包或重复启动不会重置已保存的令牌和设置。升级便携版时替换整个程序文件夹，保留用户数据目录。服务仅绑定 `127.0.0.1`；重复运行遇到端口占用时会提示，不会关闭原有实例。

### 出现“应用程序控制策略已阻止此文件”

v1.3.0 已从依赖与发布包中移除 `_pydantic_core`，解决旧版本仍需加载这一扩展的问题。请关闭旧服务并完整解压新版本便携包；若仍看到 `_pydantic_core` 的错误，先确认运行的是新包中的 EXE，且没有将新旧版本的 `_internal` 混合。

推荐便携版从完整解压后的固定目录加载依赖；单文件版会临时解压依赖。两种布局仍包含 CPython 运行时和其他必要的 DLL/PYD，移除本次故障依赖**不能保证 Smart App Control 允许其他 EXE 或 DLL**。此版本未在用户开启 Smart App Control 的实机上验证；普通 Windows 构建与接口测试不代表该策略已批准程序。

便携包**不能保证通过 App Control、WDAC、Smart App Control 或单位应用白名单**。个人电脑启用 **Smart App Control（智能应用控制）** 时，应将它与单位管理的白名单策略区分。固定目录并不使未受信任的 EXE 或依赖 DLL 自动获得信任；发布文件的哈希用于核对完整性，不等同于 Smart App Control 的单应用放行规则。[微软说明](https://support.microsoft.com/en-us/windows/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003)指出，目前不支持对单个应用手动放行。外层 EXE 获得信任也不代表所有依赖 DLL 已受信任。如果拦截原因与应用信誉或受信任签名有关，单独改变打包方式不能代替这些要求。

如果设备由单位管理，请让管理员查看“事件查看器 → 应用程序和服务日志 → Microsoft → Windows → CodeIntegrity → Operational”等对应策略日志，确认具体被阻止的文件、路径和策略，再按单位流程审核相应文件的哈希或受信任签名。不要将这套企业策略审批方式当作个人 Smart App Control 的手动白名单功能。

提供完整错误、被阻止文件路径、版本和包内 `SHA256SUMS.txt` 即可协助核对；不要提供含令牌的 `config.json`。`Start-SOARProbe.cmd` 只保留错误窗口，不修改系统安全策略。无需为了此错误关闭防护、添加整个目录或磁盘的排除规则，或改为管理员运行。

相关背景：[PyInstaller 打包运行方式](https://pyinstaller.org/en/stable/operating-mode.html)、[Microsoft App Control 事件说明](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations)。

独立程序还支持这些命令，均不依赖外部 Python：

```powershell
.\SOARProbe.exe --version
.\SOARProbe.exe --copy-token
.\SOARProbe.exe --show-token
.\SOARProbe.exe --self-test
.\SOARProbe.exe --update-cdn-rules
```

`--version` 只打印构建版本后退出；`--show-token` 只在显式调用时显示令牌；`--self-test` 不创建配置、不发起 DNS/ICMP/TCP 探测，会报告 HTTP/校验实现与 CPython 运行时位置，并确认未打包 Pydantic Core；更新 CDN 规则需要联网，成功后保存到用户数据目录并在下次启动时生效。损坏的覆盖规则会阻止服务启动，避免无规则探测。日志和配置均不写入程序文件夹或单文件版的临时解包目录。

**源码包与发布包不同。** 当前源码包提供下面的 Windows 构建流程；如果目录中没有 `SOARProbe.exe`，需先在 Windows 构建。不能把源码 ZIP 或其他系统生成的二进制当成 Windows EXE。

## 从源码构建 Windows EXE

构建电脑需要 Windows 10/11 x64 和 64 位 Python 3.11 或更新版本；最终使用电脑不需要 Python。建议用 Python 3.12 构建。

1. 将本目录完整放到 Windows 构建电脑。
2. 双击 **`Build.cmd`**。构建需联网安装固定版本的构建依赖，脚本使用独立 `.build-venv`，会清除该构建环境中旧的 FastAPI/Pydantic/Pydantic Core，不会修改系统 Python 依赖。
3. 构建脚本先运行离线测试，再分别生成单文件版和便携版，检查 Windows x64 文件格式、冻结资源和 CPython 运行时，并检查没有残留 FastAPI/Pydantic/Pydantic Core。随后启动本地健康及认证检查，不下发任何探测目标。最终便携 ZIP 还会解压到带空格的目录，再执行同类检查。
4. 发布输出为 `dist\SOARProbe.exe`、`dist\SOARProbe-Windows-x64.zip`、`dist\SOARProbe-Windows-x64-portable.zip` 和校验文件。优先将便携 ZIP 发给使用者；使用者完整解压后即可运行，无须复制源码、虚拟环境或安装脚本。

包内同时提供 `.github/workflows/build-windows-probe.yml`，可使用 GitHub 提供的 Windows 构建环境，本机无需安装 Python：

1. 将构建包中的 `windows_probe_service` 文件夹和 `.github` 文件夹上传到自己的仓库，保持目录层级。
2. 在仓库 **Actions → Build Windows probe EXE → Run workflow** 手动运行。
3. 构建成功后下载 `SOARProbe-Windows-x64` artifact，解压获得 EXE、两种发布 ZIP 和校验文件。需要发布 GitHub Release 时，在 `release_tag` 填写与服务版本一致的标签（例如 `v1.5.1`）；留空只构建。

上传范围仅需构建包内容，不要上传本机配置、令牌或诊断日志。工作流仅手动触发；只有显式填写 `release_tag` 时，独立发布任务才获得写权限，在 Windows 构建、自检和校验成功后上传 Release 附件。用于发布的仓库还需包含 `RELEASE_NOTES.md`。

Windows EXE 必须在 Windows 上构建，不能将 macOS 产物转换或改名为 Windows EXE。请使用 Windows 构建脚本通过检查后生成的发布 ZIP。依据见 [PyInstaller 官方要求](https://github.com/pyinstaller/pyinstaller#requirements)。

## 直接运行 Python 源码

首次使用时安装当前油猴脚本 v24.0：将另外提供的 `SOAR 批量封堵调度.txt` 完整内容替换到原有脚本编辑器并保存，然后刷新原站页面。已有 v21.0 或更新脚本可继续使用；仅升级本服务无需重装脚本。服务发布 ZIP 不包含油猴脚本。若通过导入新增了脚本，请停用旧副本，避免同时运行多个版本。

1. 安装 Windows 64 位 Python 3.11 或更新版本，推荐 Python 3.11–3.13。安装程序中启用 Python launcher（`py`）。
2. 将整个 `windows_probe_service` 文件夹复制到 Windows 的固定目录，例如 `C:\SOAR\windows_probe_service`，保持所有文件一起复制，包含 `cdn_rules.json`。
3. 双击 `Install.cmd`。它创建目录内的 `.venv`，安装 `requirements.txt`，创建持久配置。首次安装需要能够访问所配置的 Python 包源。无需以管理员身份运行。
4. 双击 `Start.cmd`，保持窗口运行。默认服务地址为 `http://127.0.0.1:8765`；关闭窗口或按 `Ctrl+C` 停止服务。
5. 双击 `Show-Token.cmd`，复制显示的配对令牌。在原站告警表格上方点击“配置”（也可在工作台“设置 → 原站 IPv4 与域名探测”进入），填写服务地址、令牌和备用 DNS 并保存，在原站表格上方使用唯一的“自动探测”开关。“测试连接”仅验证服务和令牌，不提交探测任务。
6. 在**原站主页面**重新查询一次。仅本次成功查询返回的当前页进入探测，翻页也使用新页结果；无须在插件中执行告警处置查询。

脚本 v21.0 在没有已保存设置时默认开启自动探测；此前明确保存的关闭状态会保留，升级不会替你开启。开关、连接配置和统一安全过滤清单保存在该站点的 `localStorage`，刷新或重开页面后保留。旧探测配置中的额外排除 IPv4/CIDR 会合并迁移到“设置 → 安全过滤清单”，迁移时保留备份；之后在该清单统一管理。不要清理站点存储。令牌不要附在发给他人的日志中。服务端不会记录 Authorization 请求头，也不会将令牌写入诊断日志。`Show-Token.cmd` 只在显式运行时将令牌显示到该窗口。

沿用工作台单实例规则：**只有运行页执行自动探测**。其他原站页面保留启用/接管入口，需要在该页探测时先接管。关闭运行页后，其他页不会自动启用，需要手动点击入口；已有设置继续保留。

浏览器和 Python 服务必须运行在**同一台 Windows 电脑**。如果浏览器在远程桌面、虚拟机或另一台电脑上，`127.0.0.1` 指向的是浏览器所在系统。探测结果代表这台电脑的网络可达性。

## 服务配置和持久化

默认文件位于 `%LOCALAPPDATA%\SOARProbe\`，重新安装本目录不会覆盖已有令牌：

| 文件 | 用途 |
| --- | --- |
| `config.json` | 配对令牌、端口、并发、超时和缓存配置 |
| `cdn_custom_rules.json` | 可选的额外 CDN CIDR/域名排除规则 |
| `logs\probe.jsonl` | 详细 JSON 日志，包含查询 ID、任务 ID、目标、解析地址、跳过原因、结果和耗时 |

首次创建的 `config.json`：

```json
{
  "token": "首次安装自动生成的随机令牌",
  "port": 8765,
  "concurrency": 16,
  "timeoutMs": 3000,
  "operationsPerSecond": 50,
  "cacheSeconds": 60,
  "excludedCidrs": []
}
```

修改后重启服务（便携版为 `Start-SOARProbe.cmd`，源码版为 `Start.cmd`）。端口变化时同步修改脚本服务地址；令牌变化时重新配对。`concurrency` 范围 1–64，单项超时 200–10000 毫秒，每秒操作上限 1–200。默认在全服务范围统一限流，不随浏览器页面数增加并发。

服务始终只绑定 `127.0.0.1`，不支持改成 `0.0.0.0`。请保持单进程运行；不要启用 Uvicorn 多 worker 或 reload。重复启动会报告端口已占用，原服务可继续使用。

日志按 4 MiB 轮转，保留当前文件和 5 个历史文件；任务结果保存在内存，最多保留 32 个任务，已完成任务约一小时后可被清理。配置不会随日志和任务清理。相同目标、排除配置和有序 DNS 配置会合并并短时复用缓存，记录 `cached` 字段及完成时间。页面日志保存当前会话最近 1500 条诊断，导出时还包含当前完整结果；需长期归档时请导出，服务端另有持久日志。

## IPv4、公网、DNS 和 CDN 排除

默认安全过滤清单始终生效，包含 `210.39.0.0/20`、`202.127.241.128/25`、`172.0.0.0/8`、`116.13.96.0/20`、内网和特殊地址，以及默认清单中的单个 IPv4。脚本还会读取“设置 → 安全过滤清单”当前保存的 IPv4 规则，和默认规则取并集后随任务下发。服务端内置默认清单；旧 `config.json` 中 `excludedCidrs` 为空也不会绕过默认保护。IPv6 规则不下发，因为整个探测仅接受 IPv4。

直接 IP 在前端提取时排除；域名解析出的每个 IPv4 在服务端再次检查。修改并保存清单后，当前页会取消旧结果并按新清单重新探测。排除规则纳入任务去重和缓存标识，命中清单的 IP 不会沿用先前的绿色或红色标记。

服务端的排除判断具有最终决定权。即使脚本误传了私网地址，或域名解析出私网地址，服务也不会向它发起 ICMP/TCP 检测。IPv6 不探测，也不会为域名发起 AAAA 查询。

内置清单排除常见公共 DNS（例如 `8.8.8.8`、`1.1.1.1`、`223.5.5.5`、`119.29.29.29`、`114.114.114.114` 等）；启动时还会排除 Windows 当前配置的 DNS 服务器。明确的 DNS 服务端口 `53`、`853` 也会跳过。任务中配置的备用 DNS 也自动排除，不会作为 IP 或域名解析结果的探测目标；此排除只作用于该任务，不会更改其他任务的配置。未配置的其他单位 DNS 可加入安全过滤清单。

需要补充 IPv4 或 CIDR 排除规则时，使用工作台“设置 → 安全过滤清单”，也可从探测配置中的“安全过滤清单”入口进入。清单随每批任务下发，服务会在域名解析后再次应用。不同排除清单的任务不会共用可绕过规则的缓存。在服务 `config.json` 的 `excludedCidrs` 中还可设置本机固定排除网段，例如 `["203.0.113.10/32"]`（示例为文档保留地址；实际请替换），修改服务配置后重启。

域名先用 **系统 DNS**，随后按探测配置中保存的备用 DNS 顺序查询 A 记录和 CNAME。默认备用列表为 `8.8.8.8`、`223.5.5.5`；脚本 v25.9 的探测配置提供默认、百度 `180.76.76.76`、阿里 `223.5.5.5/223.6.6.6`、仅系统 DNS 和自定义场景，最多 8 个规范 IPv4，去重并保留顺序，留空表示仅用系统 DNS。允许单位内网 DNS 作为解析服务器，但会拒绝 0/8、回环、链路本地、多播和特殊保留地址；它们只能参与 DNS 查询，内网地址仍不能作为 Ping/TCP 目标。列表持久保存在浏览器 localStorage，随每项任务发送，不需要编辑服务 config.json。自定义 DNS 需要服务 v1.4.0；旧脚本省略此字段时仍按原默认列表解析。只有解析失败（包括超时、无 A 记录、NXDOMAIN 或 DNS 服务错误）才尝试下一项；首次成功解析后立即停止切换 DNS。解析结果命中 CDN、安全过滤清单或其他排除规则，以及后续 Ping/TCP 不通，都不会触发 DNS 回退。全部解析失败时不执行目标的 Ping/TCP。这里的公共 DNS 只用于解析，DNS 服务器本身仍被排除，不作为探测目标。

拿到解析结果后，先检查域名/CNAME 是否属于已知 CDN，再逐个排除非公网 IPv4、DNS、CDN 和安全清单命中的地址，只向剩余数字 IPv4 发起 Ping/TCP。每次 DNS 尝试使用单项超时和全局限流；日志中的 `nslookup.attempts` 保留尝试顺序、服务器、结果和耗时。


`cdn_rules.json` 是附带的已知 CDN/WAF IP 网段和域名后缀库，来源、版本、更新时间及授权见文件本身和 `LICENSE.cdncheck.md`。规则库不是全网 CDN 的完整证明；新分配网段、私有 CDN 或未公开节点仍可能未收录。命中 IP 网段、原域名或解析链 CNAME 后均跳过检测。未收录情况可以补充自定义规则。数据损坏或缺失时服务停止启动，避免无规则探测。

在 `%LOCALAPPDATA%\SOARProbe\cdn_custom_rules.json` 增加规则示例：

```json
{
  "cidrs": [
    {"cidr": "192.0.2.0/24", "provider": "Example CDN", "source": "本地人工规则"}
  ],
  "domainSuffixes": [
    {"suffix": "cdn.example.com", "provider": "Example CDN", "source": "本地人工规则"}
  ]
}
```

示例地址仅用于展示格式，属于文档保留段，本就会跳过。实际使用时填写要排除的网段和后缀。后缀匹配完整 DNS 标签，例如 `cdn.example.com` 同时排除 `a.cdn.example.com`，不会匹配 `evilcdn.example.com`。规则修改后重启服务。

附带 `update_cdn_rules.py` 可手动刷新规则库。在服务文件夹打开 PowerShell：

```powershell
# 联网更新；读取 ProjectDiscovery/cdncheck CDN/WAF 和域名数据，校验 Git blob SHA
.\.venv\Scripts\python.exe update_cdn_rules.py
# 或导入已下载的上游 sources_data.json，适合离线环境
.\.venv\Scripts\python.exe update_cdn_rules.py --input C:\Downloads\sources_data.json
```

刷新失败不会替换原文件；成功校验后原子替换，重启服务后生效。自定义规则保存在独立文件中，更新不会覆盖。服务启动和查询时不会自动从互联网下载规则库。健康接口提供当前规则版本和数量，便于核对。仅使用上游 CDN/WAF 分类及域名后缀，不将所有公有云网段当作 CDN。

## 结果含义

| 状态 | 含义 |
| --- | --- |
| Ping `reachable` | Windows ICMP API 收到成功回应，另有 `roundTripMs` |
| Ping `timeout/unreachable/error` | 无回应、不可达或本机 API 错误；不能据此认定主机离线 |
| TCP `open` | 到该 IP/端口的 TCP 连接建立成功，不代表业务内容正确 |
| TCP `refused/timeout/error` | 连接被拒绝、超时或网络/系统错误 |
| `skipped_private` | 非公网或特殊用途地址，没有发起探测 |
| `skipped_cdn` | 命中已知 CDN/WAF 网段、域名或 CNAME，没有发起探测 |
| `skipped_dns` | 常见公共 DNS、系统 DNS、DNS 域名或 DNS 端口，没有发起探测 |
| `skipped_custom` | 命中脚本下发的安全过滤规则或服务排除网段，没有发起探测 |
| `skipped_safety` | 命中内置默认安全过滤清单，没有发起探测 |
| `skipped_ipv6` | 仅支持 IPv4，没有发起探测 |

默认每个 IPv4 固定 Ping 5 次、每个 TCP 端口固定连接 3 次、单次操作超时 3000 ms。每次操作都记录到 `attemptDetails`，前端逐条显示；任一 Ping 有回应或任一 TCP 连接成功即判定目标连通，全部失败才判定不可达。脚本 v25.10 的探测配置可修改次数（各 1–10）和单次超时（200–10000 ms），设置随每次任务下发并参与缓存/共享任务隔离。

Windows Ping 使用原生 IPv4 `IcmpSendEcho`，不解析中英文 `ping.exe` 输出，无须开启 Telnet 客户端，也不使用原始套接字。TCP 使用 asyncio 建立连接并立即关闭，等同于使用 Telnet 验证端口是否能建立连接，不发送登录或业务数据。Ping 超时、不可达或出错也会继续检测端口。端口规则如下：

| 目标 | 检测内容 |
| --- | --- |
| IPv4 或域名有明确对应的端口 | Ping，并且仅连接该端口；明确对应的源端口、目的端口都执行 |
| 域名没有端口 | DNS 解析、过滤后执行 Ping，并连接 TCP 80、443 |
| IPv4 没有端口 | 只执行 Ping，不补充默认端口 |

脚本 v21.0 始终提交数据中明确关联的源端口，无须单独开启；不会把一行中无关的端口组合到所有 IP。显式 UDP 和 DNS 端口 53/853 会跳过 TCP。不接受端口范围，也不执行任意端口扫描。

最多接受每任务 4000 个目标、4 个同时活动任务、8192 个排队的唯一目标。一次 DNS 返回超过 64 个地址或 A/CNAME 解析证据不完整时，该目标停止探测并记录错误，避免凭不完整的 CDN 判定发起连接。重复目标跨行共享结果，翻页/重新查询后旧结果不应覆盖新表格。

## 排错

- **应用程序控制策略阻止 DLL：** 先确认完整解压并运行 v1.3.0 的新包，避免混用旧依赖。新包已移除 `_pydantic_core`；个人 Smart App Control 仍可能拒绝其他程序或依赖，按上文区分代码信任与企业策略审批。启动被阻止时可能尚未生成服务日志，请保留完整错误窗口和具体文件路径。
- **无法连接服务：** 检查服务窗口是否运行，打开 `http://127.0.0.1:8765/health` 应看到 `status: "ok"`。此接口不返回令牌。
- **401：** 服务令牌与脚本中保存的令牌不一致，在服务窗口按 C 复制令牌后保存脚本配置；源码版也可运行 `Show-Token.cmd`。
- **429：** 全局队列或活动任务达到上限，稍后重新探测，避免快速重复查询。
- **端口占用：** 关闭重复实例，或修改 `config.json` 的 `port` 并同步脚本地址。
- **没有某个目标的检测：** 查看脚本详细日志和服务 JSON 日志，确认是否属于 IPv6、非公网、DNS、CDN、安全过滤清单、自定义排除、UDP、数量上限或 DNS 解析失败。IPv4 无端口只检测 Ping；域名无端口会检测 80、443。
- **浏览器访问限制：** 脚本使用 `GM_xmlhttpRequest` 并声明本机 `@connect`；新版本浏览器/油猴可能要求授予本地访问权限。不要通过关闭整个浏览器安全策略解决。

提供日志时可以导出脚本探测日志并附上服务端相关时间段的 `probe.jsonl`。其中可能包含告警目标地址，按需要脱敏；不要附上 `config.json` 或 `Show-Token.cmd` 窗口中的令牌。

## API v1

除 `GET/HEAD /health` 外，都要求 `Authorization: Bearer <token>`，仅接受本机来源和本机 Host。底层继续使用 Starlette 与纯 Python 校验；v1.4.0 增加可选的 dnsServers 字段，旧客户端省略时保持原行为。

- `GET/HEAD /health`：匿名健康检查；`customDnsServers: true` 表示支持请求级备用 DNS，`dnsServers` 为默认备用列表；`probeSettings: true`、`defaultPingCount`、`defaultTcpAttempts`、`defaultProbeTimeoutMs` 表示支持请求级 Ping/Telnet 次数和超时。
- `GET /v1/auth-check`：认证检查，不创建任务、不执行 DNS/ICMP/TCP。
- `POST /v1/probes`：提交 `{"queryId":"q1","excludedHosts":["93.184.216.34"],"excludedCidrs":["210.39.0.0/20"],"pingCount":5,"tcpAttempts":3,"timeoutMs":3000,"targets":[{"id":"t1","host":"example.com","port":443}]}`，返回 HTTP 202 和 `jobId/queryId/total/cursor`。`port` 可省略或为 `null`：域名按 80、443 检测，IPv4 只检测 Ping；有 `port` 时只检测指定端口。`excludedHosts` 为兼容旧客户端保留，可省略，最多 200 个规范 IPv4；`excludedCidrs` 可省略，最多 2048 个规范 IPv4 地址或网络地址 CIDR。脚本 v21.0 从统一安全过滤清单生成排除规则。`dnsServers` 可省略或传 IPv4 字符串数组，默认 `["8.8.8.8","223.5.5.5"]`，明确传 `[]` 表示仅系统 DNS；最多 8 个，去重保序，不能为 null。`pingCount`、`tcpAttempts` 可省略，默认均为 5 和 3，范围各 1–10；`timeoutMs` 可省略，默认 3000，范围 200–10000。所有排除配置、有序 DNS 配置、重试次数和超时均参与缓存与共享任务隔离，并检查域名解析后的地址。
- `GET /v1/probes/{jobId}?after=0`：返回任务状态、`total/completed/cursor` 和该游标之后完成的 `results`。使用上次返回的 `cursor` 继续读取；结果完成顺序不保证与提交顺序一致，使用目标 `id` 回填。
- `DELETE /v1/probes/{jobId}`：取消该任务后续结果。尚未开始且无人订阅的共享目标会跳过；已发出的单次 ICMP/TCP 在有限超时内结束，其他任务订阅的共享目标继续执行。

每个目标返回 `id/host/port/resolved/aliases/dns/nslookup/ping/tcp/cached/finishedAt`；`nslookup` 包含 A 记录、CNAME、采用的解析服务器和逐次尝试详情，直接 IPv4 为 `not_applicable`。DNS 命中 CDN 时附带 `skipped`。跳过项含 `reason/rule/source`，规则有供应商信息时附带 `provider`。不提供任意命令执行、端口范围扫描或转发原站登录凭据的接口。

提交请求必须使用 `Content-Type: application/json`，否则返回 415。身份验证先于 JSON 与字段校验；无效令牌返回 401，错误 JSON、未知字段、重复目标 ID、非整数端口或非法游标返回 422。端口只接受 1–65535 的整数或 `null`，不将字符串、布尔值或浮点数自动转换。请求正文最多 2 MiB，超过返回 413。错误响应不回显提交的目标、原始正文或令牌。

## 离线测试

在本目录运行：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

189 项离线测试通过模拟 DNS、ICMP、TCP 和本地 HTTP ASGI 请求检查自定义 DNS 顺序、仅系统模式、解析服务器排除、配置快照与缓存隔离，以及策略、队列、去重、取消和协议，包括认证顺序、严格 JSON/类型校验及正文大小限制，不向真实目标发起网络探测。GitHub Actions 在 Windows 上执行测试，并实际启动生成的两种 EXE 验证冻结资源、依赖移除、健康接口和令牌认证；便携 ZIP 会完整解压后再次验证。构建环境不复现部署机器的 Smart App Control 策略，测试通过不等同于已获得该机器的策略批准。实际目标的网络可达性取决于部署机器；详细证据记录在日志中。


## K01 威胁情报（v1.6.9）

脚本 v25.5 在 IPv4、域名复制按钮旁提供独立情报图标，并恢复 `/soar/scripts/script` 页面的“JSON 参数”和“清空变量”工具，点击打开详情抽屉。先在脚本设置中配置本地服务连接，再配置 K01 HTTPS 地址和 API 组账号。API 用户通过 `/api/cms/user/login` 获取访问令牌，资源请求使用 Bearer 调用 `/api/v1/threatintelligence/api/traceability`。账户配置保存在现有用户数据目录 `config.json` 的 `k01` 字段，现有配对令牌和探测配置保留。密码字段留空保留原密码，“清除已保存密码”明确清除。API 密码与访问令牌不随配置查询返回。

默认校验 K01 HTTPS 证书；可在更多设置填写 CA PEM 路径。需要兼容不受信任证书时，可显式勾选“忽略证书校验（不安全）”，该设置仅影响 K01 API 上游 TLS 证书与主机名校验，TLS 加密仍开启。关闭校验可能连接到伪装的 K01 服务并暴露 API 凭据，只建议在受控网络临时使用。默认仍校验。上游只使用保存的站点及两条固定接口，禁止跨站重定向。没有新增第三方依赖。

SOARProbe 启动时第一行就打印构建版本（`SOARProbe v<版本> (API v1)`，写到 stderr 以保持 `--self-test` 等命令的 stdout 是纯 JSON），窗口标题同时显示版本与监听端口，`service_started` 日志记录 `serviceVersion`；`GET /health` 返回 `version`（服务版本）和 `apiVersion`（接口版本）。

K01 的每个响应（成功和失败）都带 `serviceVersion`，脚本日志与导出 JSON 一并记录，面板显示 `probe v<版本>`。**排查“改了好像没生效”时先看这个字段**：显示“probe 版本未知”或与发布标签不一致，说明该机器上跑的还是旧 EXE，需要替换 exe 后重启服务。

账号未配置、API 登录拒绝或正式接口不可用时，本地服务返回 `K01_FRONTEND_REQUIRED`。启用脚本的网页登录兜底，并保持已登录且已加载情报检索的 K01 标签页，脚本在该页面内调用原站请求函数或该页面自身可用的访问令牌。会话认证由浏览器执行；本服务不读取、接收或保存网页登录 Cookie、JWT 和签名。结果标记实际认证来源。

改密弹窗按照 `k01_website_resources` 中的 Ant Design `ant-modal` / `ant-form` / `ant-input` / `ant-btn` DOM 结构实现，并限制在独立作用域，避免与 SOAR 的 Quasar 样式冲突；`/soar/scripts/script` 工具继续使用 `website_resources` 中实际页面的 `.formily-qaxd-array-table`、`input[name=key/default/type]` 和原生 input/change 事件。

如果 K01 以 `success:false`、`error_code:10140`（`The initial password has not been changed`）拒绝溯源查询，说明 API 账号仍在使用初始密码。服务返回 `K01_FRONTEND_REQUIRED`、`reason:api_initial_password_required`、`diagnosticCode:initial_password_not_changed`；工作台脚本不会对该诊断静默走会话兜底，而是在情报面板显示“修改初始密码”入口。用户输入新密码后，脚本调用本地 `POST /v1/intelligence/change-password`；服务使用已保存的旧 API 密码调用 K01 `/api/v1/account/changepwd`，成功后原子保存新密码并重新登录查询，新密码和旧密码均不出现在响应或日志中。其他业务拒绝也会附带脱敏后的上游 `msg`，便于定位原因。

新增接口都沿用本地配对 Bearer 鉴权：

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/v1/intelligence/status` | 读取情报能力与配置状态 |
| GET | `/v1/intelligence/config` | 读取脱敏配置 |
| PUT/POST | `/v1/intelligence/config` | 保存 K01 地址、API 账户、超时和缓存配置 |
| POST | `/v1/intelligence/change-password` | 使用本地已保存的旧 API 密码修改 K01 API 初始密码，正文 `{newPassword,confirmPassword}`，成功后保存新密码 |
| POST | `/v1/intelligence/trace` | 单个 IPv4/域名溯源，`{host,count:10,force:false}` |

`success` 代表请求成功；厂商空记录、过期记录、未知结论和请求失败分开表示。每个目标的并发查询合并并短期缓存，强制刷新跳过缓存。日志只记录脱敏信息。构建会测试真实 EXE 的配置读取和未配置时的会话兜底响应，这些检查不请求 K01。
