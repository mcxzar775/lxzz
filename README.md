# VPNGate Multi-Exit Manager

VPNGate 多出口管理系统。当前版本具备可迁移数据库、网页登录、角色权限、审计与完整 Vue 管理台，并已完成 VPNGate 节点安全导入、快速与完整节点检测、连接生命周期、受限命令执行、Network Namespace 编排、OpenVPN 进程管理、独立 SOCKS5/3proxy 管理和按连接隔离的 Kill Switch。

网络安全默认值是 **模拟执行器**。应用不会在开发或测试期间修改宿主机默认路由、防火墙、Network Namespace 或 SSH 网络。只有显式设置 `VPNGATE_ENABLE_REAL_NETWORK=true` 才能构造真实执行器；受限 Root Helper 还会从 root 所有、不可写的安装配置中再次确认该开关。

节点刷新只从 HTTPS 数据源下载 CSV，不会启动 OpenVPN。公开配置在入库前必须通过 IP、端口、协议和指令白名单；脚本、插件、外部文件路径及未知指令会被拒绝。需要暂存净化后的 OpenVPN 文件时，`SecureConfigStore` 使用固定文件名、原子替换、`0700` 目录和 `0600` 文件权限。

节点检测分为 fast 和 full。fast 模式检查主机名解析是否仍包含节点公开 IPv4；TCP 节点执行带连接和总超时的端口连接，UDP 节点仅执行不发送载荷的路由基础检查，因此 UDP fast 成功不会单独将节点标记为可用。full 模式使用最多 3 个保留扫描槽，依次创建临时 Namespace、安装不带公网 SOCKS 映射的 Kill Switch、启动 OpenVPN、确认 `tun0` 和隧道路由，并在 Namespace 内通过固定 HTTPS 目标获取出口 IP 和限量测速，随后按 OpenVPN、规则、Namespace 的安全顺序清理。扫描状态、延迟、出口 IP、标准化错误码和清理结果保存到 `node_scan_results`；模拟扫描始终标记 `simulated=true`，不会更改节点真实可用状态。

真实 full 扫描成功后会对实际出口 IP 执行可解释分类，保存出口国家/城市、ASN、运营商、PTR、网络类型、置信度、规则依据与更新时间。默认分类器完全离线，只使用已有的 VPNGate/PTR/缓存信息；可选 IPinfo Lookup 集成只接受固定 HTTPS 端点、Bearer 令牌、有限响应大小与超时，失败时自动回退到本地规则且不影响扫描结果。外部查询必须同时设置 `VPNGATE_ENABLE_REAL_IP_INTELLIGENCE=true` 和私密的 `VPNGATE_IPINFO_API_TOKEN`，令牌不会写入数据库、审计或响应。

解锁检测覆盖 Netflix、ChatGPT、OpenAI API 与 YouTube。默认探针返回带 `simulated=true` 的确定性 `UNKNOWN`，不会打开网络连接。真实探针只接受枚举服务名，并由 Root Helper 在对应 Namespace 内确认 Kill Switch 与 `tun0` 后访问固定 HTTPS 目标；正文仅在 Helper 内用于状态判断，不写入日志、数据库或 API。Netflix 区分完整目录、仅自制内容、阻断与可达；ChatGPT 检查 DNS/TLS/HTTP、固定静态资源和基础 WebSocket Upgrade，并区分可用、地区限制、挑战页和 HTTP 阻断；OpenAI API 仅做无凭据网络连通性检查；YouTube 尽力识别地区。启用真实检测必须同时开启真实网络、防火墙、OpenVPN 与 `VPNGATE_ENABLE_REAL_UNLOCK_CHECKS=true`。

自动切换模块按连接执行健康检查，识别 OpenVPN 断线、出口 IP 缺失或变化、连续失败、延迟/速度不达标、网络类型不符和指定服务失效。候选节点会排除当前节点、不可用节点和黑名单，并按失败次数、延迟、速度、评分及 ID 做稳定排序。切换时先停止 SOCKS5，确认 Kill Switch 仍存在，再停止旧 OpenVPN、更新为候选节点的精确规则、启动新 OpenVPN、验证出口 IP、网络类型及指定服务，全部通过后才恢复 SOCKS5；失败时代理保持关闭，并保留可用的 Kill Switch。每条连接最近一小时最多执行 5 次自动切换尝试，事件会保存标准化结果但不包含配置正文或凭据。

后台健康监控默认由 `VPNGATE_ENABLE_AUTO_SWITCH=false` 关闭；即使开启，默认连接驱动仍是模拟实现，不会调用网络执行器。真实自动切换必须精确设置 `VPNGATE_ENABLE_REAL_AUTO_SWITCH=true`，并同时开启真实网络、防火墙、OpenVPN、SOCKS5、full 探测和解锁探测。延迟、最低速度、允许网络类型和必须通过的服务可通过对应 `VPNGATE_AUTO_SWITCH_*` 设置约束。

管理台包含运行仪表盘、节点筛选/刷新/批量扫描/黑名单、连接创建/启停/重启/切换/健康检查/凭据轮换、解锁检测、统一脱敏日志以及用户和非敏感设置管理。创建与轮换 SOCKS5 密码时明文只在单次响应中返回，数据库仅保存密文，审计日志不保存密码。真实连接生命周期还需要显式设置 `VPNGATE_ENABLE_REAL_CONNECTIONS=true`，并同时开启真实网络、防火墙、OpenVPN、SOCKS5 与 full 扫描；否则生命周期使用确定性的模拟驱动。

应用启动采用 fail-closed 恢复：数据库中未停止的连接或仍标记活动的 SOCKS5 端点，在重新验证前全部关闭。模拟模式只更新数据库且不会调用网络执行器；真实连接模式先通过固定 `connection-purge <连接 ID>` Helper 清理项目受管的进程、规则、Namespace、DNS 与 veth，任何清理失败都会阻止服务进入可用状态。

系统设置页只保存允许公开的运行参数并提示重启生效。API Token、Cookie 密钥、凭据密钥和全部真实执行开关必须在 root 管理的环境配置中维护，不允许从 Web 写入或回显。TOTP 字段会显示认证模型的真实状态；当前版本尚未开放 TOTP 配置流程。

命令执行层不接收任意命令行。它只接受枚举化操作，Namespace、veth、tun、IP、端口和受管路径必须通过严格校验，再由 Helper 映射为固定的 `ip` 参数数组。所有进程均使用非交互 sudo、固定环境、有限超时、输出长度上限和凭据脱敏，且没有使用 `shell=True`。sudoers 只允许服务账户执行 `/usr/local/libexec/vpngate-manager-helper`，不包含 `NOPASSWD: ALL`。

Namespace 资源按连接 ID 确定性分配：`lxvpn-<id>`、`lvh<id>`、`lvn<id>` 和 `10.220.0.0/16` 内互不重叠的 `/30` 子网。编排只在目标 Namespace 内设置默认路由，不修改宿主机默认路由；DNS 写入固定的 `/etc/netns/lxvpn-<id>/resolv.conf`。任一步失败都会尝试清理 DNS、Namespace 和 veth，并单独报告残留清理失败。连接切换 API 默认只使用模拟驱动；只有全部真实功能开关满足时才会触发已存在 Namespace 内的真实切换。

OpenVPN Manager 只接受已规范化的数据库配置，写入权限固定为 `0600`。Root Helper 启动前会再次执行完整白名单解析并要求内容保持字节级规范化一致，随后原子复制到 root 所有的 `0600` 运行时文件，避免服务进程篡改配置或在校验与打开之间替换文件。OpenVPN 只能通过固定的 `ip netns exec lxvpn-<id>` 命令启动，PID、日志、配置路径、`script-security 1` 和降权账户均由 Helper 生成。启动后必须同时看到 `tun0` 为 UP 且默认路由指向 `tun0`；超时或进程退出会自动停止。停止前会核验 `/proc/<pid>/exe` 和受管命令参数，拒绝伪造 PID 文件。

Kill Switch 优先使用 nftables，在不可用时才回退至 iptables，单次连接不会混用两种后端。每条连接只创建带连接 ID 的项目专用表或链，不刷新宿主机全局规则。Namespace 侧默认拒绝流量，只允许经 veth 访问该节点 OpenVPN 的固定 IPv4、协议和端口，以及经 `tun0` 出站；宿主机侧只为对应远端做精确转发与 NAT，并将公开 SOCKS 端口按客户端 IPv4/CIDR 白名单映射到 Namespace。OpenVPN 与 SOCKS5 启动前必须验证规则仍存在，且节点 ID、SOCKS 端口和已净化配置一致；隧道中断时 Namespace 不存在借用宿主机公网出口的放行路径。

真实防火墙必须先显式设置 `VPNGATE_ENABLE_REAL_NETWORK=true` 和 `VPNGATE_ENABLE_REAL_FIREWALL=true`。真实 OpenVPN 还必须设置 `VPNGATE_ENABLE_REAL_OPENVPN=true`，且 Kill Switch 已安装；真实 SOCKS5 再额外要求 `VPNGATE_ENABLE_REAL_SOCKS5=true` 和就绪的 `tun0`。Root Helper 从 root 所有配置中再次确认所有开关。本地开发和自动化测试不会调用这些真实功能。公网端口映射依赖 Linux IPv4 forwarding；Helper 和安装器不会静默修改该内核设置，`scripts/diagnose.sh` 会在真实防火墙开启时检查并报告。

主机侧真实 fast 扫描需要精确设置 `VPNGATE_ENABLE_REAL_SCANS=true`。真实 full 扫描还必须同时开启真实网络、防火墙、OpenVPN 和 `VPNGATE_ENABLE_REAL_FULL_SCANS=true`；应用设置与 root 所有 Helper 配置会分别校验。所有扫描默认使用模拟实现，不会连接节点或更改本机网络。完整扫描失败或请求取消时会等待有界清理完成后才归还扫描槽；若 OpenVPN 无法停止，则保留 Kill Switch 和 Namespace，而不是冒险拆除隔离。

SOCKS5 默认从 `21000–21999` 自动分配端口，也支持池内手动指定。用户名、随机强密码、客户端 IPv4/CIDR 白名单、最大连接数和超时均经过严格规范化；数据库只保存与连接 ID 绑定的 Fernet 认证密文，密钥文件固定为 `0600`，日志和命令行都不会出现明文密码。启动时应用仅暂存一个 `0600` JSON 规范，Root Helper 再次逐字段验证并生成 root 所有的 `0600` 3proxy 配置，随后删除应用侧明文规范。代理启动前必须确认 `tun0` 和默认隧道路由，PID、3proxy 二进制、运行时配置以及监听端口都必须匹配；失败或超时会自动停止并清理。

安装脚本在系统没有 3proxy 时会下载固定的 `0.9.6` 源码、验证 SHA-256 后构建，只安装受管二进制；开发和测试不会启动真实代理。

## 本地开发

要求：Python 3.10+、uv、Node.js 20+、pnpm 11。

```bash
make install-dev

cd backend
VPNGATE_DATABASE_URL=sqlite:///./data/vpngate.db uv run alembic upgrade head
VPNGATE_DATABASE_URL=sqlite:///./data/vpngate.db uv run python -m app.cli create-admin
VPNGATE_DATABASE_URL=sqlite:///./data/vpngate.db uv run uvicorn app.main:app --host 127.0.0.1 --port 8765
```

另一个终端启动前端：

```bash
cd frontend
pnpm dev
```

浏览器访问 `http://127.0.0.1:5173`。开发服务器将 `/api` 代理到本机后端。

## 验证

```bash
make test
make build
make acceptance
make release-check
```

`make test` 会运行 Python 语法检查、mypy、pytest、Vue TypeScript 检查、`bash -n`，并在存在 ShellCheck 时运行 ShellCheck。`make build` 会生成 Python wheel 和 Vue 生产构建。

`make acceptance` 单独运行双连接隔离与启动恢复的跨模块模拟验收。`make release-check` 在完整测试和构建后执行 Alembic 升降级往返、静态安全检查、可复现发布打包及清单校验；如果任一真实网络功能环境变量已经开启，它会直接拒绝运行。详细验收矩阵、部署和发布说明分别位于 `docs/ACCEPTANCE.md`、`docs/DEPLOYMENT.md` 与 `docs/RELEASE.md`。

## 发布包

```bash
make release
bash scripts/verify-release.sh dist/vpngate-manager-0.1.4.tar.gz
```

发布命令生成带外部 SHA-256 文件和内置逐文件 `RELEASE-MANIFEST.json` 的规范化归档。`.env`、凭据密钥、SQLite 数据库、缓存、虚拟环境、`node_modules` 和工作目录不会进入发布包；校验器拒绝路径穿越、符号链接、特殊文件、重复成员、未列入清单的文件和摘要不匹配。

将源码托管到 GitHub 并创建同版本 Release 后，可以使用 `scripts/install-from-github.sh` 完成校验后安装。上传步骤、Release 资产清单和版本固定的一键命令见 `docs/GITHUB.md`。

## Linux 安装与维护

支持 Ubuntu/Debian 与 Rocky/AlmaLinux/CentOS Stream 9 系列。安装器默认创建自签名 TLS 证书；生产部署应替换为受信任证书。

```bash
sudo bash scripts/install.sh
sudo bash scripts/upgrade.sh
sudo bash scripts/repair.sh
sudo bash scripts/diagnose.sh
sudo bash scripts/reset-password.sh
sudo bash scripts/uninstall.sh
```

所有修改型维护脚本使用 `/run/lock/vpngate-manager-maintenance.lock` 互斥。配置文件必须是 root 所有的普通文件、权限为 `0600` 或 `0640`，仅接受不重复的 `VPNGATE_*` 赋值；脚本不会以 root 身份 `source` 配置，而是通过受控的干净环境把配置交给服务账户。

安装过程交互式创建首个超级管理员，并安装 root 所有的受限 Helper 与最小 sudoers 规则。安装器会重新构建 Vue、创建原子发布目录、执行 Alembic、运行 Helper 自检、启动服务并验证健康接口版本。非交互安装可临时传入 `VPNGATE_ADMIN_USERNAME` 与 `VPNGATE_ADMIN_PASSWORD`；密码会写入服务账户可读的临时 `0600` 文件，CLI 读取后立即删除，不会进入命令参数或输出。只有明确设置 `VPNGATE_USE_PREBUILT_FRONTEND=true` 才会跳过前端重建。

升级脚本先在独立目录构建完整新版本，再停止服务并备份 root 私有配置、当前应用和受管 SQLite 数据库（包括可能存在的 WAL/SHM）。随后原子切换代码、执行 Alembic、更新 Helper/systemd/Nginx、运行自检并验证运行版本。迁移、配置、自检或健康检查任一步失败都会恢复旧应用和数据库；备份保留在 `/var/lib/vpngate-manager/backups/`。外部数据库必须先由运维人员完成独立备份，并显式设置 `VPNGATE_UPGRADE_ALLOW_EXTERNAL_DATABASE=true`。重复部署相同版本默认拒绝，可在确认需要时临时设置 `VPNGATE_ALLOW_SAME_VERSION_UPGRADE=true`。

`repair.sh` 会修复虚拟环境、目录权限、Helper、sudoers、systemd 与 Nginx 资产，并确认数据库位于 Alembic head，但不会重建或清空数据库。`diagnose.sh` 是只读检查，覆盖依赖、权限、配置、证书、迁移、服务状态、运行版本和全部真实执行开关。`reset-password.sh` 会离线重置指定用户密码、撤销该用户全部 Session 并记录不含密码的审计事件；可使用 `VPNGATE_RESET_USERNAME` 和 `VPNGATE_RESET_PASSWORD` 非交互执行，密码同样通过一次性 `0600` 文件传递。

卸载前会汇总数据库和运行时中严格匹配项目命名规则的连接 ID，通过 Root Helper 依次停止托管 OpenVPN/SOCKS5，并删除对应的项目专用防火墙、Namespace、DNS 和 veth。任一资源无法确认清理时，卸载会在删除 Helper 和应用前失败。默认保留配置、数据库、备份、日志以及服务账户以便恢复；只有显式设置 `VPNGATE_PURGE_DATA=true` 才会删除这些状态，此操作不可由脚本恢复。非交互卸载还必须设置 `VPNGATE_UNINSTALL_CONFIRM=YES`。

## API

基础前缀为 `/api/v1`：

- `POST /auth/login`
- `POST /auth/logout`
- `GET /auth/me`
- `POST /auth/password`
- `GET /dashboard`
- `GET /nodes`
- `POST /nodes/refresh`
- `POST /nodes/{id}/scan?scan_type=fast|full`
- `POST /nodes/{id}/classify`
- `POST /nodes/{id}/block`
- `DELETE /nodes/{id}/block`
- `GET /connections`
- `POST /connections`
- `POST /connections/{id}/start`
- `POST /connections/{id}/stop`
- `POST /connections/{id}/restart`
- `POST /connections/{id}/rotate-password`
- `DELETE /connections/{id}`
- `POST /connections/{id}/health-check`
- `POST /connections/{id}/switch`
- `POST /connections/{id}/check-unlock`
- `GET /connections/{id}/checks`
- `GET /connections/{id}/events`
- `GET /nodes/{id}/scans`
- `GET /logs`
- `GET/PUT /settings`
- `GET/POST/PATCH/DELETE /users`
- `POST /users/{id}/password`

修改类请求使用 Cookie Session，并要求 `X-CSRF-Token` 与 `vpngate_csrf` Cookie 匹配。公开注册默认不存在。

`GET /nodes` 和扫描历史对三种角色开放，支持国家、协议、可用状态、搜索、排序和分页。节点刷新与扫描仅允许超级管理员和管理员调用，要求 CSRF，并记录不含配置正文的脱敏审计事件。
