# 验收指南

本项目把验收分为默认模拟验收和显式开启的真实 Linux 验收。默认命令不会创建 Network Namespace、启动 OpenVPN/3proxy，也不会修改宿主机路由或防火墙。

## 自动化验收

在源码根目录执行：

```bash
make test
make acceptance
make build
make release-check
```

`make acceptance` 使用临时 SQLite 数据库和模拟执行器完成一条跨模块流程：登录、创建两个出口、验证 Namespace 与 SOCKS 端口隔离、启动连接、核对模拟出口、执行四类解锁检测、停止其中一个出口并确认另一个不受影响、删除连接并检查级联清理。整个过程断言模拟网络执行器没有收到任何宿主机命令。

服务启动时还有一项 fail-closed 验收：数据库中处于运行或过渡状态的连接，以及仍标记为活动的 SOCKS 端点，在被重新验证前都会被关闭。模拟模式只修正数据库状态；真实连接模式先通过固定的 `connection-purge <连接 ID>` Helper 清理受管运行时资源，任一清理失败都会阻止应用启动。

## 文档验收矩阵

| 开发文档标准 | 默认自动化证据 | 真实 Linux 验收 |
| --- | --- | --- |
| 安装后可登录 | 认证、Session、CSRF、RBAC 与 Vue 构建测试 | 安装后使用首个管理员登录 HTTPS 页面 |
| 抓取、显示和筛选节点 | CSV 下载边界、解析、入库与节点 API 测试 | 手动刷新 VPNGate 数据并筛选国家/协议 |
| 至少两个独立连接 | `test_acceptance.py` 创建并启动两个模拟出口 | 创建两个真实连接并逐项核对 |
| Namespace、tun、SOCKS 隔离 | 验证不同 Namespace、`Namespace + tun0` 组合及不同端口 | `ip netns list`、Namespace 内 `tun0`、监听端口检查 |
| SOCKS 出口与 VPN 出口一致 | 模拟驱动使用对应节点的出口 IP | 分别通过每个 SOCKS 访问固定出口 IP 服务 |
| 停止一个连接不影响另一个 | 跨模块模拟验收覆盖 | 停止其中一个连接后再次验证另一个 SOCKS |
| VPN 掉线不泄漏主机 IP | Kill Switch 规则和失败回滚测试 | 停止隧道后确认 SOCKS 请求失败且不返回主机 IP |
| IP 分类 | 分类规则、缓存和 API 测试 | 查看实际出口 ASN、类型、置信度和依据 |
| 四类解锁检测 | Netflix、ChatGPT、OpenAI API、YouTube 模拟及解析测试 | 对每条真实连接执行全部检测 |
| 删除后无残留 | 外键级联、Helper purge、卸载残留检查测试 | 删除后检查 Namespace、veth、进程和项目防火墙对象 |
| 重启后代理保持关闭 | `test_startup_recovery.py` | 重启服务，确认连接重新验证前端口不接受连接 |

同一 Namespace 内的 OpenVPN 设备名固定为 `tun0`；隔离标识是 `Namespace + tun0`，因此不同连接不会共享同一个网络栈。

## 真实集成测试安全门

真实测试只能在专用、可丢弃的 Linux 虚拟机上执行，并应具备带外控制台。不要在承载当前 SSH 会话或其他生产流量的主机上进行首次验证。

真实功能需要在 root 所有的 `/etc/vpngate-manager/vpngate.env` 中逐项精确设置为 `true`：

```text
VPNGATE_ENABLE_REAL_NETWORK=true
VPNGATE_ENABLE_REAL_FIREWALL=true
VPNGATE_ENABLE_REAL_OPENVPN=true
VPNGATE_ENABLE_REAL_SOCKS5=true
VPNGATE_ENABLE_REAL_SCANS=true
VPNGATE_ENABLE_REAL_FULL_SCANS=true
VPNGATE_ENABLE_REAL_IP_INTELLIGENCE=true
VPNGATE_ENABLE_REAL_UNLOCK_CHECKS=true
VPNGATE_ENABLE_REAL_CONNECTIONS=true
VPNGATE_ENABLE_REAL_AUTO_SWITCH=true
```

只开启实际需要验证的最小功能集合。例如 Namespace 与 Kill Switch 验收不需要开启外部 IP 情报或自动切换。应用设置和 Root Helper 会分别检查开关，单独设置其中一个不会绕过第二层门禁。

推荐真实验收顺序：

1. 先执行 `sudo bash scripts/diagnose.sh`，确认依赖、权限、迁移、证书和 Helper 均正常。
2. 从控制台验证单个 Namespace 的创建、路由与清理。
3. 分别验证 nftables 和 iptables 项目专用规则，并在每次测试后确认完全移除。
4. 启动一条 OpenVPN，确认 `tun0` 与 Namespace 默认路由后再启动 SOCKS5。
5. 执行出口 IP、Kill Switch 断线和四类解锁检测。
6. 扩展到两个连接，验证隔离、单连接停止、删除和服务重启。
7. 最后运行 `sudo bash scripts/diagnose.sh`，确认不存在异常残留。

所有真实测试凭据只能放在 root 管理的配置或项目规定的 `0600` 文件中，不得出现在命令参数、终端历史、测试报告或问题单中。
