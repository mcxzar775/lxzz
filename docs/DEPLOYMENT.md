# 部署与运维

## 支持范围

生产安装面向使用 systemd 的 Ubuntu/Debian 与 Rocky/AlmaLinux/CentOS Stream 9 系列。应用绑定 `127.0.0.1:8765`，由 Nginx 提供 HTTPS。首次安装生成自签名证书，正式上线前应替换为受信任证书。

默认配置关闭所有真实网络功能。安装、升级、修复和卸载不会静默修改主机默认路由、SSH 配置或 IPv4 forwarding。

## 首次安装

从已验证的发布包中解压后执行：

```bash
sudo bash scripts/install.sh
```

安装器完成操作系统和 systemd 检查、依赖安装、专用系统账户与目录创建、Python 环境和 Vue 构建、密钥与数据库初始化、交互式管理员创建、受限 Helper/sudoers 安装、Nginx/systemd 配置、自检、启动和版本健康检查。

非交互自动化可以临时传入 `VPNGATE_ADMIN_USERNAME` 和 `VPNGATE_ADMIN_PASSWORD`。密码只会进入服务账户可读的一次性 `0600` 文件，CLI 读取后立即删除。自动化日志必须关闭命令回显，并确保环境变量不会被采集。

## 升级与回滚

```bash
sudo bash scripts/upgrade.sh
```

升级器在停止服务前完成新版本构建。随后备份应用、root 配置、受管 SQLite 数据库及安装资产，原子切换应用并执行 Alembic。迁移、自检、服务启动、Nginx 或版本健康检查失败时自动恢复旧应用和数据库。

备份位于 `/var/lib/vpngate-manager/backups/`，目录为 root 私有。使用外部数据库时，运维人员必须先完成数据库原生备份，并显式设置 `VPNGATE_UPGRADE_ALLOW_EXTERNAL_DATABASE=true`。

## 修复、诊断和密码重置

```bash
sudo bash scripts/repair.sh
sudo bash scripts/diagnose.sh
sudo bash scripts/reset-password.sh
```

修复脚本重建损坏的虚拟环境并恢复目录权限、Helper、sudoers、systemd 和 Nginx 资产，但不会重建数据库或擅自迁移未确认的结构。诊断脚本是只读的。密码重置会撤销目标用户的全部 Session，并写入不含密码的审计事件。

## 卸载

```bash
sudo bash scripts/uninstall.sh
```

卸载器在删除 Helper 和应用前，先汇总数据库及运行时中严格匹配项目命名规则的连接 ID，并逐个执行固定清理。无法确认 Namespace、veth、进程或项目防火墙规则已经移除时，卸载立即失败。

默认保留配置、数据库、备份、日志和服务账户。只有明确设置 `VPNGATE_PURGE_DATA=true` 才清除这些状态；此操作不可由脚本恢复。非交互卸载还必须设置 `VPNGATE_UNINSTALL_CONFIRM=YES`。

## 权限基线

- `/etc/vpngate-manager/vpngate.env`：root 所有，`0600` 或 root:`vpngate-manager` 的 `0640`。
- OpenVPN 配置、凭据密钥和私钥：`0600`。
- `/var/lib/vpngate-manager/backups`：root 所有，`0700`。
- `/usr/local/libexec/vpngate-manager-helper`：root 所有，不可由服务账户写入。
- `/etc/sudoers.d/vpngate-manager`：`0440`，只允许固定 Helper，不允许 `NOPASSWD: ALL`。

环境文件只接受不重复的 `VPNGATE_*` 单行赋值。维护脚本不会以 root 身份 source 该文件，而是经过校验后用干净环境交给服务账户。
