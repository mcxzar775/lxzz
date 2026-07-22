# GitHub 托管与一键安装

## 上传源码

解压交付的源码包并进入顶层目录。源码包包含 `.gitignore`，本地数据库、凭据、环境文件、虚拟环境、依赖目录、构建缓存和发布输出不会被加入仓库。

```bash
git init
git add .
git commit -m "Initial VPNGate Manager release"
git branch -M main
git remote add origin https://github.com/OWNER/REPOSITORY.git
git push -u origin main
```

仓库当前没有附带开源许可证。公开仓库前，请由项目所有者选择合适的许可证；不要在不确认授权意图的情况下自动添加许可证。

## 创建版本发布

为提交创建并推送与应用版本一致的标签：

```bash
git tag v0.1.1
git push origin v0.1.1
```

在 GitHub 的 Releases 页面创建 `v0.1.1` 发布，并上传两个文件：

```text
vpngate-manager-0.1.1.tar.gz
vpngate-manager-0.1.1.tar.gz.sha256
```

发布归档和标签必须使用相同版本。不要重新压缩或修改归档，否则 SHA-256 和内置清单将失效。

## 一键安装命令

将下面命令中的 `OWNER/REPOSITORY` 替换为实际 GitHub 仓库：

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/OWNER/REPOSITORY/v0.1.1/scripts/install-from-github.sh | sudo bash -s -- --repo OWNER/REPOSITORY --version 0.1.1
```

引导脚本从对应 GitHub Release 下载源码归档和 SHA-256 文件，再从相同版本标签取得归档校验器。只有外部摘要、内置逐文件清单、路径和成员类型全部通过后，才会调用项目安装器。

该命令不会开启真实 Network Namespace、OpenVPN、防火墙、SOCKS5 或扫描功能。安装完成后，真实功能仍需由管理员在 root 管理的配置中逐项明确开启。
