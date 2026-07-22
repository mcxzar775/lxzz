# 发布流程

## 发布前检查

版本必须同时更新在 `backend/pyproject.toml` 和 `backend/app/__init__.py`，并符合语义版本格式。随后执行：

```bash
make release-check
```

该命令依次运行后端语法检查、mypy、pytest、前端 TypeScript 检查、Shell 语法检查、生产构建、可复现发布打包、静态安全规则、Alembic 升降级往返及发布包校验。若环境中存在 ShellCheck，也会执行 ShellCheck。

发布检查会拒绝任何已开启的真实网络功能变量，不会修改宿主机网络。

## 发布产物

`make release` 生成：

```text
dist/vpngate-manager-<version>.tar.gz
dist/vpngate-manager-<version>.tar.gz.sha256
```

归档使用 `SOURCE_DATE_EPOCH` 统一时间、root 所有权和规范化文件模式。相同源码、版本和时间戳会生成相同字节。归档仅包含安装和验证需要的源码、锁文件、部署资产、测试、文档及已构建前端；明确排除 `.env`、凭据密钥、SQLite 数据库、缓存、虚拟环境、`node_modules` 和工作目录。

归档内的 `RELEASE-MANIFEST.json` 为每个文件记录 SHA-256 与大小，`VERSION` 记录发布版本。校验器拒绝符号链接、特殊文件、路径穿越、重复成员、未列入清单的文件、超限成员及摘要不匹配。

## 独立校验

```bash
bash scripts/verify-release.sh dist/vpngate-manager-<version>.tar.gz
```

发布前还应在全新、可丢弃的受支持 Linux 虚拟机中验证以下命令：

```bash
sudo bash scripts/install.sh
sudo bash scripts/diagnose.sh
sudo bash scripts/uninstall.sh
```

首次真实网络验收必须按照 `docs/ACCEPTANCE.md` 使用显式安全门和带外控制台。发布记录不得包含真实密码、Token、Cookie、API Key、OpenVPN 私钥或完整环境文件。
