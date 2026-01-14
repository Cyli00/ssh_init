# SSH Init

一键 SSH 加固脚本，支持 Debian 和 Ubuntu 系统。

## 功能

- 修改 SSH 端口
- 创建/配置登录用户
- 配置公钥认证（禁用密码登录）
- 配置 Root 登录策略
- 自动配置 sudo 免密码
- 自动配置 UFW 防火墙（如已启用）

## 支持系统

- Debian 10/11/12
- Ubuntu 20.04/22.04/24.04
- 其他基于 Debian/Ubuntu 的发行版

## 使用方法

```bash
# 下载脚本
curl -O https://raw.githubusercontent.com/Cyli00/ssh_init/refs/heads/main/linux_ssh_init.sh

# 运行
sudo bash linux_ssh_init.sh
```

## 交互流程

```
══════════════════════════════════════════════════
   SSH Hardening (Interactive)
══════════════════════════════════════════════════

→ Detected: Debian GNU/Linux 12 (bookworm)

[1/5] SSH Port
→ New SSH port [10022]:

[2/5] Login User
→ Login user [root]:

[3/5] Root Login Policy
→ Root login policy:
   1) Allow root with key only (prohibit-password)
   2) Disable root login completely (no)
→ Select [1]:

[4/5] Public Key
→ Paste your SSH public key (ssh-ed25519/ssh-rsa/ecdsa):

[5/5] Apply Configuration
...

──────────────────────────────────────────────────
✔ SSH hardening completed successfully

Test in a NEW terminal:
  ssh -p 10022 root@<SERVER_IP>

⚠ Do NOT close this session until confirmed.
──────────────────────────────────────────────────
```

## 注意事项

- 必须以 root 权限运行
- 配置完成后，请在**新终端**测试连接，确认无误后再关闭当前会话
- 如使用云服务器，需在安全组中放行新的 SSH 端口

## License

MIT
