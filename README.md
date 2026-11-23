# SSH Init

一键 SSH 加固脚本，支持 Debian 和 Ubuntu 系统。

## 功能

- 修改 SSH 端口
- 创建/配置登录用户
- 配置公钥认证（禁用密码登录）
- 配置 Root 登录策略
- 可选择配置 sudo 免密码（默认不启用）
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

## 安全保护

- 公钥必须能通过 `ssh-keygen` 校验；无效密钥不能强行跳过
- 在写入 SSH 配置之前会检测原始配置和 socket activation；变更后检查 `sshd -t` 和 `sshd -T` 的有效参数
- 若 SSH 检查或服务重启失败，自动恢复此前的本脚本管理的配置文件（不会删除新建用户或已安装的密钥）
- 非 root 用户的 `NOPASSWD:ALL` 需要明确确认；若禁用 root SSH，目标用户必须具备可用的 sudo 提权方式
- 遇到 `.ssh` 或 `authorized_keys` 符号链接会拒绝执行，避免写入意外位置

## 限制与操作前检查

- **自动回滚只覆盖本脚本写入的 sshd drop-in**，不能自动恢复防火墙规则、账户或云平台安全组
- 各系统的 SSH 配置可能由更早加载的配置文件覆盖；这种情况会中止，请先手动检查现有设置
- 若采用 `ssh.socket` 且要更换端口，请先切换到 `ssh.service` 并确认服务正常运行；脚本不会自动修改 socket 的监听端口
- 若拒绝免密 sudo，必须给新用户设置密码才能使用常规 sudo；特别是在禁用 root 登录前
- 请预先在云安全组放行目标 TCP 端口，并保持现有 SSH 会话连接
- `bash tests/test_hardening.sh` 可运行不需要 root 权限的回归检查；它不能代替真实 Debian/Ubuntu 主机上的端到端验证

## 注意事项

- 必须以 root 权限运行
- 配置完成后，请在**新终端**测试连接，确认无误后再关闭当前会话
- 如使用云服务器，需在安全组中放行新的 SSH 端口

## License

MIT
