# TEWA-ONT-Manager

> 天邑 / 电信天翼光猫（TEWA-708G 等同系列）**超管密码获取 + IPv6 放行规则管理 + Telnet 开关 + IPv6 路由修复**的一体化 GUI 工具。

[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](#环境要求)
[![GUI](https://img.shields.io/badge/GUI-tkinter-informational.svg)](#)
[![No deps](https://img.shields.io/badge/dependencies-none-success.svg)](#环境要求)

---

## 简介

本工具面向社区常见的 **天邑（TEWA）博通方案光猫**（如 `TEWA-708G`、`708E`、`707G`、`1006E`、`1100E` 等电信天翼网关），把散落的手工命令整合成一个开箱即用的图形界面，用于**自有设备**的网络调试：

- 免登录开启 Telnet → 由设备 MAC 离线推导 **SU 密码** → 提权到 `root`；
- 读取网页**超级管理员（telecomadmin）密码**；
- 图形化管理光猫 **`ip6tables` 的 IPv6 端口放行规则**（新增 / 删除 / 导出）；
- 一键 **开关 Telnet**（网络层拦截，带防锁死自动恢复）；
- 一键 **修复 IPv6 委派路由**（解决前缀变更后全屋 IPv6 双向不通的固件老毛病）。

整个程序**只依赖 Python 3 标准库**（含 tkinter），单文件即可运行，无需安装任何第三方包。

---

## ✨ 功能特性

| 标签页 | 功能 |
| --- | --- |
| **① 超管密码** | 一键 `开启Telnet → 读取设备MAC → 离线算SU → 提权 → telecomadmin get`，自动复制密码到剪贴板，并列出 3 个 SU 候选。 |
| **② 放行规则** | 查看光猫 `ip6tables` 的 `INPUT` / `FORWARD` 规则；按「链 × 协议 × 端口 × 地址范围」批量添加放行；选中即删；支持导出为 `.sh` 脚本。 |
| **③ Telnet 开关** | 一键开 / 关 Telnet。关闭采用 `iptables` 只拦截**新**连接（不影响当前会话），并可设置 N 秒后**自动恢复**，避免把自己锁在外面。 |
| **④ IPv6 路由修复** | 自动识别光猫 `br0` 上未指向二级路由的委派前缀，补一条下一跳路由，修复「前缀变更后全屋 IPv6 出站/入站同时失效」。 |

- 支持多网段掩码/前缀范围的放行（如 `-d 2001:db8:1:2::/64`）。
- 自动探测二级路由下一跳（邻居表 / EUI-64 反推，多级兜底）。
- 全部网络操作在后台线程执行，界面不卡死。

## 🖼 界面

```
┌─ TEWA-708G 光猫 · 超管密码 / 放行规则管理 ─────────────────┐
│ 连接参数：光猫 IP  [192.168.1.1]  端口[23]  用户[telnetadmin]       │
│ ① 超管密码   ② 放行规则   ③ Telnet 开关   ④ IPv6 路由修复         │
│ ...                                                                 │
└────────────────────────────────────────────────────────────────────┘
```

> 截图占位：欢迎 PR 补充 `docs/screenshot.png`。

## 🔧 环境要求

- **Windows**（本工具用 PowerShell / `ipconfig` 做本机 IPv6 探测，WebUI 交互界面基于 tkinter）。
- **Python 3.8+**，且包含 `tkinter`（官方安装包默认自带，无需额外安装）。
- 电脑与光猫处于同一局域网（默认光猫地址 `192.168.1.1`）。

## 🚀 快速开始

```bash
# 1) 克隆
git clone https://github.com/mqx2333/tewa-ont-manager.git
cd tewa-ont-manager

# 2) 运行（二选一）
python ont_manager.py
# 或双击
run.bat
```

### 使用步骤

1. **连接参数**：确认「光猫 IP / Telnet 端口 / 用户 / 密码」正确（默认 `192.168.1.1` / `23` / `telnetadmin` / `telnetadmin`）。
2. **① 超管密码**：点「⚡ 一键获取超管密码」。工具会自动开 Telnet、读 MAC、算 SU、提权并取回密码。
3. **② 放行规则**：点「连接并提权」→「刷新规则」，在「添加放行」里填端口（支持逗号分隔多个）后点「添加放行」；选中规则可「删除」或「导出为 .sh」。
4. **③ Telnet 开关 / ④ IPv6 路由修复**：按需一键操作。

## 🧠 工作原理（简述）

- **SU 密码**：光猫把 `root` 密码存成 `/etc/passwd` 的 MD5-crypt 哈希，而该密码由**设备 MAC 经固定置换/位运算算法**派生（每台不同、可离线算出）。本工具内置该算法，产生 3 个候选逐一尝试 `su`。
- **Telnet 开启**：`http://<网关>:8080/entelnet.cgi` 是一个**免登录**的开启接口。
- **放行规则**：本质是对光猫 `ip6tables` 的 `INPUT` / `FORWARD` 链插入 `ACCEPT` 规则（`-I <chain> 1 ... -j ACCEPT`），让入站 IPv6 流量命中规则而不落入末尾的 `DROP`。
- **IPv6 路由修复**：部分固件在**运营商重新下发前缀**后，会把委派前缀装成 `on-link`（无下一跳），导致光猫直接向局域网做邻居发现（NDP）而主机其实在二级路由后面 → 双向不通。本工具为前缀补一条 `via <二级路由> dev br0` 的路由。

> ⚠️ 以上放行规则与路由均为**运行时**改动，**光猫重启后失效**，需要重新执行。

## ⚠️ 免责声明

- 本项目仅供**自有设备**的网络运维与学习研究，**请勿用于任何未授权设备或非法用途**。
- 关闭防火墙 / 放行入站端口会让内网服务**暴露在公网**，请自行评估风险并配置好各终端的主机防火墙。
- 修改运营商设备可能触发其远程管理（TR-069）回滚，或导致设备离线。**使用前请务必备份 / 记录 LOID、宽带账号等关键信息，后果自负。**
- 作者不对因使用本工具造成的任何直接或间接损失负责。

## 📄 许可证

本项目以 **GNU General Public License v3.0 (GPL-3.0)** 开源，全文见 [LICENSE](LICENSE)。

```
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```

## 🙏 致谢

- SU 密码算法源自社区（chinesesuper 等）对天邑固件的逆向成果，本项目仅做工程化整合。
- 感谢所有为家庭光猫互操作、IPv6 放行方案做出贡献的网友。

## 👥 贡献者 / Contributors

| 贡献者 | 角色 | 链接 |
| --- | --- | --- |
| **mqx2333** | 项目作者 / 维护者 | https://github.com/mqx2333 |
| **DeepSeek** | AI 模型（代码生成 / 调试协助） | https://www.deepseek.com |
| **OpenCode** | AI 编程 Agent（CLI，驱动本项目开发） | https://opencode.ai |

> 本项目由作者与上述 AI 工具协作完成。欢迎通过 Issue / PR 参与贡献，也欢迎把你的名字加进 [`CONTRIBUTORS.md`](CONTRIBUTORS.md)。

---

<details>
<summary><b>English</b></summary>

**TEWA-ONT-Manager** is an all-in-one GUI toolkit for **TEWA / China Telecom fiber ONTs** (e.g. TEWA-708G and siblings):

- One-click recovery of the router **super-admin password** (opens Telnet, reads the device MAC, derives the `SU` password offline, escalates to `root`).
- GUI management of the ONT's **`ip6tables` IPv6 allow rules** (add / delete / export).
- One-click **Telnet on/off** with a lockout-safe auto-recovery timer.
- One-click **fix for broken IPv6 delegated-prefix routing** after the ISP changes the prefix.

Windows + Python 3 stdlib only (tkinter). No third-party dependencies.

> For your **own** devices only. Use at your own risk.

Licensed under **GPL-3.0**.

Contributors: [mqx2333](https://github.com/mqx2333) · **DeepSeek** (AI model) · **OpenCode** (AI coding agent). See [CONTRIBUTORS.md](CONTRIBUTORS.md).

</details>
