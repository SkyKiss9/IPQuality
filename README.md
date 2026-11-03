# IPQuality · IP 质量测试

[中文](#中文) · [English](#english)

![Ping test](docs/screenshot-ping.png)

---

## 中文

一个 Windows 绿色小工具，用来测试**本机到某个 IP 的网络质量**：延迟、丢包率、抖动。

- **绿色单文件**：只有一个约 90 KB 的 exe，不用安装，双击就开。
- **不留痕迹**：不写注册表、不写配置文件、不常驻后台，关掉窗口进程就退出。
- **能绕过代理软件**：v2rayN、Clash 等开着 TUN 模式时，普通 ping 会被它们接管，测出来的是假结果。这个工具可以指定从实体网卡（Wi‑Fi / 网线）直接发包，测到的才是真实网络质量。

### 功能

| 项目 | 说明 |
|---|---|
| 测试方式 | **ICMP Ping**，或 **TCP 连接**（测指定端口的握手时间，适合禁 ping 的服务器） |
| 目标 | IPv4 地址或域名；直接粘贴 `IP:端口` 会自动切到 TCP |
| 参数 | 次数（0 = 一直测）、间隔、超时、Ping 包大小 |
| 出口网卡 | 自动选中实体网卡；也可以选「不指定（按系统路由）」做对比 |
| 结果 | 平均延迟、丢包率、最小、最大、抖动、已收 / 已发 |
| 图表 | 延迟走势图，丢包用红色竖条标出，鼠标悬停显示每一次的结果 |
| 其他 | 逐次结果列表、一键复制结果；跟随 Windows 深色 / 浅色模式 |

快捷键：回车开始，Esc 停止。

![Packet loss](docs/screenshot-loss.png)

### 下载和运行

到 [Releases](../../releases) 下载 `IPQuality.exe`，双击运行即可。

- 需要 Windows 10 / 11（系统自带 .NET Framework 4.8，不用另外安装）。
- 这个 exe 没有数字签名，第一次打开 Windows 可能会提示「已保护你的电脑」，点「更多信息 → 仍要运行」即可。不放心的话可以按下面的方法自己编译。
- 只支持 IPv4。

### 为什么能绕过代理软件

代理软件开 TUN 模式后，系统的默认路由会指向它的虚拟网卡。这时：

- ICMP Ping 可能直接由代理软件在本机回复（延迟不到 1 ms、TTL=255）；
- TCP 连接会在本机虚拟网卡上完成握手，测到的只是「本机到代理软件」的时间。

本工具把 ICMP 请求的源地址、TCP 套接字都绑定到实体网卡的 IP（TCP 另加 `IP_UNICAST_IF`）。Windows 是强主机模型，这样包只会从这张网卡发出去，不进 TUN。

域名解析也走实体网卡。v2rayN 的 strict_route 会拦截 TUN 以外的 53 端口，所以先用阿里 DNS 的 HTTPS 接口（223.5.5.5 / 223.6.6.6），失败再试普通 DNS。选「不指定」时用系统 DNS；如果解析出 198.18.x.x 这种 fake-ip，会提示结果不可信。

实测（v2rayN TUN 模式开着）：

| 目标 | 按系统路由（经 TUN） | 绑定实体网卡 |
|---|---|---|
| ICMP 1.1.1.1 | 0.3–1.1 ms，TTL=255（代理软件本地代答） | 29 ms，TTL=49 |
| TCP 1.1.1.1:443 | 约 0.9 ms（本地握手） | 超时（本地网络直连不通） |

### 自己编译

不需要安装任何 SDK，用 Windows 自带的 C# 编译器：

```bat
build.cmd
```

生成的 `IPQuality.exe` 在同一个目录里。图标是 `src\make-icon.ps1` 画的，改图标时才需要运行它。

### 文件说明

| 文件 | 内容 |
|---|---|
| `src/IpQuality.cs` | 全部源码（WPF 界面、ICMP / TCP 测试、DNS 解析、图表） |
| `src/app.manifest` | 高 DPI 与权限声明（普通用户权限即可，不需要管理员） |
| `src/app.ico`、`src/make-icon.ps1` | 图标及生成脚本 |
| `build.cmd` | 编译脚本 |

---

## English

A small portable Windows tool that measures **network quality from this PC to an IP**: latency, packet loss and jitter.

- **Portable single file**: one ~90 KB exe. No installer, just double-click.
- **Leaves nothing behind**: no registry writes, no config files, no background process. Closing the window ends the process.
- **Bypasses proxy clients**: when v2rayN, Clash and similar tools run in TUN mode, a normal ping is intercepted and the numbers are fake. This tool can send probes straight out of the physical adapter (Wi‑Fi / Ethernet), so you see the real network.

### Features

| Item | Details |
|---|---|
| Probe type | **ICMP ping**, or **TCP connect** (handshake time to a port; useful when ICMP is blocked) |
| Target | IPv4 address or domain name; pasting `IP:port` switches to TCP automatically |
| Options | Count (0 = run until stopped), interval, timeout, ping payload size |
| Outgoing adapter | Physical adapter selected by default; pick "system routing" to compare |
| Results | Average latency, loss rate, min, max, jitter, received / sent |
| Chart | Latency over time, lost probes marked with red bars, hover for each probe |
| Other | Per-probe log, copy results to clipboard, follows Windows dark / light mode |

Shortcuts: Enter to start, Esc to stop.

The interface is in Chinese.

### Download and run

Download `IPQuality.exe` from [Releases](../../releases) and double-click it.

- Requires Windows 10 / 11 (.NET Framework 4.8 is built in).
- The exe is not code-signed, so SmartScreen may warn on first launch. Choose "More info → Run anyway", or build it yourself (below).
- IPv4 only.

### How the bypass works

In TUN mode the proxy client takes over the default route. Then:

- ICMP pings may be answered locally by the proxy client (under 1 ms, TTL=255);
- TCP handshakes complete on the local virtual adapter, so you only measure "PC to proxy client".

The tool binds the ICMP source address and the TCP socket to the physical adapter's IP (plus `IP_UNICAST_IF` for TCP). Windows uses the strong host model, so the packets leave only through that adapter and never enter the TUN.

Name resolution also goes out through the physical adapter. v2rayN's strict_route blocks port 53 outside the TUN, so the tool first uses AliDNS over HTTPS (223.5.5.5 / 223.6.6.6), then falls back to plain DNS. With "system routing" it uses the system resolver and warns if it gets a 198.18.x.x fake-ip address.

Measured with v2rayN in TUN mode:

| Target | System routing (via TUN) | Bound to physical adapter |
|---|---|---|
| ICMP 1.1.1.1 | 0.3–1.1 ms, TTL=255 (answered locally) | 29 ms, TTL=49 |
| TCP 1.1.1.1:443 | ~0.9 ms (local handshake) | timeout (not reachable directly from this network) |

### Build from source

No SDK needed; it uses the C# compiler that ships with Windows:

```bat
build.cmd
```

`IPQuality.exe` is written next to the script. `src\make-icon.ps1` draws the icon and only needs to run if you change it.

### Files

| File | Contents |
|---|---|
| `src/IpQuality.cs` | All source code (WPF UI, ICMP / TCP probes, DNS, chart) |
| `src/app.manifest` | High-DPI and privilege settings (runs as a normal user, no admin needed) |
| `src/app.ico`, `src/make-icon.ps1` | Icon and the script that draws it |
| `build.cmd` | Build script |
