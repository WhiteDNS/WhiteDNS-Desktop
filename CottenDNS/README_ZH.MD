<p align="center">
  <img src="assets/cottendns.png" alt="CottenDNS 标志" width="150">
</p>

<h1 align="center">CottenDNS</h1>

<p align="center">
  <strong>面向审查、高丢包和不稳定网络的速度优先 DNS 隧道。</strong>
</p>

<p align="center">
  <a href="LICENSE"><img alt="MIT 许可证" src="https://img.shields.io/badge/license-MIT-16a34a?style=flat-square"></a>
  <a href="https://github.com/TaJirax/cottenDNS/actions/workflows/build-go.yml"><img alt="构建状态" src="https://github.com/TaJirax/cottenDNS/actions/workflows/build-go.yml/badge.svg"></a>
  <a href="https://github.com/TaJirax/cottenDNS/releases/latest"><img alt="最新版本" src="https://img.shields.io/github/v/release/TaJirax/cottenDNS?style=flat-square"></a>
</p>

<p align="center">
  <a href="README.MD">English</a> ·
  <a href="README_FA.MD">فارسی</a> ·
  <a href="README_RU.MD">Русский</a> ·
  <a href="README_ZH.MD">简体中文</a> ·
  <a href="README_ES.MD">Español</a>
</p>

<p align="center">
  <a href="https://github.com/TaJirax/cottenDNS/releases/latest">下载</a> ·
  <a href="docs/ENGINEERING_CHANGES.md">工程记录</a> ·
  <a href="CONFIG_PRESETS.md">配置预设</a> ·
  <a href="https://t.me/whitedns">Telegram</a>
</p>

> [!IMPORTANT]
> CottenDNS 用于普通 VPN 和代理被封锁、但仍存在可用 DNS 路径的网络。DNS 隧道天然比普通 VPN 慢。本项目追求的是审查环境下的最大可用速度和持续连接，而不是脱离实际的带宽宣传。

## 从这里开始

| 目标 | 章节 |
| --- | --- |
| 部署新的隧道 | [完整部署指南](#完整部署指南) |
| 了解自动传输选择 | [自动智能模式](#自动智能模式) |
| 选择配置预设 | [配置预设](#配置预设) |
| 查看服务器状态 | [监控](#监控) |
| 嵌入 Android 引擎 | [Android 与引擎子模块](#android-与引擎子模块) |

## 项目来源与致谢

CottenDNS 建立在两个项目的工作之上：

1. **[MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN)**，作者 **Amin Mahmoudi**：提供了低开销 DNS 隧道、自定义 ARQ、解析器负载均衡、会话复用和恶劣网络设计基础。
2. **[StormDNS](https://github.com/nullroute1970/StormDNS)**，维护者 **NullRoute1970**：CottenDNS 的直接上游来源。
3. **CottenDNS** 由 **tajirax** 维护，在此基础上扩展，并保留 MasterDNS/StormDNS 客户端兼容性。

CottenDNS 是独立的衍生项目，并不声称原始架构由本项目首创。项目延续 MIT 许可证，详见 [LICENSE](LICENSE)。

## 工作方式

```text
应用程序
   │
   ▼
本地 SOCKS5 / TCP
   │
   ▼
CottenDNS 客户端
   ├── UDP/53 ─────┐
   ├── TCP/53 ─────┤
   ├── DoT ────────┤──► DNS 解析器 ──► CottenDNS 服务端 ──► 互联网
   └── DoH ────────┘
```

客户端把数据流拆成适合 DNS 的小帧，进行加密和可选压缩，选择解析器与传输路径，并通过 ARQ 和可选 Reed–Solomon FEC 修复丢包。服务端重组数据流，并直接连接目标、通过上游 SOCKS5，或连接固定 TCP 目标。

内置 SOCKS5 支持 TCP 和通用 UDP association；本地 DNS 监听器与缓存为可选功能。

## 核心优势

| 网络问题 | CottenDNS 的处理方式 |
| --- | --- |
| UDP 很快但可能被污染或限速 | 保留可用 UDP，只切换受影响的解析器 |
| 每个解析器路径不同 | 独立评估每个 `(解析器, 传输)` |
| 上行和下行质量不同 | 分别记录送达率、失败、RTT 和置信度 |
| DNS MTU 很小 | 每条路径单独探测 MTU，按数据包大小路由 |
| 丢包严重 | ARQ、ACK/NACK、即时重放、自适应复制、FEC/Super-FEC |
| 伪造响应异常快速 | 把它视为预警，并竞争一个经过验证的备用路径 |
| 路径失效时仍有在途帧 | 不重建会话，立即在其他路径重放 |
| 可靠性机制挤占带宽 | FEC、复制、重放和探测共享统一预算 |
| 多条路径质量接近 | 单副本批量流量在成熟路径间条带化 |
| DPI 识别重复 DNS 形态 | 轮换记录类型、调整 QNAME、随机 ID/cookie、可选 DoT/DoH |

## 自动智能模式

推荐默认值：

```toml
CONFIG_PRESET = "speed"
RESOLVER_TRANSPORT = "auto"
PATH_CONTROLLER_MODE = "unified"
COMPARABLE_PATH_STRIPING = true
```

客户端会自动：

- 优先尝试 UDP，并在其仍有价值时继续使用；
- 对每个解析器分别比较 UDP 和 TCP/53；
- 只切换失败或明显更慢的路径；
- 按数据包大小、MTU、RTT、丢包、方向和置信度选择路径；
- 用低开销后台预算保持备用路径温热；
- 避免 FEC、探测和不必要复制叠加；
- 在检测到 DNS poisoning 时竞争备用路径；
- 在完整 ARQ 超时之前重放在途帧。

`auto` 不会暗中启用 DoT/DoH。它们由用户明确选择：

```toml
RESOLVER_TRANSPORT = "dot" # 或 "doh"
```

也可以按解析器覆盖：

```toml
RESOLVER_TRANSPORT_PATHS = { "1.1.1.1" = "doh", "8.8.8.8" = "auto", "9.9.9.9" = "tcp" }
```

## 动态服务端

UDP、TCP/53、DoT 和 DoH 共用同一个原生会话引擎。启用：

```toml
ENCRYPTION_AUTO_DETECT = true
```

后，服务端会自动接受客户端选择的有密钥方法 1–5。AES-128/192/256-GCM 总是在旧式非认证解码器之前检查。XOR 和 ChaCha20 还必须符合活动会话或严格的 MTU 请求语义。明文方法 `0` 只有在服务端明确配置为明文时才会启用。

不同客户端可以使用不同的受支持加密、传输、MTU、压缩和可靠性参数，而无需重新配置服务端。服务端仍会执行自己的安全上限。

## 完整部署指南

常规部署路径：

```text
[客户端设备] → [递归 DNS 解析器] → [VPS 上的委派子域] → [互联网]
```

### 开始之前

你需要：可修改 DNS 记录的域名、拥有公网 IPv4 和 `sudo` 权限的 Linux VPS、已放行的 UDP/53 与 TCP/53，以及 Windows、Linux 或 macOS 客户端。VPS 系统防火墙和云厂商安全组都必须允许 53 端口。

> [!CAUTION]
> `systemd-resolved`、BIND、dnsmasq 或服务器面板可能已经占用 53 端口。安装前运行 `sudo ss -lntup | grep ':53 '`。同时保留 SSH 管理端口，避免因防火墙修改而失联。

### 第 1 步 — 委派一个短 DNS 子域

在 `example.com` 的 DNS 提供商处创建：

```dns-zone
ns.example.com.  300  IN  A   203.0.113.10
v.example.com.   300  IN  NS  ns.example.com.
```

将 IP 替换为 VPS 公网地址。不要为这两条记录启用 CDN 代理。较短的隧道域名可为每个 DNS 数据包保留更多有效载荷。

等待记录生效后检查：

```bash
dig +short A ns.example.com
dig +short NS v.example.com
```

应分别返回服务器 IP 和 `ns.example.com.`。如果没有 NS 结果，请先修复委派，客户端调优无法弥补错误的 DNS 记录。

### 第 2 步 — 安装服务端

```bash
sudo install -d -m 0755 /opt/cottendns
cd /opt/cottendns
curl -fsSL https://raw.githubusercontent.com/TaJirax/cottenDNS/main/server_linux_install.sh | sudo bash
```

安装器询问域名时输入 `v.example.com`。它会下载 release、创建配置和密钥、设置 systemd、在支持的本机防火墙中开放 UDP/TCP 53，并检查 `/healthz`。

重要文件：

```text
/opt/cottendns/server_config.toml
/opt/cottendns/encrypt_key.txt
```

通过安全渠道把密钥复制到客户端：

```bash
sudo cat /opt/cottendns/encrypt_key.txt
```

不要把密钥放进截图、Issue、公共配置或解析器列表。

### 第 3 步 — 验证服务端

```bash
systemctl is-active cottendns
curl -fsS http://127.0.0.1:9090/healthz
sudo ss -lnup | grep ':53 '
sudo ss -lntp | grep ':53 '
```

如果失败：

```bash
journalctl -u cottendns -n 100 --no-pager
```

监控端口 `9090` 默认仅供本机使用，不应直接暴露到公网。

### 第 4 步 — 配置客户端

从 [Releases](https://github.com/TaJirax/cottenDNS/releases/latest) 下载与系统和 CPU 架构匹配的客户端。将可执行文件、`client_config.toml` 和 `client_resolvers.txt` 保持在同一目录。

先使用最小安全配置：

```toml
DOMAINS = ["v.example.com"]
ENCRYPTION_KEY = "服务端密钥"
DATA_ENCRYPTION_METHOD = 3

PROTOCOL_TYPE = "SOCKS5"
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 18000

CONFIG_PRESET = "speed"
STARTUP_MODE = "resolvers"
RESOLVER_TRANSPORT = "auto"
PATH_CONTROLLER_MODE = "unified"
COMPARABLE_PATH_STRIPING = true
```

`client_resolvers.txt`：

```text
1.1.1.1
8.8.8.8
9.9.9.9
```

先使用少量、来源不同的解析器。大量低质量地址只会延长扫描时间。

### 第 5 步 — 首次扫描和启动

Linux：

```bash
chmod +x ./CottenDns_Client_*
./CottenDns_Client_Linux_AMD64_vVERSION --config ./client_config.toml
```

Windows PowerShell：

```powershell
.\CottenDns_Client_Windows_AMD64_vVERSION.exe --config .\client_config.toml
```

客户端会测量每个解析器的隧道可达性、MTU、延迟、丢包以及 UDP/TCP 路径。只扫描而不启动代理时可添加 `--scan-only`。

每次启动都应保持 `STARTUP_MODE = "resolvers"`。解析器可达性、污染状态、
传输质量和 MTU 可能在重启后发生变化，因此不能信任旧缓存。
`FAST_CONNECT = true` 会在得到一个小型已验证解析器池后先建立连接，
其余解析器继续在后台进行全新验证。

### 第 6 步 — 测试 SOCKS5

在应用中设置 `SOCKS5 127.0.0.1:18000`，或运行：

```bash
curl --proxy socks5h://127.0.0.1:18000 https://example.com/
```

`socks5h` 会让域名解析也通过代理完成。

### 安全升级

```bash
cd /opt/cottendns
curl -fsSL https://raw.githubusercontent.com/TaJirax/cottenDNS/main/server_linux_install.sh | sudo bash -s -- --upgrade
```

服务端升级会保留配置和密钥；如果新服务未通过健康检查，会自动回滚。升级桌面客户端时，请先解压到新目录并复制配置，完成扫描和 SOCKS 测试后再删除旧版本。

## 配置预设

| 预设 | 适用场景 |
| --- | --- |
| `speed` | 默认选择，优先最大有效吞吐 |
| `survival` | 高丢包、不稳定解析器或强审查 |
| `tcp-survival` | UDP/53 基本不可用，但 TCP/53 可用 |
| `iran`, `china`, `russia`, `venezuela`, `cuba` | 常见地区限制的客户端起点 |
| `low-bandwidth` | 上行极弱或 DNS 查询预算很小 |

预设只是起点，不是自动国家识别。ISP、城市、时间和审查事件都会改变实际情况。详见 [CONFIG_PRESETS.md](CONFIG_PRESETS.md)。

## 监控

```bash
curl -s http://127.0.0.1:9090/healthz
curl -s 'http://127.0.0.1:9090/healthz?details=1' | jq
curl -s http://127.0.0.1:9090/metrics
```

查看进程资源：

```bash
pid=$(systemctl show -p MainPID --value cottendns)
ps -p "$pid" -o pid,%cpu,%mem,rss,vsz,etime,cmd
top -p "$pid"
```

## Android 与引擎子模块

Android 应用可以把本仓库作为 Git submodule 或 CI 依赖。已验证的引擎提交：

```text
8eea49d1267b1a41441c25c75e69e6f12ad0a11f
```

引擎已在禁用 CGO 的情况下通过 Android arm64、armv7、amd64 和 386 编译。Android 外壳应保留推荐 TOML 默认值。

## 兼容性与安全

- 新客户端 + 新服务端：完整功能。
- 旧客户端 + 新服务端：支持，包括 MasterDNS/StormDNS。
- 新客户端 + 旧服务端：客户端路由改进可用，但缺少新服务端功能。
- 认证加密请使用 AES-GCM 方法 `3`、`4` 或 `5`。
- DoT/DoH 只保护客户端到解析器这一段。
- 流量大小和时间特征仍可能暴露隧道行为。
- 不要公开 `encrypt_key.txt`。
- 仅在获得授权的环境中使用。

## 文档与开发

| 文档 | 内容 |
| --- | --- |
| [CONFIG_PRESETS.md](CONFIG_PRESETS.md) | 速度、生存和地区预设 |
| [ENGINEERING_CHANGES.md](docs/ENGINEERING_CHANGES.md) | 架构、修复和测试 |
| [client_config.toml.simple](client_config.toml.simple) | 完整客户端配置 |
| [server_config.toml.simple](server_config.toml.simple) | 完整服务端配置 |

```bash
go build ./cmd/client
go build ./cmd/server
go test ./...
go vet ./...
```

## 许可证与致谢

CottenDNS 由 **tajirax** 维护，并按 [MIT License](LICENSE) 发布。

- **Amin Mahmoudi** — [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN)，原始架构和项目基础。
- **NullRoute1970** — [StormDNS](https://github.com/nullroute1970/StormDNS)，直接上游来源。
- 感谢所有贡献者、测试者以及提供审查网络反馈的用户。
