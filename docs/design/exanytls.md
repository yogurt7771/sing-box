# ExAnyTLS：保留 AnyTLS 全部能力的可恢复 session

## 结论

`exanytls` 保留标准 AnyTLS 的配置面和运行语义，只替换池中每个 AnyTLS session
所使用的底层连接：普通 TLS/WSS carrier 变为 Extrojan 的可恢复可靠字节流。

```text
应用 TCP / UDP (UoT)
  -> AnyTLS 原有代理与地址封装
  -> AnyTLS session pool
       -> AnyTLS session A -> Extrojan logical session A -> 1..N 个可替换 carrier
       -> AnyTLS session B -> Extrojan logical session B -> 1..N 个可替换 carrier
       -> AnyTLS session C -> Extrojan logical session C -> 1..N 个可替换 carrier
```

因此，协议能力没有缩减为“单 session”或“仅 TCP”：TCP、UDP-over-TCP、padding、
`client_metadata`、session 池、空闲清理、兼容回退和原有路由元数据都继续存在。
变化只发生在 session 的承载与恢复层。

## AnyTLS session 池语义

ExAnyTLS 沿用上游 `sing-anytls` 的池行为：

1. 新应用 stream 优先租用一个空闲 AnyTLS session。
2. 没有空闲 session 时创建新的 AnyTLS session。
3. 应用 stream 关闭后，其 AnyTLS session 回到空闲池。
4. `idle_session_check_interval` 控制清理周期。
5. `idle_session_timeout` 控制空闲 session 的过期时间。
6. `min_idle_session` 是清理时至少保留多少个**已经创建**的空闲 session；它不会
   预建 session，也不是总 session 数量上限。

`session.connections` 是另一个维度：它控制**每个** Extrojan logical session 的
并行 carrier/lane 数，默认是 `1`。例如同时有 3 个活动 AnyTLS session 且
`session.connections: 2` 时，最多可能使用 6 条活动 carrier。这个乘法关系是恢复
能力与连接占用之间的直接权衡，不应把 `session.connections` 误解为 AnyTLS 池大小。

## 完整配置继承

ExAnyTLS inbound 直接继承 `AnyTLSInboundOptions`：

- listen、用户、TLS；
- `padding_scheme`；
- AnyTLS 的入站路由、用户元数据与 UDP-over-TCP 解封装。

ExAnyTLS outbound 直接继承 `AnyTLSOutboundOptions`：

- dialer、server、TLS、password；
- `idle_session_check_interval`；
- `idle_session_timeout`；
- `min_idle_session`；
- `client_metadata`；
- TCP 与 UDP-over-TCP。

ExAnyTLS 只额外增加：

- `session`：每个 AnyTLS session 下方的恢复参数与 carrier 数；
- `transport`：可选 V2Ray transport，例如 WebSocket；
- `fallback_to_anytls`：旧服务端兼容回退，默认开启。

与标准 sing-box AnyTLS 一致，内置 outbound 要求启用 TLS；inbound 仍保留 AnyTLS
原有的可选 TLS 行为。

## Wire 与兼容模式

同一个 ExAnyTLS inbound 可以识别两种认证头：

1. 标准 `SHA-256(password)`：进入原生 AnyTLS service；
2. ExAnyTLS `OPEN` / `JOIN`：进入可恢复 logical session，再在可靠字节流上运行
   AnyTLS v2 session frame。

兼容关系如下：

| 客户端 | 服务端 | 行为 |
| --- | --- | --- |
| ExAnyTLS | ExAnyTLS | 完整 AnyTLS 语义，并支持每个 session 的 carrier 恢复 |
| AnyTLS | ExAnyTLS | 标准 AnyTLS 模式 |
| ExAnyTLS | AnyTLS | 探测后回退到标准 AnyTLS 模式 |
| AnyTLS | AnyTLS | 标准 AnyTLS |

客户端只在首次建池 session 时进行能力探测。确定服务端模式后，后续池 session
直接使用该模式。回退模式仍保留 AnyTLS session 池和 UDP-over-TCP，但普通 AnyTLS
carrier 本身不具备跨 socket 恢复能力。

TLS 和可选 transport 的顺序是：

```text
TCP -> TLS -> 可选 WebSocket -> ExAnyTLS/AnyTLS -> AnyTLS session
```

两端必须使用一致的外层 transport。裸 TLS 客户端不能直接连接要求 WebSocket
Upgrade 的监听。

## 掉线恢复边界

每个池 session 都拥有独立的 Extrojan logical session。其全部 carrier 发生 RST、
EOF 或静默失活后，客户端使用 session ID、resume token 和累计 ACK 建立新 carrier，
只重放未确认字节；上层 AnyTLS session、活动 stream 和目标 TCP/UDP association
不会因此重建。

本地 AnyTLS v2 session 实现保持原 wire 格式，并把 control write 与 SYNACK
watchdog 放宽到 `link_timeout + resume_timeout` 的恢复预算，避免恢复窗口内把
session 误判为失败。大于 65535 字节的单次写入会拆成多个合法 AnyTLS frame。

恢复需要满足：

- 中断不超过 `resume_timeout`；
- 至少在恢复窗口内能够重新连到保存该 logical session 的服务端实例；
- 两端进程未重启，认证和 resume token 仍有效；
- 未确认数据没有持续耗尽配置的有界重放窗口。

已经保留在空闲池中的 session 也可恢复。若掉线期间有新应用连接且池中存在空闲
session，它可以租用该 session 并等待 carrier 恢复；若必须从零创建 logical
session，则仍需要当时能够完成首次 `OPEN`，不会把一次全新的连接伪装成恢复。

## 配置示例

客户端完整示例：

```json
{
  "type": "exanytls",
  "tag": "exanytls-out",
  "server": "relay.example.org",
  "server_port": 443,
  "password": "CHANGE_ME",
  "idle_session_check_interval": "30s",
  "idle_session_timeout": "30s",
  "min_idle_session": 5,
  "client_metadata": "",
  "fallback_to_anytls": true,
  "tls": {
    "enabled": true,
    "server_name": "proxy.example.org"
  },
  "transport": {
    "type": "ws",
    "path": "/proxy",
    "headers": {
      "Host": "proxy.example.org"
    }
  },
  "session": {
    "connections": 1,
    "resume_timeout": "60s",
    "heartbeat_interval": "2s",
    "link_timeout": "10s",
    "retransmit_interval": "1s",
    "reconnect_initial_delay": "200ms",
    "reconnect_max_delay": "3s"
  }
}
```

服务端示例：

```json
{
  "type": "exanytls",
  "tag": "exanytls-in",
  "listen": "0.0.0.0",
  "listen_port": 443,
  "users": [
    { "name": "client", "password": "CHANGE_ME" }
  ],
  "padding_scheme": [],
  "tls": {
    "enabled": true,
    "server_name": "proxy.example.org",
    "certificate_path": "/path/to/fullchain.pem",
    "key_path": "/path/to/private.key"
  },
  "transport": {
    "type": "ws",
    "path": "/proxy"
  },
  "session": {
    "connections": 1,
    "resume_timeout": "60s",
    "heartbeat_interval": "2s",
    "link_timeout": "10s"
  }
}
```

## 验收覆盖

自动化测试覆盖以下关键路径：

1. ExAnyTLS JSON 可读取全部 AnyTLS outbound 字段，包括 `min_idle_session`；
2. 两个并发应用 stream 创建两个池 session，关闭后可复用；
3. 空闲清理会过期多余 session，并按 `min_idle_session` 保留指定数量；
4. 多个独立 AnyTLS session 在多次全 carrier 中断后继续传输，目标 TCP 不重建；
5. 掉线期间可从空闲池租用 session，恢复后建立新的应用 stream；
6. UDP-over-TCP association 在 carrier 替换后继续收发；
7. 两个 AnyTLS 兼容方向以及 WSS 外层 transport。

Windows PowerShell 下执行长流式恢复验收：

```powershell
Set-Location D:\Codes\Proxy\sing-box\test
$env:EXANYTLS_LONG_TEST = '1'
go test -mod=mod . -run '^TestExAnyTLSPreservesSessionPoolAcrossCarrierRecovery$' -count=1 -v
Remove-Item Env:EXANYTLS_LONG_TEST
```

1 GiB 确定性输入的预期长度是 `1073741824` 字节，预期 SHA-256 是
`01c0060fcb8c4d8b5d62176d1e0c7be73311fc62713b76d06cb611ed214a6812`。
