# extrojan 方案设计

## 1. 目标

`extrojan` 是一个与 Trojan 双向兼容的新协议类型，解决中间 TCP 载体不稳定时的两个问题：

1. TCP 业务连接在全部载体短暂断开后仍保持原客户端连接和原服务端连接，恢复后字节不丢失、不重复。
2. UDP association 同时使用多条 TCP 载体，单条载体故障不终止 association，并保持服务端上游 UDP socket 不变。

兼容矩阵：

| 客户端 | 服务端 | 行为 |
| --- | --- | --- |
| extrojan | extrojan | TCP 可恢复；UDP 多链路 |
| extrojan | trojan | 自动降级为普通 Trojan，单载体且不可恢复 |
| trojan | extrojan | 按普通 Trojan 处理，单载体且不可恢复 |

兼容只保证旧协议正常工作。任意一端不是 extrojan 时，不提供恢复或多链路能力。

## 2. 约束

- 采用加法式实现，不修改现有 Trojan 线协议和传输实现。
- 新功能集中在新目录和新文件；现有实现文件只增加注册调用、一处仅对 extrojan 标记连接保持包装层 `CloseWrite` 能力的路由修正，以及 WebSocket client 对调用方更短握手截止时间的遵守；`go.mod` 只把既有 yamux 版本归类为直接依赖。
- 不依赖公网，所有关键行为必须能用本机故障注入测试。
- 不持久化会话。任一 extrojan 进程重启后，原 TCP socket 已不存在，不能恢复。
- 不绕过应用自己的超时。载体中断期间应用只是不收到 EOF/RST，但应用设置的读写超时仍可能触发。
- 所有缓冲、会话、association 和载体队列必须有明确上限。

## 3. 总体架构

```text
                              extrojan session
                        ┌────────────────────────┐
App TCP ─ sing-box ─────┤ Yamux + stream framing ├──── sing-box ─ App Server TCP
                        │ reliable ordered stream│
App UDP ─ sing-box ─────┤ UDP associations       ├──── sing-box ─ App Server UDP
                        └────────────┬───────────┘
                                     │ framed packets
                         ┌───────────┼───────────┐
                         │           │           │
                      lane 1      lane 2      lane N
                    Trojan/TCP  Trojan/TCP  Trojan/TCP
```

一个 extrojan session 包含：

- 一条不会因载体 TCP 断开而立即关闭的可靠有序字节流；
- 建立在可靠字节流上的 Yamux，用于承载多个 TCP 业务流；
- 多个 UDP association；
- 1 到 N 条可独立替换的 Trojan/TLS/TCP lane；
- 双向独立的字节 offset、累计 ACK 和未确认数据缓冲。

## 4. TCP 恢复语义

可靠字节流将 Yamux 数据切分为带 offset 的帧：

```text
STREAM_DATA(offset, payload)
STREAM_ACK(next_expected_offset)
```

发送端只有在收到累计 ACK 后才释放对应数据。载体断开时：

1. 不向 Yamux 返回 EOF；
2. 保留未确认数据和两个边缘 TCP socket；
3. 新 lane 使用 session ID 和 resume token 加入原 session；
4. 发送端重新发送未确认数据；
5. 接收端按 offset 去重、重排并继续向 Yamux 提供连续字节。

当所有 lane 不可用超过 `resume_timeout` 时，session 才关闭，业务 TCP 随后收到错误。

如果所有 lane 都已消失，且新的 `EXT_JOIN` 收到明确的永久拒绝（session 不存在、token/用户不匹配、版本不支持或请求无效），客户端立即关闭旧 session，不再等待完整 `resume_timeout`。这覆盖服务端进程重启或 session 已到期的情况：旧 TCP 流确定性失败，新 TCP 流和带稳定包装的 UDP socket 可以建立新 session。网络 I/O 错误、未知状态和 `resource limit` 仍按有限退避重试；后者可能只是服务端尚未清理一条半开 lane。

只要还有一条 lane 存活，任一新 lane 收到永久拒绝都不会终止 session。该拒绝可能来自滚动更新中没有此 session 的另一台后端。完整多 lane 恢复仍要求反向代理按 extrojan session 提供后端亲和性；session 状态不在服务端实例之间共享。

ACK 表示数据已进入有界接收缓冲，而不是目标应用已经读取。接收缓冲满后不推进 ACK，发送端未确认缓冲最终填满并对业务写入施加背压。

Yamux 负责：

- 多 TCP 业务流复用；
- 每个业务流的流量控制。

业务流沿用 sing-mux 的请求/响应格式，但直接使用 Yamux session。Yamux keepalive 被关闭，连接写入和 stream close 的超时预算大于 `link_timeout + resume_timeout + reconnect` 预算，避免可恢复窗口内被底层 mux 提前终止。

每个 Yamux stream 上另加轻量数据帧和应用 `FIN` 帧。应用半关闭不会立刻切换 Yamux stream 状态；双方应用 `FIN` 都到达后才关闭 Yamux stream，从而避免一端仍传输业务数据时发生 Yamux 半关闭竞态。仅当复制源连接带有 extrojan 半关闭标记时，路由才通过包装链查找并调用目标连接的真实 `CloseWrite`；其他协议保持原有行为。接收端若已经缓存超过最终 offset 的乱序数据，会将对应 session 视为协议错误并关闭。

## 5. UDP 多链路语义

UDP 数据报不进入可靠字节流，直接编码为 lane 帧：

```text
UDP_OPEN(association_id, destination)
UDP_OPEN_ACK(association_id, status)
UDP_DATA(association_id, destination, payload)
UDP_CLOSE(association_id)
UDP_CLOSE_ACK(association_id)
```

规则：

- 同一 association 在服务端只创建一个上游 UDP socket；
- 不同 lane 收到的 `UDP_DATA` 汇聚到同一 association；
- 服务端回复可以通过任意健康 lane 返回；
- lane 调度优先选择健康且排队字节最少的连接，并用轮转打破并列；
- lane 写入失败时 UDP 数据报允许丢失，不跨 lane 重放；
- 全部 lane 中断时保留 association，但中断期间的新数据报默认丢弃；
- 恢复后不批量发送陈旧数据报；
- UDP association 的生命周期不依赖某一条 lane。
- `UDP_CLOSE` 在收到 `UDP_CLOSE_ACK` 前周期性重发，接收端幂等关闭并回复 ACK，避免 lane 切换造成 association 泄漏。
- association 进入待关闭状态后保留短期墓碑；同 ID 的迟到或重传 `UDP_OPEN` 只会再次触发 `UDP_CLOSE`，不会创建第二个上游 socket。墓碑数量不超过 `max_udp_associations`，并在覆盖恢复/链路/重拨窗口后到期。
- 可选 `udp_idle_timeout` 按 association 统计双向 UDP 活动；超过该时间没有数据报时，双方按正常 `UDP_CLOSE` 流程回收 association。
- native extrojan UDP 始终使用稳定的应用侧 `PacketConn` 包装；无论 association 因空闲回收还是底层 session 失败而消失，读操作等待，下一次应用写入自动新建 association/session。`udp_idle_timeout: 0` 只禁用空闲计时，不禁用 session 失败后的透明重建。
- 客户端最后一个 UDP association 被回收且没有存活的 TCP 业务流时，关闭整个逻辑 session 和全部 TCP lane。应用侧 `PacketConn` 保持可用并在空闲期等待；同一个应用 UDP socket 的下一次写入会自动新建 association 和 session，不保留已回收的服务端 UDP socket。
- 可选 `lane_rotation_interval` 仅在客户端存在 UDP association、lane pool 已满时生效；每个周期只淘汰一条最旧 lane，由现有重拨逻辑补齐，避免同一时刻轮换全部连接。

UDP 本身不保证可靠或有序。WireGuard 等上层协议应自行处理丢包；TCP-over-WireGuard 的重传仍由内层 TCP 完成。

## 6. Trojan 兼容协商

保留 Trojan 的认证前缀：

```text
SHA224_HEX(password) || CRLF || command
```

新增认证后命令：

| 命令 | 值 | 用途 |
| --- | ---: | --- |
| `EXT_OPEN` | `0xE1` | 创建 extrojan session 和首条 lane |
| `EXT_JOIN` | `0xE2` | 向既有 session 加入或恢复 lane |

旧 Trojan 服务端会拒绝未知命令。extrojan 客户端只发送能力探测，不在收到肯定响应前发送业务数据；初始未知状态需要连续三次收到可判定为旧服务端的响应，才缓存普通 Trojan 模式并用新连接降级。一旦成功确认过 extrojan，后续探测失败只作为链路错误返回，不会静默切换为普通 Trojan。由于旧服务端拒绝和探测阶段的瞬时复位无法完全区分，初始连续三次复位仍可能触发最长一分钟的兼容缓存。

extrojan 服务端读取认证前缀和命令：

- `EXT_OPEN` / `EXT_JOIN` 交给 extrojan session manager；
- 标准 `TCP` / `UDP` / `Mux` 命令将已读取字节放回缓存后交给现有 Trojan service；
- 未认证数据同样交给现有 Trojan service，以保留原 fallback 行为。

## 7. 会话握手

### 7.1 EXT_OPEN

请求：

```text
version:u8
flags:u16
requested_lanes:u16
```

成功响应：

```text
magic:"EXT1"
status:u8
version:u8
session_id:[16]byte
resume_token:[32]byte
lane_id:u32
resume_timeout_ms:u32
accepted_lanes:u16
```

`accepted_lanes` 取客户端请求值与服务端上限的较小值，双方按该值维护 lane pool，避免配置不一致时持续发起无效 `EXT_JOIN`。

### 7.2 EXT_JOIN

请求：

```text
version:u8
session_id:[16]byte
resume_token:[32]byte
```

响应：

```text
magic:"EXT1"
status:u8
version:u8
lane_id:u32
```

`resume_token` 使用密码学安全随机数生成，并同时校验：

- session 是否存在；
- token 是否恒定时间匹配；
- 当前 Trojan 用户是否与 session 所有者一致；
- session 是否尚未过期。

## 8. Lane 帧

每条 lane 在握手后使用：

```text
frame_length:u32
frame_type:u8
frame_payload:[frame_length-1]byte
```

初始帧类型：

| 类型 | 值 | 载荷 |
| --- | ---: | --- |
| `STREAM_DATA` | `0x01` | `offset:u64 + data` |
| `STREAM_ACK` | `0x02` | `next_offset:u64` |
| `STREAM_FIN` | `0x03` | `final_offset:u64` |
| `STREAM_FIN_ACK` | `0x04` | `final_offset:u64` |
| `UDP_OPEN` | `0x10` | `association_id:u64 + destination` |
| `UDP_OPEN_ACK` | `0x11` | `association_id:u64 + status:u8` |
| `UDP_DATA` | `0x12` | `association_id:u64 + destination + data` |
| `UDP_CLOSE` | `0x13` | `association_id:u64` |
| `UDP_CLOSE_ACK` | `0x14` | `association_id:u64` |
| `PING` | `0x20` | `nonce:u64` |
| `PONG` | `0x21` | `nonce:u64` |
| `SESSION_CLOSE` | `0x30` | `code:u16` |

限制：

- TCP 数据分片默认不超过 16 KiB；
- 单帧最大 128 KiB；
- UDP payload 最大 65,535 字节；
- 未知帧类型关闭对应 lane；畸形长度关闭 lane，不能导致大内存分配；
- 会话级错误才关闭 session，单 lane I/O 错误只移除该 lane。

## 9. 状态机

### 9.1 Session

```text
CREATING ── first lane ready ──> ACTIVE
ACTIVE ── all lanes lost ──────> SUSPENDED
SUSPENDED ── valid EXT_JOIN ───> ACTIVE
SUSPENDED ── resume timeout ───> CLOSED
SUSPENDED ── terminal JOIN reject > CLOSED
ACTIVE/SUSPENDED ── local close > CLOSED
```

### 9.2 Lane

```text
DIALING -> AUTHENTICATING -> ACTIVE -> CLOSED
```

客户端维持配置数量的 lane。lane 消失后独立重拨，退避必须有上限和抖动。服务端不主动建立 lane。

### 9.3 UDP association

```text
OPENING -> ACTIVE -> CLOSED
```

重复的 `UDP_OPEN` 必须幂等。恢复 lane 后客户端可以重新发送现有 association 的 `UDP_OPEN`，服务端不能创建第二个上游 socket；已经进入关闭墓碑的 ID 也不能被重新打开。

## 10. 配置草案

```json
{
  "type": "extrojan",
  "tag": "ext-out",
  "server": "server.example",
  "server_port": 443,
  "password": "password",
  "tls": {
    "enabled": true,
    "server_name": "server.example"
  },
  "session": {
    "connections": 4,
    "resume_timeout": "60s",
    "heartbeat_interval": "2s",
    "link_timeout": "10s",
    "retransmit_interval": "1s",
    "max_unacked_bytes": "8MB",
    "max_receive_bytes": "8MB",
    "max_stream_segments": 4096,
    "udp_queue_size": 256,
    "max_udp_queue_bytes": "8MB",
    "max_udp_associations": 1024,
    "udp_idle_timeout": "2m",
    "lane_rotation_interval": "30m"
  },
  "fallback_to_trojan": true
}
```

入站额外支持：

```json
{
  "session": {
    "resume_timeout": "60s",
    "max_sessions": 1024,
    "max_sessions_per_user": 128
  }
}
```

默认值必须在一个新文件中集中定义，入站和出站共享相同的协议限制。

`udp_idle_timeout` 和 `lane_rotation_interval` 默认均为 `0`（禁用），因此完全不配置时不会触发空闲回收或主动 lane 轮换。稳定 UDP 包装不依赖这两个计时选项。`lane_rotation_interval` 是“每次替换一条 lane”的间隔；例如 `connections: 4`、`lane_rotation_interval: 15m` 时，每 15 分钟错峰替换一条连接。只有一条 lane 时轮换会产生一次短暂的全 lane 中断，但仍受 `resume_timeout` 保护；需要无缝轮换时应配置至少两条 lane。

## 11. 资源和安全

- `session_id` 和 `resume_token` 均使用 `crypto/rand`；
- token 使用恒定时间比较；
- session 与认证用户绑定；
- 限制全局 session 数和每用户 session 数；
- 限制每 session 的 lane、UDP association、未确认字节和接收字节；
- 每方向最多保留 4096 个可靠流 segment，并限制乱序窗口；
- UDP 接收队列同时受数据报数量和默认 8 MB 总字节数限制；
- lane 发送队列有界，UDP 队列满时丢包，可靠帧等待后续重试；
- 所有帧长度在分配内存前验证；
- 认证前缀读取受 `link_timeout` 限制，慢速未认证连接不会无限占用 goroutine；
- 关闭路径必须幂等；
- 不在日志中输出密码、Trojan key、resume token 或完整 session ID。

## 12. 最小侵入文件边界

主要新增：

```text
docs/design/extrojan.md
docs/design/extrojan-todo.md
constant/extrojan.go
option/extrojan.go
include/extrojan.go
transport/extrojan/*
protocol/extrojan/*
test/*extrojan*
```

现有文件预期只需：

```text
include/registry.go     # 调用 extrojan 入站/出站注册
route/conn.go           # 仅为带 extrojan 标记的源连接透传底层 CloseWrite
go.mod                  # 将已存在的 yamux 依赖标记为 extrojan 生产代码的直接依赖，不改变版本
transport/v2raywebsocket/client.go
                        # WebSocket upgrade 采用调用方更短的握手截止时间，避免 early-data 黑洞退回全局 TCP 超时
```

不修改：

```text
transport/trojan/*
protocol/trojan/*
option/trojan.go
现有 Trojan 测试
```

## 13. 验收

必须通过：

1. 双向 TCP 持续传输时在任意字节边界切断全部 lane，恢复后哈希一致且使用原业务连接；
2. 中断期间写入和半关闭，恢复后顺序与 FIN 正确；
3. 超过恢复超时后确定性关闭；
4. UDP 数据实际经过至少两条 lane；
5. 单 lane 失败时 UDP association 和其他 lane 不受影响；
6. 服务端同一 UDP association 的上游源端口保持不变；
7. 全部 lane 短断后 association 继续，但不重放陈旧 UDP 包；
8. 三种兼容组合的 TCP 和 UDP 均可工作；
9. 伪造 token、跨用户 token、未知版本和畸形帧被拒绝；
10. 缓冲达到上限时产生背压或丢包，不无限增长；
11. 并发断链、恢复和关闭通过 Go race 检测；
12. 服务端进程重启后旧 session 在明确 `not found` 时快速失败，新 TCP 不等待完整恢复窗口；
13. 同一应用 UDP socket 在服务端重启后能够建立新 session，且客户端重启遗留的服务端 session 按时释放。

## 14. 已知限制与后续优化

已知限制：

- session 只存在于内存中；任一端进程重启都会丢失原 TCP 会话；
- 服务端重启后，客户端只有在新服务端已经可达并明确拒绝旧 session 后才能快速失效；服务端尚不可达时仍保留旧 session 到 `resume_timeout`，以免把普通网络中断误判为进程重启；
- 客户端进程重启后，服务端无法区分“即将恢复”和“永久退出”，因此旧 session 会继续占用一个 session 配额直到 `resume_timeout`；快速重复重启仍受 `max_sessions` 和 `max_sessions_per_user` 的硬上限保护；
- 全部 lane 中断期间的新 UDP 数据报按设计丢弃，恢复后不会补发；
- 不支持在不同 extrojan 服务端实例之间迁移 session；
- 多后端反向代理需要 session affinity。尚有存活 lane 时，来自无状态后端的 `not found` 不会杀死 session；全部 lane 都消失后无法判断哪台后端持有状态，会以快速建立新 session 为优先；
- 客户端确认过 extrojan 后不会因重启或瞬时错误静默降级。如果服务端被有意替换为纯 Trojan，必须重载客户端出站配置后才会重新进行兼容探测；
- 初始能力探测连续三次遭遇不可区分的复位时，可能误进入最长一分钟的普通 Trojan 兼容缓存；
- 当前 wire version 是首次实现，不承诺兼容开发阶段的临时草案。
- 空闲回收会结束原 UDP association；后续数据报使用新 association，因此不保证跨空闲期保持同一个服务端 UDP 源端口。
- lane 轮换期间落在被淘汰 lane 上、尚未写出的 UDP 数据报可能丢失；可靠 TCP 帧仍由 extrojan 重传。

后续可选优化：

- 增加 session、lane、重传、背压和 UDP 丢包指标；
- 让初始探测重试次数与兼容缓存时间可配置；
- 根据实时 RTT、失败率和队列长度改进 lane 调度权重。
