# extrojan TODO

本清单是实现顺序和完成定义。只有对应自动化验证通过后才能勾选。

## A. 仓库边界

- [x] 新增独立配置类型和协议常量。
- [x] 新增独立注册文件。
- [x] 现有注册入口只增加必要调用。
- [x] 不修改现有 Trojan 协议实现、Trojan 配置和 Trojan 测试文件。
- [x] 除交付二进制外，不新增持久缓存、日志或临时生成物。
- [x] WebSocket client 仅增加调用方握手截止时间上限，不改变默认全局超时。

## B. Wire protocol

- [x] 实现 `EXT_OPEN` 请求与响应。
- [x] 实现 `EXT_JOIN` 请求与响应。
- [x] 使用安全随机 session ID 和 resume token。
- [x] token 与 Trojan 用户绑定并恒定时间校验。
- [x] 实现有界的 lane 帧编解码。
- [x] 未知版本、未知帧和畸形长度安全失败。

## C. Trojan 兼容

- [x] extrojan 入站识别自定义命令。
- [x] 标准 Trojan 命令无损转交现有 Trojan service。
- [x] 未认证连接保留现有 Trojan fallback 行为。
- [x] extrojan 出站在肯定响应前不发送业务数据。
- [x] 探测旧服务端后使用新连接降级到普通 Trojan。
- [x] 初始探测抗瞬时复位，确认 extrojan 后禁止静默降级。
- [x] 验证三种客户端/服务端组合的 TCP 和 UDP。

## D. Lane pool

- [x] 建立首条 lane 并创建 session。
- [x] 建立额外 lane 并加入 session。
- [x] 健康检查、读写截止时间和坏 lane 移除。
- [x] 独立重拨和有限退避。
- [x] 有界 lane 写队列。
- [x] 基于队列量并带轮转的多 lane 调度。
- [x] 全 lane 消失后进入 `SUSPENDED`。
- [x] 恢复超时内新 lane 加入后回到 `ACTIVE`。
- [x] 超时后关闭 session。
- [x] 全 lane 消失后对永久 `JOIN` 拒绝快速关闭旧 session。
- [x] 尚有存活 lane 时忽略其他后端的永久拒绝，避免滚动更新误杀。
- [x] 网络错误、未知状态和 `resource limit` 保持有限退避重试。

## E. TCP reliable stream

- [x] `STREAM_DATA` 带 64 位 offset。
- [x] 累计 `STREAM_ACK`。
- [x] 有界未确认发送缓冲。
- [x] 有界接收、去重和乱序缓冲。
- [x] lane 故障后重发未确认数据。
- [x] 缓冲满时对上层写入施加背压。
- [x] 实现稳定的 `net.Conn` 地址和截止时间。
- [x] 在可靠流上运行 sing-mux/Yamux。
- [x] 验证多业务 TCP 流和半关闭。

## F. UDP associations

- [x] 打开、确认、关闭 association。
- [x] 重复 `UDP_OPEN` 幂等。
- [x] 待关闭墓碑阻止同 ID association 重建。
- [x] 服务端每 association 只创建一个上游 UDP socket。
- [x] 数据报绕过可靠重放层。
- [x] 数据报在多个健康 lane 间调度。
- [x] 单 lane 失败不关闭 association。
- [x] 全 lane 中断时保留 association。
- [x] 中断期间不无限缓存 UDP。
- [x] 恢复后不重放陈旧数据报。
- [x] UDP 队列和 association 数量有界。
- [x] 可配置的 UDP association 双向空闲超时。
- [x] native extrojan UDP 默认使用稳定包装，session 失败后同一应用 socket 可重建。
- [x] 最后一个 UDP association 空闲回收且无 TCP 流时关闭全部 lane。
- [x] 长 UDP association 定期错峰轮换一条 TCP lane。

## G. 集成

- [x] 实现 extrojan 入站生命周期、TLS 和可选 V2Ray transport。
- [x] 实现 extrojan 出站生命周期、detour、TLS 和可选 V2Ray transport。
- [x] 接入 sing-box TCP router。
- [x] 接入 sing-box packet router。
- [x] Interface update 触发 lane 重建而不是立即终止 session。
- [x] 关闭过程幂等且不泄漏 goroutine。

## H. Verification

- [x] 配置 JSON round-trip 和默认值测试。
- [x] 帧编解码、边界和恶意长度测试。
- [x] token、用户和版本拒绝测试。
- [x] TCP 任意边界断链恢复测试。
- [x] TCP 双向并发和半关闭恢复测试。
- [x] TCP 恢复超时测试。
- [x] UDP 多 lane 分布测试。
- [x] UDP 源端口稳定测试。
- [x] UDP 单 lane 与全 lane 故障测试。
- [x] 兼容矩阵测试。
- [x] 缓冲上限与背压测试。
- [x] `go test` 窄范围测试。
- [x] `go test -race` 并发测试。
- [x] 完整构建。
- [x] 完整差异审查。
- [x] UDP 活动刷新空闲计时，空闲回收后同一应用 socket 可建立新 session。
- [x] lane 轮换不同时关闭多条连接，并由维护器补齐连接池。
- [x] WebSocket transport 下新旧客户端握手、读写超时和阻塞写退出。
- [x] 服务端重启后旧 TCP 快速失败且新 TCP 不等待完整 `resume_timeout`。
- [x] 服务端重启后同一应用 UDP socket 可建立新 session。
- [x] 客户端重启遗留 session 到期后释放用户 session 配额。
- [x] 多后端误投 `JOIN` 时只要仍有健康 lane 就不关闭 session。
- [x] exanytls 保留完整 AnyTLS session 池；池中每个 session 使用独立可靠链路，全部 carrier 短断后保持原 TCP stream / UoT association 与目标连接。
- [x] exanytls 同端口接受标准 AnyTLS 客户端，且出站可串行探测并回退标准 AnyTLS；兼容路径并发 carrier 峰值为一。

## I. 交付清理

- [x] 删除本任务产生的临时文件。
- [x] 确认没有修改用户已有的工作区变更。
- [x] 列出所有被修改的现有文件及必要原因。
- [x] 列出未覆盖限制和后续可选优化。
