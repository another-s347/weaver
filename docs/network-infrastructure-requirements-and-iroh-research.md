# 面向 Local-first 应用的网络基础设施层：需求规格与 iroh 调研

> 状态：需求草案 / 技术选型调研
>
> 日期：2026-08-21
>
> 调研基线：iroh 1.0.3
>
> 本文中的 MUST、SHOULD、MAY 分别表示必须、建议和可选。

## 1. 摘要

目标是提供一个 Rust 网络库：应用只使用稳定的虚拟应用地址，不感知 IP、NAT、局域网变化或中继节点；网络层在端到端认证和加密的前提下，自动选择远程中继或本地直连，并尽量在同一逻辑连接内无感切换路径。库同时提供可靠有序的字节流和不可靠无序的数据报，并提供贴近 Tokio 网络类型的异步接口。

初步结论：iroh 与底层连接需求高度匹配，适合作为候选传输内核，而不是完整产品层。它已经提供按公钥拨号、QUIC 流与数据报、NAT 穿透、加密中继、局域网发现扩展和多路径迁移。项目仍需自行实现加密虚拟网络、成员与配置传播、网络隔离、虚拟应用地址、服务寻址、授权、密钥生命周期、Tokio socket 外观、产品级重连语义和验收体系。

## 2. 背景与目标

Local-first 应用通常优先在设备本地工作，但仍需要在用户的多台设备、协作者设备和远程服务之间同步。真实网络环境会持续变化：设备可能从蜂窝网络进入同一个 Wi-Fi，也可能从局域网离开、切换接口、经过多层 NAT，或只能建立出站 TCP/TLS 连接。

本网络层需要隐藏这些变化，让上层围绕“哪个应用节点、哪个服务”编程，而不是围绕“哪个 IP 和端口”编程。

### 2.1 核心目标

- 使用 Rust 实现，并以 Tokio 为首要异步运行时。
- 引入加密的 `VirtualNetwork` 作为最高层安全与命名边界；成员、拓扑、配置、地址和连接均属于且仅属于一个虚拟网络。
- 使用稳定的虚拟应用地址标识节点和服务，IP 仅存在于内部路由候选中。
- 在无法直连时通过不解密业务载荷的中继通信。
- 自动发现节点和候选路径，优先选择可用且质量更好的直连路径。
- 在 relay、互联网直连和 LAN 直连之间迁移时，已有连接和应用读写不需要重新建立。
- 同时支持可靠有序字节流与不可靠无序数据报。
- 对应用提供接近 `tokio::net::TcpStream`、`TcpListener` 和 `UdpSocket` 的接口。
- 强制端到端身份认证与加密，并提供明确的授权接入点。
- 不支持跨虚拟网络认证、寻址或通信；同一物理节点加入多个网络时，各网络的身份、状态和数据路径严格隔离。

### 2.2 非目标

- 不实现通用三层 VPN、虚拟网卡或任意 IP 包转发。
- 不承诺与操作系统 TCP/UDP 的每个 socket option、错误码和边缘行为完全一致。
- 不以隐藏通信双方、流量大小和时序等元数据为目标；中继仍可能观察这些元数据。
- 不在第一版提供匿名网络、洋葱路由、群组密钥协议或跨节点一致性数据库。
- 不提供跨虚拟网络网关、路由桥接或身份联邦。
- 不承诺在双方同时长时间离线、进程重启或密钥丢失后保留同一个字节流。此类恢复需要更高层的持久化会话协议。

## 3. 术语与地址模型

### 3.1 术语

- **节点（Node）**：运行本网络层并持有身份密钥的应用实例或设备。
- **虚拟网络（Virtual Network）**：成员身份、地址命名、拓扑、配置和通信的最高层隔离域。
- **网络 ID（NetworkId）**：虚拟网络的稳定、自认证标识，由网络根公钥派生。
- **网络成员（Member）**：持有该网络有效成员凭据的节点；成员凭据仅对签发它的网络有效。
- **网络权威（Network Authority）**：由独立 `weaver-relay` 进程承担的网络初始化和配置签名角色，不属于应用 SDK。
- **端点身份（Endpoint Identity）**：握手时使用的密码学身份，通常由公钥表示。
- **服务（Service）**：同一节点上由名称或编号区分的应用协议，例如同步、控制或媒体服务。
- **虚拟应用地址（Virtual Address）**：不含 IP 的稳定目标标识。
- **地址提示（Route Hint）**：可变的内部可达信息，例如 relay URL、局域网 socket 地址或公网候选地址。
- **路径（Path）**：某个已建立连接实际使用的 relay 或 IP 传输路径。
- **连接（Connection）**：经端到端认证的长期 QUIC 连接，可承载多个流和数据报。
- **流（Stream）**：连接内可靠、有序、双向或单向的字节通道。

### 3.2 虚拟网络模型

每个虚拟网络拥有独立的根身份、成员集合、配置版本和加密密钥：

```rust
pub struct NetworkId([u8; 32]);

pub struct VirtualNetwork {
    pub id: NetworkId,
    // 根公钥、当前配置 epoch、成员凭据、网络配置密钥等由内部管理。
}
```

- `NetworkId` 建议定义为网络根公钥的加密哈希，使其不可抢注且可自认证。
- 网络根密钥只用于签发管理密钥、成员凭据和配置 epoch，不直接参与日常数据传输。
- 虚拟网络只能由独立 `weaver-relay` 可执行文件初始化；应用 SDK 不提供 `create network` 接口，只提供加入和打开已有网络。
- 初始化网络的 relay 默认同时承担配置权威、bootstrap、presence 和透明数据中继角色；这些角色在协议上分离，后续 relay 可只启用其中一部分。
- 每个成员在每个网络中使用独立的设备/endpoint 密钥。即使同一物理设备加入多个网络，也不得复用 `DeviceId`、`EndpointId`、发现记录或连接池。
- 网络拓扑和完整配置仅对当前有效成员可读，并使用当前网络配置密钥加密。
- 地址唯一性仅在所属 `NetworkId` 内成立。两个不同网络可以合法使用相同的 `AppAddr` 或 `DeviceId`，两者没有任何关系。
- 所有公开 API 通过 `VirtualNetwork`/`NetworkHandle` 限定作用域。一个 handle 不接受另一个网络的地址、凭据或连接。
- 序列化、持久化或跨进程传递地址时必须携带 `NetworkId`；在已经绑定某个 `NetworkHandle` 的进程内，可以使用省略网络 ID 的 scoped address。

### 3.3 双角色虚拟地址模型

虚拟地址分为服务端地址与客户端地址。两者共享一个由应用指定的 `AppAddr`；服务端直接绑定该地址，客户端在该地址下增加设备唯一的 `DeviceId`，从而把应用实例稳定绑定到具体设备。

以下 Rust 类型用于表达语义，32 字节长度是建议值，最终编码可在协议设计阶段确定：

```rust
/// 由应用指定的稳定地址，不包含 IP、端口或 relay 信息。
pub struct AppAddr([u8; 32]);

/// 应用作用域内的设备唯一标识。
pub struct DeviceId([u8; 32]);

pub enum ScopedVirtualAddr {
    /// 服务端应用绑定指定的 AppAddr。
    Server { app: AppAddr },

    /// 客户端应用绑定 AppAddr + 本设备唯一 ID。
    Client { app: AppAddr, device: DeviceId },
}

pub struct VirtualAddr {
    pub network: NetworkId,
    pub addr: ScopedVirtualAddr,
}
```

建议文本形式为：

```text
# 服务端应用地址
weaver://<network-id>/<app-addr>

# 同一应用在某台设备上的客户端地址
weaver://<network-id>/<app-addr>/devices/<device-id>
```

地址语义如下：

- `AppAddr` 由应用配置或创建，表示该虚拟网络内稳定的服务端应用地址。默认由应用根公钥派生，所有权可以离线验证；人类指定的名称只作为别名。服务器更换 IP、端口、relay 或承载机器时，该地址不变。
- 服务端通过 `bind(Server { app })` 声明自己承载这个应用地址。默认采用单一有效绑定；多实例和负载均衡必须作为显式扩展，不能随机命中多个状态不一致的实例。
- 客户端通过 `bind(Client { app, device })` 绑定到该应用的设备命名空间。相同设备上的不同应用使用不同 `AppAddr`，因此不会共享可关联的客户端地址。
- `DeviceId` 必须是虚拟网络和应用双重作用域内、随机生成并安全持久化的 ID，建议由该网络内的设备身份公钥派生或直接使用其公钥摘要。不得使用 MAC、IMEI、序列号、广告 ID 等可追踪的硬件标识。
- `DeviceId` 的唯一性必须通过密码学密钥所有权证明，而不能只相信客户端提交的字符串。设备私钥保存在本机安全存储中。
- `AppAddr` 与 `DeviceId` 都是逻辑身份，不是 iroh 的路由地址。它们通过签名绑定映射到当前 `EndpointId`，再由发现层解析为 direct/relay 路径提示。
- 应用协议或子服务使用单独的 `ServiceId`/ALPN 选择，不再混入节点地址。这样同一服务端 `AppAddr` 可以复用一个底层连接承载多个协议。
- 地址不得携带 IP、端口或 relay URL。可变路由信息由发现层单独解析并带序列号与有效期。
- 人类可读名称只能作为经过认证目录中的别名，不得直接成为认证依据。

### 3.4 寻址与拨号规则

| 发起方 | 目标地址 | 语义 |
|---|---|---|
| 客户端 | `Server { app }` | 连接该应用当前有效的服务端实例。 |
| 服务端 | `Client { app, device }` | 精确连接该应用在指定设备上的客户端实例。 |
| 客户端 | `Client { app, device }` | 可选的同应用设备间直连；默认由应用策略决定是否允许。 |

- 客户端连接服务端时，服务端看到并验证的来源必须是完整的 `Client { app, device }`，不能只是底层临时 `EndpointId`。
- 服务端连接客户端时，必须使用完整客户端地址；仅有 `AppAddr` 不得被解释为任意客户端或广播。
- 同一个 `DeviceId` 不得同时绑定到不同设备密钥。检测到冲突时默认拒绝后注册者，并产生安全事件。
- 同一设备重启后应恢复同一个客户端地址；卸载重装、清除安全存储或主动“忘记设备”后可以生成新 `DeviceId`。
- 若设备密钥轮换，旧设备密钥或应用授权方必须签署 `DeviceId -> new EndpointId/key` 轮换声明，使逻辑客户端地址保持不变。
- 发起方和目标地址的 `NetworkId` 必须一致；不一致时在本地直接返回 `NetworkMismatch`，不得发起发现或网络握手。

## 4. 功能需求

### 4.1 身份与生命周期

- **NET-1 MUST**：每个 `NetworkId` 拥有独立信任根、成员凭据、配置 epoch 和配置加密密钥。
- **NET-2 MUST**：同一进程可加入多个虚拟网络，但每个网络使用独立 endpoint 身份、发现状态、连接池、地址表、配置存储和日志作用域。
- **NET-3 MUST**：禁止跨网络拨号、认证、连接复用、数据转发和地址解析；网络库不得提供隐式 bridge。
- **NET-4 MUST**：网络成员被移除或凭据过期后，不得建立新连接，也不得解密后续 epoch 的配置。
- **NET-5 MUST**：应用进程不能生成网络根或权威配置；创建、恢复和管理网络必须通过独立 `weaver-relay`/管理 CLI 完成。
- **ID-1 MUST**：服务端绑定应用指定的 `Server { app }` 地址，并证明自己拥有该 `AppAddr` 的有效服务端凭据。
- **ID-2 MUST**：客户端绑定 `Client { app, device }` 地址，并使用本设备私钥证明 `DeviceId` 所有权。
- **ID-3 MUST**：首次运行生成设备密钥和应用作用域 `DeviceId`，并在安全存储中持久化；普通重启不得改变客户端虚拟地址。
- **ID-4 MUST**：每条连接在握手阶段双向认证，连接结果必须暴露经过验证的远端 `VirtualAddr` 和底层 `EndpointId`。
- **ID-5 MUST**：同一底层 endpoint 可承载多个 `ServiceId`/ALPN，但服务端应用绑定仍以 `AppAddr` 为边界。
- **ID-6 MUST**：支持应用地址凭据和设备密钥的吊销、轮换；轮换记录必须由旧密钥、应用管理密钥或受信目录签名。
- **ID-7 SHOULD**：设备身份与用户账号身份分离，一个用户可在同一 `AppAddr` 下授权多个 `DeviceId`。

### 4.2 加入网络与配置传播

应用只需通过任一在线成员节点加入虚拟网络。加入凭据必须包含足以首次联系该节点的最小 bootstrap 信息；在成为成员之前，新节点不需要预先知道网络的完整 relay、发现服务或拓扑。

建议加入流程：

1. 新节点先生成该网络专用的成员公钥；网络权威 relay 为此公钥签发一次性 `JoinTicket` 和预授权成员凭据。
2. ticket 至少包含 `NetworkId`、网络根公钥、被授权的成员公钥与角色、一个引导节点的 `EndpointId` 与最小可达提示、唯一 nonce、有效期和管理签名。
3. 新节点通过 ticket 联系该引导节点，验证网络根身份；引导节点离线验证管理签名，并要求新节点证明其持有 ticket 指定成员公钥的私钥。
4. 任一普通成员在验证通过后即可向新成员发送经过签名且加密的最新配置快照及必要的增量日志，无需自身具有签发成员的权限。
5. 新成员获知 relay、其他可发现成员、策略和配置传播节点，然后发布自己的网络内地址记录。
6. 此后新成员可以从任一在线成员获取并校验更新，不再依赖最初的引导节点。

- **CFG-1 MUST**：任一在线成员都可以转发它持有的配置快照和增量，但第一版只有网络权威 relay 持有的在线管理密钥可以提交新的权威配置。
- **CFG-2 MUST**：配置使用单调递增的 `epoch + revision`、内容哈希和管理签名；节点只接受合法后继版本，拒绝回滚、分叉和过期配置。
- **CFG-3 MUST**：完整配置和拓扑使用当前 epoch 的网络配置密钥加密。非成员、已撤销成员、公共发现服务和普通 relay 不得获得明文。
- **CFG-4 MUST**：成员间使用 gossip/anti-entropy 传播配置，节点重新上线后可以从任一成员补齐缺失版本；传播过程最终收敛但不得赋予普通成员修改权限。
- **CFG-5 MUST**：配置至少包含网络信任根、管理公钥、成员/角色策略、relay 节点、发现策略、协议版本、地址分配规则、撤销信息、过期时间和下一个密钥 epoch。
- **CFG-6 MUST**：节点被撤销、管理员主动轮换或配置密钥泄露时创建新 epoch，并只向剩余成员封装新配置密钥。撤销不承诺抹除成员已经读取的历史配置。
- **CFG-7 MUST**：动态直连候选、RTT 和短期在线状态不进入权威配置日志，而使用成员签名、短 TTL 的运行时公告传播。
- **CFG-8 MUST**：bootstrap ticket 仅暴露首次联系所必需的单节点信息；网络完整拓扑必须等成员认证完成后才能获取。
- **CFG-9 SHOULD**：ticket 默认一次性、短有效期、绑定新成员公钥并限定角色，且支持在使用前撤销。若无法获得权威一次性消费状态，重复使用同一 ticket 也只能证明同一把成员私钥，不能创建第二个身份。
- **CFG-10 MUST**：为支持零基础设施加入，ticket/bundle 可以携带候选成员可解密的已签名配置 snapshot/delta。候选连接配置较旧的成员时，可以先提交该权威更新；对端必须验签、校验哈希链并原子应用后再认证新成员。
- **CFG-11 MUST**：配置包含网络内 Virtual DNS zone，记录至少为规范化 `*.virtual` 名称、目标 `AppAddr` 和有效期；名称在同一配置中必须唯一，目标应用必须已注册，只有 authority 可以提交变更。
- **CFG-12 MUST**：Virtual DNS 记录随签名配置使用相同的加密、哈希链和 anti-entropy 传播；更新原子生效，过期记录不得继续解析。

### 4.3 发现与路由

- **DISC-1 MUST**：客户端仅凭 `Server { app }`、服务端仅凭 `Client { app, device }` 即可发起连接，不要求调用者提供 IP、端口、`EndpointId` 或 relay URL。
- **DISC-2 MUST**：在当前虚拟网络内组合多个发现源并并行查询：加密配置/进程内缓存、成员间发现、受保护的 LAN mDNS，以及网络配置授权的私有目录。
- **DISC-3 MUST**：发现记录至少包含目标 `VirtualAddr`、当前 `EndpointId`、候选路径、序列号、过期时间、能力和签名；过期或回滚记录不得覆盖新记录。
- **DISC-4 MUST**：网络接口、默认路由、IP 或可用 relay 变化时，自动重新发布本机候选并刷新活跃对端。
- **DISC-5 MUST**：发现源只提供“在哪里尝试连接”，网络成员凭据和端到端握手身份共同决定“连接到的是谁、属于哪个网络”。不可信发现源不能冒充目标或把连接导向另一网络。
- **DISC-6 MUST**：LAN 公告不得明文广播 `NetworkId`、`AppAddr`、`DeviceId` 或完整拓扑；应使用由当前网络密钥派生并定期轮换的 discovery tag，使同网络成员可识别、非成员不可关联。
- **DISC-7 SHOULD**：对负缓存、查询超时和多来源冲突给出可观测状态。
- **DISC-8 MUST**：默认禁用向公共 DNS/Pkarr 发布网络成员和拓扑；如未来启用，只能发布不泄露网络身份的加密或不透明记录。
- **DISC-9 MUST**：`NetworkHandle` 内置网络作用域名称解析，支持名称连接可靠流和数据报；不得把 `.virtual` 名称交给系统 DNS。未知、过期或另一网络中的同名记录必须在本地失败。

### 4.4 建连与路径选择

- **CONN-1 MUST**：能够并行或分阶段尝试 relay、LAN 和公网直连候选，不能因单一发现源失败而中止全部尝试。
- **CONN-2 MUST**：没有可用直连路径时通过 relay 建连；relay 只转发端到端加密的数据包。
- **CONN-3 MUST**：发现可用直连路径后，在同一已建立连接中增加并验证路径，再将发送流量切到直连，应用层 stream 不重建。
- **CONN-4 MUST**：采用 make-before-break。新路径通过认证、可达性和质量验证前，不释放当前可用路径。
- **CONN-5 MUST**：直连失效但 relay 仍可用时，连接可迁回 relay；短暂路径切换期间应用读写可以背压，但不得静默丢失可靠流数据。
- **CONN-6 MUST**：路径选择默认偏好安全策略允许的直连，其次按 RTT、丢包、带宽估计和成本选择；必须有滞回，防止路径抖动。
- **CONN-7 MUST**：网络变化应主动触发 LAN 发现、地址更新和路径探测，不能只等待周期性超时。
- **CONN-8 MUST**：只要同一加密连接仍存活且至少一条路径在超时窗口内恢复，流 ID、字节序和应用句柄保持不变。
- **CONN-9 SHOULD**：支持多 relay 配置和快速故障转移。是否长期维持多个 relay 热连接必须可配置并记录资源成本。
- **CONN-10 SHOULD**：对连接已经死亡后的“逻辑会话恢复”提供独立扩展协议；它必须使用消息编号、确认和去重，不能伪装成天然可靠的 TCP 字节流。
- **CONN-11 MUST**：允许 relay 列表为空。只有客户端与服务端之间存在可用直连路径时才能通信，例如同一 LAN，或至少一端具有公网可达地址/端口映射；双方位于互不直达的 NAT 后或 UDP 被阻断时，不承诺可用。

“透明迁移”的边界必须明确：relay 到 LAN 的切换可以由 QUIC 多路径在同一连接内完成；如果所有路径失效超过 idle timeout，原 QUIC 连接已经终止。此时若要继续使用旧句柄并保证 exactly-once，需要本项目额外实现可恢复逻辑流，不能仅依靠 QUIC。

### 4.5 可靠有序流

- **STREAM-1 MUST**：提供双向可靠有序字节流，单个流内不乱序、不重复交付。
- **STREAM-2 MUST**：实现 `tokio::io::AsyncRead + AsyncWrite + Unpin + Send`，支持 `split`、半关闭、flush 和取消安全的异步读写。
- **STREAM-3 MUST**：支持服务端 `bind(Server { app })` 和 listener/accept 语义，并在 accept 结果中提供已认证的 `Client { app, device }` 来源地址。
- **STREAM-4 MAY**：未来可增加同一端点的 QUIC 连接池；第一版每个逻辑 TCP 流使用独立 QUIC connection，连接复用不属于语义或兼容性要求。
- **STREAM-5 MUST**：定义与 QUIC reset、stop、idle timeout 和应用关闭码之间的错误映射，不能把未确认交付报告为成功。
- **STREAM-6 SHOULD**：支持流优先级、连接与流级背压、读写超时和优雅关闭。

### 4.6 不可靠无序数据报

- **DGRAM-1 MUST**：保持消息边界，允许丢失和乱序，不做自动重传。
- **DGRAM-2 MUST**：提供 `bind`、`connect`、`send`、`send_to`、`recv`、`recv_from` 风格接口；服务端绑定 `Server { app }`，客户端绑定 `Client { app, device }`，收发地址均使用 `VirtualAddr`。
- **DGRAM-3 MUST**：在发送前暴露或校验当前最大数据报尺寸；不得暗中分片后伪装成单个原子 UDP 包。
- **DGRAM-4 MUST**：定义发送缓冲区满时的策略：立即返回 `WouldBlock/QueueFull`，或显式等待空间。默认不得无提示地挤掉旧数据报。
- **DGRAM-5 SHOULD**：可选提供有界去重窗口，但基础接口不承诺 exactly-once。
- **DGRAM-6 MAY**：未来支持广播/组播语义；它不是 QUIC 数据报天然提供的能力。

### 4.7 Tokio 兼容层

建议公开以下本项目类型：

```rust
VirtualTcpStream
VirtualTcpListener
VirtualUdpSocket
NetworkEndpoint
VirtualNetwork
NetworkHandle
NetworkId
VirtualAddr
ScopedVirtualAddr
ServerAddr
ClientAddr
AppAddr
DeviceId
```

- **API-1 MUST**：常见业务代码只需替换导入、地址类型和构造入口，后续基于 `AsyncRead/AsyncWrite` 的 codec、framing 和 `tokio::io::copy` 可继续工作。
- **API-2 MUST**：`VirtualTcpStream` 将一对 QUIC 双向流包装为单个全双工对象；底层 QUIC connection 生命周期对调用者透明，不承诺连接池复用。
- **API-3 MUST**：`VirtualUdpSocket` 基于已认证连接的数据报实现，不能暴露伪造的源地址。
- **API-4 MUST**：提供底层扩展句柄以读取路径类型、RTT、远端身份、最大数据报和关闭原因，但正常业务不依赖它们。
- **API-5 SHOULD**：抽象出便于依赖注入和测试的 connector/listener traits。
- **API-6 MUST**：服务端入口显式接收 `AppAddr`，客户端入口显式接收 `AppAddr + DeviceId`；不得用重载或缺省值混淆两种绑定角色。
- **API-7 MUST**：所有 bind/connect/resolve 操作都从一个已加入网络的 `NetworkHandle` 发起；地址中的 `NetworkId` 与 handle 不一致时必须在本地失败。

建议的最小使用方式：

```rust,no_run
// 网络由独立 weaver-relay 初始化；应用只加入已有网络。
let network = VirtualNetwork::join(join_ticket, device_key).await?;

// 服务端：在当前网络内，用指定地址绑定服务端应用。
let listener = network
    .bind_tcp(ServerAddr::new(app_addr), server_credential)
    .await?;
let (stream, peer) = listener.accept().await?;
assert!(matches!(peer.addr, ScopedVirtualAddr::Client { .. }));

// 客户端：在同一网络内，以指定地址 + 本机唯一 DeviceId 绑定应用设备。
let endpoint = network
    .bind_client(ClientAddr::new(app_addr, device_id), device_credential)
    .await?;
let stream = endpoint.connect(ServerAddr::new(app_addr), service_id).await?;
```

这里的“无缝替换”定义为异步 I/O 生态兼容和低迁移成本，不是与 `tokio::net` 具体类型的 ABI 或 100% 源码兼容。`SocketAddr`、端口复用、TTL、IP multicast、原始 fd 等 IP 专属能力没有合理的一对一映射。

### 4.8 认证、授权与加密

- **SEC-1 MUST**：所有直连和中继路径均使用 TLS 1.3/QUIC 级端到端加密，禁止明文降级。
- **SEC-2 MUST**：客户端拨号时验证服务端确实被授权绑定目标 `AppAddr`；服务端验证来源 `AppAddr + DeviceId` 与设备公钥的签名绑定，并在交付给服务前执行应用/设备/service ACL。
- **SEC-3 MUST**：定义信任引导方式，例如扫描邀请、短码配对、受信账号目录或管理员签名；生产默认不得采用无提示 TOFU。
- **SEC-4 MUST**：发现记录经过签名并防重放，服务协商使用版本化 ALPN，未知或降级版本默认拒绝。
- **SEC-5 MUST**：私钥使用系统密钥库或等价安全存储；日志、崩溃转储和遥测中不得出现私钥或会话密钥。
- **SEC-6 MUST**：relay 接入控制和端到端应用授权分离。即便 relay 允许某节点使用带宽，也不代表应用服务允许该节点连接。
- **SEC-7 MUST**：限制握手速率、并发流、接收窗口、数据报队列和每身份资源占用，以防 DoS。
- **SEC-8 SHOULD**：支持证书/公钥轮换、设备撤销列表和受控的 0-RTT；涉及非幂等操作时默认禁用 0-RTT。
- **SEC-9 MUST**：网络成员凭据绑定 `NetworkId + member public key + role + validity + epoch`，不得在其他网络中复用或被其他网络的根信任。
- **SEC-10 MUST**：业务连接在交付任何应用数据前验证双方属于同一 `NetworkId`。未知网络、其他网络或已撤销网络凭据统一拒绝。
- **SEC-11 MUST**：业务载荷使用连接级双向认证 QUIC 加密；网络配置和拓扑另外使用网络 epoch 密钥加密。两层密钥用途分离，禁止把配置群组密钥直接用作业务传输密钥。

### 4.9 中继

- **RELAY-1 MUST**：中继只根据端点标识转发加密包，不持有端到端解密密钥。
- **RELAY-2 MUST**：relay 以独立 Rust 二进制 `weaver-relay` 部署，不与应用进程或 SDK 生命周期绑定。
- **RELAY-3 MUST**：支持完全自托管，并可禁用任何公共基础设施。
- **RELAY-4 MUST**：relay 地址、鉴权、容量和地域策略可配置；至少支持两个故障域。
- **RELAY-5 MUST**：可用 relay 列表属于加密网络配置。加入网络前仅允许使用 ticket 中为联系引导节点附带的最小 relay 提示。
- **RELAY-6 MUST**：纯 data-relay 可见传输端点标识、来源 IP、时序和流量大小；若鉴权按租户分区，它还可能看到不透明租户域，但不应获得 `NetworkId`、网络配置、应用地址或拓扑明文。
- **RELAY-7 SHOULD**：支持滚动升级、健康检查、限速、配额、审计和快速摘除故障节点。
- **RELAY-8 MUST**：`weaver-relay init` 是创建虚拟网络的唯一入口，负责生成 `NetworkId`、根/在线管理密钥、初始配置和 recovery bundle。
- **RELAY-9 MUST**：同一二进制支持 `authority`、`data-relay` 和 `combined` 角色。第一版首个 relay 使用 combined；附加 relay 推荐使用 data-relay/bootstrap 角色。
- **RELAY-10 MUST**：透明数据中继模块不持有业务端到端密钥。combined 进程中的配置权威会接触拓扑明文，因此其可信边界必须与纯 data-relay 明确区分。
- **RELAY-11 MUST**：虚拟网络可以包含零个 `data-relay`。`weaver-relay` 可以只作为初始化/authority 管理工具运行，完成离线 provisioning 后退出；这不影响已经加入且能够直连的成员通信。

### 4.10 加密网络拓扑

网络拓扑描述成员及其可承担的基础设施角色，但不是一张永久、强一致的在线状态表：

```text
VirtualNetwork
  ├─ config authorities：签发成员和权威配置
  ├─ member nodes：持有网络凭据、传播配置
  ├─ service nodes：绑定 Server { app }
  ├─ client nodes：绑定 Client { app, device }
  ├─ relay nodes：透明转发端到端加密包
  └─ bootstrap nodes：接受 JoinTicket，引导新节点加入
```

- **TOPO-1 MUST**：一个节点可以同时具有多个网络内角色，但角色由网络凭据和配置授权，不能自行声明。
- **TOPO-2 MUST**：权威拓扑只记录稳定身份、角色、relay/引导能力和策略；短期 IP、候选路径、在线状态和质量指标使用短 TTL 公告。
- **TOPO-3 MUST**：完整拓扑仅以加密配置形式保存和传播；磁盘缓存也必须使用网络密钥或系统安全存储保护。
- **TOPO-4 MUST**：普通成员可以转发密文配置和已签名拓扑，但不能添加成员、提升角色、替换 relay 或修改授权策略。
- **TOPO-5 MUST**：节点同时加入多个网络时，为每个网络运行逻辑独立的拓扑视图；禁止自动把 A 网络获知的节点或 relay 发布到 B 网络。
- **TOPO-6 MUST**：网络层不实现跨网络 route、proxy、identity federation 或 stream forwarding。未来若需要，必须由显式应用网关在两个独立连接之间转发，并不属于本协议。
- **TOPO-7 SHOULD**：成员可从任一节点请求网络配置；没有配置传播专用节点时，所有在线成员都承担只读 seed 能力。
- **TOPO-8 MUST**：第一版不支持 relay chaining/federation。中继路径的双方 endpoint 必须连接到同一个 relay B；relay C 不能通过作为 B 的普通客户端，为位于 C 后面的其他 endpoint 提供到 B 的级联路由。
- **TOPO-9 MUST**：首版标准拓扑为本地服务端 A、远程 relay B、客户端 C。A 主动维持到 B 的出站连接；C 可以直接连接 A，或连接同一 B 后由 B 将端到端加密包转发给 A。

### 4.11 存储边界

- **STORE-1 MUST**：网络层必须持久化恢复稳定身份和网络成员资格所需的最小状态，包括 `DeviceId`、成员/endpoint 身份引用、凭据、已验签配置及 current head、epoch/撤销状态；authority 还必须持久化管理序列和 ticket 状态。
- **STORE-2 MUST**：应用 SDK 通过公开 `StateStore` 与 `SecretStore` 接口接受上层注入实现，不强占应用已有数据库；同时必须提供官方默认持久化实现，避免每个接入方重复实现关键事务语义。
- **STORE-3 MUST**：普通状态与秘密材料分离。`StateStore` 不接收明文私钥；`SecretStore` 使用系统密钥库或等价保护，并报告安全能力和降级状态。
- **STORE-4 MUST**：`StateStore` 提供带前置版本条件的原子批量提交、崩溃一致性、持久提交和 schema 版本迁移。配置 head 与对应 envelope、epoch 指针及 ticket 消费状态不得分批提交。
- **STORE-5 MUST**：存储 namespace 由内部网络上下文派生；同一物理数据库中的不同 `NetworkId`、relay authority 状态和应用数据不得串用 key space。
- **STORE-6 MUST**：独立 `weaver-relay` 自带可生产使用的默认本地持久化，并通过 `--data-dir` 管理；authority 禁止以内存存储运行。应用 SDK MAY 注入自有实现或采用官方默认实现。
- **STORE-7 MUST**：活动连接、stream/datagram 队列、短期候选路径、RTT 和 presence 缓存默认仅驻留内存。网络层不持久化应用业务内容，也不承诺进程重启后恢复同一字节流。
- **STORE-8 MUST**：自定义存储只负责保存 opaque、版本化记录；协议编码、加密、验签、schema 迁移和状态机规则仍由 Weaver 控制，不能由存储实现绕过。
- **STORE-9 MUST**：`StateStore` 与 `SecretStore` 之间不得假定分布式事务；写入、轮换、删除和崩溃恢复顺序必须保证已提交状态不会引用缺失密钥，允许并安全清理无引用 secret。

### 4.12 可观测性与运维

- **OBS-1 MUST**：公开连接状态和路径事件：discovering、relay、direct-LAN、direct-WAN、mixed、migrating、degraded、closed。
- **OBS-2 MUST**：记录每次路径选择的原因、耗时和失败阶段，但默认对 IP、`AppAddr`、`DeviceId`、`EndpointId` 和用户数据做脱敏。
- **OBS-3 MUST**：提供连接成功率、直连率、迁移耗时、RTT、丢包、relay 带宽、重连和认证拒绝指标。
- **OBS-4 SHOULD**：支持 qlog/诊断包，并确保必须由用户显式启用敏感网络诊断。
- **OBS-5 MUST**：指标、缓存键和后台任务全部带内部 `NetworkId` 作用域；面向外部导出的标签默认使用不可逆脱敏值，避免意外关联不同虚拟网络。

## 5. 非功能需求与初始 SLO

以下数值是供原型验收使用的初始目标，需通过真实设备实验校准：

| 项目 | 初始目标 |
|---|---|
| 已知地址的 LAN 建连 P95 | ≤ 500 ms |
| relay 首次建连 P95 | ≤ 2 s（不含离线目标超时） |
| 已有 relay 连接发现 LAN 后切换 P95 | ≤ 3 s |
| 单路径失效、备用路径存活时的可靠流可见中断 P95 | ≤ 1 s |
| 可靠流迁移 | 不丢字节、不重复、不乱序 |
| 静止后台流量 | 可配置；移动端必须有节能模式 |
| 首批支持平台 | Android arm64 交叉编译；Linux、Windows、macOS 原生库构建与测试 |
| 后续平台 | iOS，进入支持列表前必须完成后台网络与密钥存储真机验收 |

可靠性目标必须区分：底层库单元测试通过、网络仿真通过、真实 NAT/防火墙通过、移动设备网络切换通过，以及生产 relay 故障演练通过。

### 5.1 Android 首批支持要求

- 本仓库的 Android 支持边界是核心 Rust 客户端代码能够使用 NDK 为 `aarch64-linux-android` 编译；不要求仓库提供 JNI/CDylib、Kotlin 生命周期封装或真机自动化。
- `StateStore` 与 `SecretStore` 保持平台无关的注入接口；是否使用 Android Keystore、如何桥接 Rust，由宿主应用决定。
- 网络层公开 `network_change()`，宿主若已有 Android 网络回调，可在 Wi-Fi、蜂窝、VPN 或链路属性变化时调用它；本仓库不绑定 `ConnectivityManager`。
- Android 编译验收必须记录 Rust target、NDK 版本、API level 和实际 `cargo ndk build` 结果，不能只验证桌面 host build。

## 6. 验收场景

### 6.1 必测拓扑

1. 同一二层 LAN、无互联网且配置中没有 data-relay：仅一个客户端和一个服务端通过 invitation bundle/LAN 发现组成网络并直连。
2. 不同 NAT，UDP 可用：先 relay 建连，再成功穿透并迁移到直连。
3. 不同 NAT，UDP 被封：全程经 relay，业务可用。
4. 已经通过 relay 传输时，两端进入同一 LAN：旧 stream 句柄保持可用，路径转为 LAN。
5. 已经 LAN 直连时一端切到蜂窝/其他 Wi-Fi：如 relay 路径仍存活，旧 stream 继续工作。
6. 传输中 relay 重启或单个 relay 故障：验证多 relay 的实际中断时间和连接是否存活。
7. Wi-Fi/蜂窝反复切换、NAT 映射变化、系统睡眠恢复。
8. 伪造 `AppAddr` 绑定、重复 `DeviceId`、错误 EndpointId、撤销设备、重放旧记录和未授权 service。
9. 可靠流持续传输带校验序号；数据报测试丢失、乱序、队列满和 MTU 变化。
10. Android arm64 NDK 构建；Windows、Linux 和 macOS 分别执行其原生构建与适用的集成测试。Android 真机互通属于宿主应用验收，不作为本仓库首批支持门槛。
11. 新节点只持有 `JoinTicket`，通过任一在线成员加入并取得加密配置；随后关闭原引导节点，配置更新仍能从其他成员收敛。
12. 创建两个使用相同 `AppAddr/DeviceId` 的虚拟网络，验证地址不冲突、凭据不互认、发现不串线、连接池不复用且不能跨网络通信。
13. 对默认存储和应用注入存储执行断电点故障测试；重启后身份与配置 head 稳定，不出现半提交 revision、重复消费 ticket 或状态引用缺失密钥。
14. 撤销某成员并推进配置 epoch，验证它不能解密新配置、不能重新建连，剩余成员能够继续传播配置。
15. 被动监听 LAN、公共发现服务和 relay 日志，确认无法得到完整 `NetworkId`、应用地址、成员清单或拓扑明文。
16. 本地服务端 A 主动连接远程 relay B；客户端 C 在远程时走 `C -> B -> A`，进入 A 所在 LAN 后切换为 `C -> A`，离开 LAN 后回退 B。全过程验证 A/C 身份不变、B 无业务明文，并记录同一 connection/stream 是否连续。

### 6.2 relay → LAN 无感迁移判定

- 迁移前确认选中路径为 relay，而非仅根据 IP 推测。
- 迁移过程中持续发送单调递增、带哈希的可靠流数据。
- 两端加入同一 LAN 后，观测到新 LAN path opened、validated、selected。
- 原应用 stream 未重建，stable connection ID 不变。
- 接收数据连续、无重复、无乱序，发送方没有收到连接关闭。
- 保留对 relay 回退的验证，确保不是关闭旧连接后悄悄创建新连接。

## 7. iroh 项目调研

### 7.1 项目定位与现状

[iroh](https://github.com/n0-computer/iroh) 是 n0 团队维护的 Rust P2P QUIC 库，核心理念是按公钥而不是 IP 拨号。本文调研时最新 crate 为 [iroh 1.0.3](https://docs.rs/iroh/latest/iroh/)，发布于 2026-07-20；crate 使用 Rust 2024 edition，MSRV 为 Rust 1.91，核心许可证声明为 MIT OR Apache-2.0。relay 源码还包含 DERP 衍生部分的 BSD-3-Clause 许可文件，正式引入前应生成完整依赖与许可证清单。

核心组件：

- `iroh`：端点、发现、NAT 穿透、多路径 QUIC、流和数据报 API。
- `iroh-relay`：relay 客户端和可自托管服务端；协议源自 Tailscale DERP 的修订版本。
- `iroh-base`：`EndpointId`、`EndpointAddr`、`RelayUrl` 等基础类型。
- `iroh-dns-server` / `iroh-dns`：基于 DNS/Pkarr 的端点地址发布和解析。
- `iroh-mdns-address-lookup`：独立 crate，提供 LAN mDNS 地址发现。
- `noq`：iroh 当前使用的 QUIC 实现，公开 API 中可见多路径、流和数据报能力。

### 7.2 工作原理

1. 每个 endpoint 持有密钥，公钥同时作为 `EndpointId`。
2. 发起连接至少需要目标 `EndpointId`、ALPN，以及由显式参数或 address lookup 得到的 relay/direct 地址提示。
3. endpoint 通常先连接 home relay，使不可直接寻址的节点仍可达。
4. 两端经 relay 开始通信并尝试 NAT 穿透；成功后在连接内加入 direct path。
5. 多路径选择器可把选中路径从 relay 改为 IP；`Connection::paths_stream` 和 `path_events` 可观测路径开关与选中路径变化。
6. QUIC 连接承载多个可靠有序 stream，以及不可靠无序、单包大小受限的 datagram。

官方文档明确说明：连接通常先经 relay，随后迁移到直连；relay 只能转发已端到端加密的包，无法读取载荷。当前 `Connection` API 也明确暴露多个并存 path 和 selected-path 变化，这比旧版仅报告 `Relay/Direct/Mixed` 的模型更贴近本需求。

### 7.3 与需求的匹配度

| 需求 | 匹配度 | 说明 |
|---|---|---|
| Rust + Tokio | 高 | Rust 原生，非浏览器目标使用 Tokio runtime。 |
| 加密虚拟网络 | 低 | iroh 提供端点连接，不提供本需求中的 NetworkId、成员凭据、加密拓扑、配置传播或跨网络隔离策略。 |
| 虚拟地址 | 中 | `EndpointId` 是传输公钥地址；服务端 `AppAddr`、客户端 `AppAddr + DeviceId` 及其签名映射需自行实现。 |
| 透明中继 | 高 | relay 转发端到端加密包，可自托管。 |
| NAT 穿透 | 高 | 内建 relay 辅助的 hole punching、地址探测和端口映射选项。 |
| relay → LAN 既有连接迁移 | 高但必须实测 | 1.0 API 有多 path 与 selected-path；网络变化和 LAN 后加入路径需按目标平台验证。 |
| 可靠有序连接 | 高 | QUIC 双向 stream 严格有序并可靠传输。 |
| 无序数据报 | 高 | QUIC datagram 明确定义为不可靠、无序，受单包 MTU 限制。 |
| Tokio `TcpStream` 外观 | 中 | `RecvStream`/`SendStream` 分别实现 AsyncRead/AsyncWrite；需包装成单个双工类型并补 listener/地址语义。 |
| Tokio `UdpSocket` 外观 | 中 | 底层有 connection-scoped datagram；bind/send_to/recv_from、多 peer 映射需自行封装。 |
| 端到端认证与加密 | 高 | QUIC/TLS 1.3，目标公钥固定，双方身份可验证。 |
| 应用授权 | 低到中 | iroh 负责身份认证，是否允许某个 peer/service 由应用或 endpoint hooks 决定。 |
| 网络内与 LAN 自动发现 | 中 | 核心支持可组合 AddressLookup，mDNS 是额外 crate；成员专属加密发现和 topology privacy 需自行实现。 |
| 生产级 relay HA | 中 | 支持多 relay 和自托管，但故障窗口与热备行为需要压测和故障演练。 |

### 7.4 关键 API 映射

| 本项目概念 | iroh 候选能力 | 仍需实现 |
|---|---|---|
| `VirtualNetwork` / `NetworkId` | 无直接对应 | 网络根、成员证书、epoch 密钥、配置日志、加入流程和硬隔离 |
| `AppAddr` / `DeviceId` | `EndpointId` | 双角色逻辑地址、应用凭据、设备绑定、轮换与别名目录 |
| 路由解析 | `AddressLookup`、DNS/Pkarr、Memory、mDNS crate | 签名目录策略、隐私策略、缓存和冲突规则 |
| 底层端点 | `Endpoint` | 生命周期管理、平台集成、统一配置 |
| 服务分发 | ALPN、`protocol::Router` | `ServiceId` 注册、版本协商、ACL |
| 可靠流 | `Connection::open_bi/accept_bi` | `VirtualTcpStream/Listener`、连接池、错误映射 |
| 数据报 | `send_datagram/read_datagram` | 多 peer socket 外观、队列策略、虚拟源地址 |
| 路径迁移 | QUIC multipath、`paths_stream/path_events` | 选择策略、SLO、UI/指标、全拓扑验证 |
| 中继 | `iroh-relay` | 部署、鉴权、容量、地域和 HA 策略 |
| 身份认证 | EndpointId + TLS | 应用/设备/service 授权、撤销与密钥轮换 |

### 7.5 不可直接等同的地方

#### iroh 地址不等于完整应用地址

`EndpointId` 解决“当前连接到哪把传输公钥”，但不天然表示服务端应用地址或某应用在某设备上的客户端地址。连接仅凭 `EndpointId` 时仍需 address lookup 找到 relay/direct 地址。我们的地址层必须维护两种经过签名的映射：`Server { app } -> current EndpointId(s)` 与 `Client { app, device } -> current EndpointId`。因此传输密钥轮换不会迫使应用地址或设备地址改变。

#### QUIC stream 不等于 `TcpStream`

iroh 为一次 QUIC connection 提供许多单向或双向 stream。双向 stream 是独立的发送和接收对象；包装层可以实现 Tokio `AsyncRead/AsyncWrite`，但 TCP 的 `SocketAddr`、Nagle、TTL、OOB、原始 fd 等接口没有对应物。对基于异步字节流 trait 的代码可低成本替换，对硬编码具体 `TcpStream` 或 socket option 的代码不能声称零修改。

#### QUIC datagram 不等于完整 UDP socket

iroh datagram 依附于已认证 QUIC connection，优点是来源传输身份可信、路径可迁移；差异是必须先有 connection、单包上限随路径 MTU 变化，而且没有天然 IP 广播/组播。多 peer `send_to/recv_from` 需要本项目维护 `VirtualAddr -> EndpointId -> Connection` 映射，并校验逻辑地址与传输身份的签名绑定。

#### 身份认证不等于授权

iroh 能证明对端持有对应 EndpointId 的私钥，但官方文档明确把“是否允许该 peer”留给应用。必须在 service handler 收到业务数据之前执行 ACL，不能把“知道 EndpointId”或“声称某个 DeviceId”当成已经获得应用授权。

### 7.6 风险与待验证项

1. **路径迁移不能只看文档描述。** iroh 1.0 引入/强化了多路径，发布记录包含网络变化后主动 hole punching 和切换 uplink 的测试，但目标平台、目标 NAT 和 relay 拓扑仍需端到端验证。
2. **LAN 最优路径仍有工程风险。** 官方 issue 列表在 1.0 时代仍有“局域网中 relay 与 direct 路径选择不理想”等问题，必须用 path events 和 qlog 判定真实选路。
3. **多 relay 不等于已有连接一定零中断。** 一个仍处于 Needs Triage 的 1.0.0-rc.0 issue 报告 home relay 故障约 30 秒不可达且已有连接死亡。它不能证明 1.0.3 仍存在同样问题，但足以要求我们在选型 PoC 中复现和验证，而不能只依赖“自动 failover”的产品描述。
4. **默认基础设施不适合直接作为生产承诺。** 官方公共 relay 面向开发测试且限速；生产应自托管或购买专用 relay，并至少跨两个故障域。
5. **发现隐私需自行设计。** DNS/Pkarr 或 mDNS 发布哪些地址与用户数据取决于配置；默认 preset 不等同于本产品的隐私策略。
6. **MSRV 较新。** iroh 1.0.3 要求 Rust 1.91，应确认桌面、移动端 CI 和供应链能够接受。
7. **依赖和二进制体积。** 正式集成前应分别测量 minimal、自托管 discovery、TLS provider 和 portmapper feature 组合的编译时间、产物体积和依赖漏洞面。

### 7.7 推荐决策

建议进入一个有退出条件的 iroh PoC，而不是现在自行开发 QUIC、多路径、NAT 穿透和 relay 协议。

推荐分层：

```text
Application
  └─ NetworkHandle (one encrypted VirtualNetwork)
      └─ VirtualTcpStream / VirtualTcpListener / VirtualUdpSocket
          └─ Service registry + ACL + network-scoped connection pool
              └─ Encrypted config/topology + membership + address resolver
                  └─ Per-network iroh Endpoint / streams / datagrams / multipath
                      ├─ LAN or WAN direct UDP path
                      └─ self-hosted encrypted relay path
```

iroh 负责困难且通用的传输机制；本项目负责稳定的产品语义。不要 fork iroh 作为第一步，优先通过公开的 `AddressLookup`、endpoint hooks、path selector、Router 和 connection API 组合能力。只有 PoC 证明公开扩展点无法满足硬性需求时，再评估上游贡献或维护小型补丁。

## 8. PoC 范围与通过标准

### 8.1 PoC 实现

- 固定 iroh 1.0.x 精确版本，建立两个客户端和两个自托管 relay。
- 实现独立 `weaver-relay init/serve/invite`，由 relay 生成 `NetworkId`、网络根密钥、成员凭据、一次性 `JoinTicket`、配置 epoch 和加密配置。
- 实现最小 `ScopedVirtualAddr::{Server { app }, Client { app, device }}`、逻辑地址到 EndpointId 的签名映射、网络内目录和受保护的 mDNS lookup。
- 实现一个 `VirtualTcpStream` 包装器和一个多 peer `VirtualUdpSocket` 原型。
- 在服务入口根据已验证 EndpointId 执行 allowlist。
- 暴露 path event、stable connection ID、RTT 和 relay/direct 指标。
- 使用可控网络仿真测试丢包、接口切换、relay 故障、配置分区和跨网络攻击，再做真实 Android/Windows/macOS/Linux 设备验证。

### 8.2 Go / No-Go 条件

以下全部满足才建议采用 iroh：

- relay → 同 LAN 后，既有可靠流在同一 connection ID 上迁移，数据连续无误。
- direct → relay 回退达到约定中断 SLO。
- UDP 被完全封锁时，relay 路径仍可工作。
- 单 relay 故障时，结果符合产品 SLO；不符合则能通过热 relay、配置或可维护的小补丁修正。
- 自定义发现不依赖 n0 公共基础设施，并能抵抗伪造、过期和回滚记录。
- 节点可通过任一成员加入网络并获得加密配置；移除初始引导节点后配置仍可传播和收敛。
- 两个网络即使复用相同应用地址也完全隔离，不能互认、互连、互相发现或复用连接。
- Tokio 包装层能运行一个现有基于 `AsyncRead/AsyncWrite` 的真实协议，而不修改其 framing 逻辑。
- 目标平台上的 CPU、内存、待机流量、产物体积和恢复行为可接受。
- 完成依赖许可证、漏洞和密码学配置审计。

若同连接路径迁移、relay-only 可达性或移动端网络变化无法达到硬性目标，应停止扩大上层封装，先决定向 iroh 上游修复、维护受控补丁，或改评 Tailscale/netstack、libp2p、WebRTC/ICE 等替代路线。

## 9. 已确认决策与可延后事项

### 9.1 已确认的基线

- `VirtualNetwork` 是最高层安全边界，`NetworkId` 由网络根公钥派生。
- 网络只能由独立 `weaver-relay` 初始化；应用 SDK 不提供 create，只能 join/open。
- relay 自带生产可用的持久化；应用 SDK 通过 `StateStore`/`SecretStore` 注入存储，并提供官方默认实现。私钥与普通状态分开保存。
- 网络配置和拓扑加密，仅在成员间传播；应用持 ticket 通过任一在线成员加入后即可获知 relay 等节点配置。
- 地址唯一性仅限单个虚拟网络；不同网络不互认、不互连、不共享发现或连接。
- `AppAddr` 默认由应用根公钥派生，人类名称仅作别名。
- 协议允许同一 `AppAddr` 多实例，PoC 和第一版先采用单活服务端绑定。
- `DeviceId` 是网络和应用作用域内的随机密码学身份；重启保持，卸载重装默认生成新设备身份。
- 网络加入使用网络管理方签发的一次性邀请；应用设备授权由应用根密钥签发，网络成员资格不自动获得所有应用权限。
- relay/direct 透明迁移只承诺原 QUIC 连接仍存活的情况；跨进程或长时间全断网恢复不属于第一版字节流语义。
- 开发可以使用公共 iroh 基础设施，生产必须支持完全自托管，并至少部署两个 relay 故障域。
- 首批支持 Android arm64 交叉编译以及 Linux、Windows、macOS 原生构建；iOS 后续支持。Android 真机网络切换、后台保活和安全密钥存储由具体宿主应用另行验收。

### 9.2 可以在 PoC 后确定

1. 是否增加跨进程重启或长时间离线后的持久化逻辑会话。
2. 多服务端实例采用主备、负载均衡还是应用保证状态一致。
3. 网络管理配置采用单管理员签名、多签还是阈值签名。
4. UDP-like 接口是否需要广播/组播，以及最大业务消息尺寸。
5. 正式的迁移中断 SLO、离线等待时间、relay 成本和移动端后台流量预算。
6. 网络元数据的地域、合规和更高等级抗关联要求，例如是否需要隐藏同一传输端点在一段时间内的重复出现。

## 10. 主要资料

- [iroh 官方仓库与架构概览](https://github.com/n0-computer/iroh)
- [iroh 1.0.3 crate 文档：建连、认证、relay、address lookup](https://docs.rs/iroh/latest/iroh/)
- [iroh Connection API：stream、datagram 与多路径事件](https://docs.rs/iroh/latest/iroh/endpoint/struct.Connection.html)
- [iroh AddressLookup 源码文档：可组合发现与外部 mDNS/DHT crate](https://docs.rs/iroh/latest/src/iroh/address_lookup.rs.html)
- [iroh FAQ：LAN 发现、relay 控制、安全与授权边界](https://docs.iroh.computer/about/faq)
- [自托管 relay 官方指南](https://docs.iroh.computer/add-a-relay)
- [iroh 1.0.3 Cargo 元数据：MSRV、edition 与许可证](https://docs.rs/crate/iroh/latest/source/Cargo.toml.orig)
- [iroh 1.0.3 发布记录](https://github.com/n0-computer/iroh/releases/tag/v1.0.3)
- [多 relay 故障转移风险 issue #4319](https://github.com/n0-computer/iroh/issues/4319)
- [局域网路径选择风险 issue #4251](https://github.com/n0-computer/iroh/issues/4251)
