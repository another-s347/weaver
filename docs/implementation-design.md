# Weaver 具体实现方案

> 状态：可实施技术设计草案
>
> 日期：2026-08-21
>
> 依赖基线：Rust 1.91、Tokio 1.x、iroh 1.0.3
>
> 上游需求：[network-infrastructure-requirements-and-iroh-research.md](./network-infrastructure-requirements-and-iroh-research.md)

## 0. 当前实现状态

2026-08-21 已完成首个 A/B/C 传输切片：

- `weaver-relay` 可作为独立开发中继进程运行。
- `weaver-net::VirtualTcpStream` 将 iroh QUIC 双向流适配为 Tokio `AsyncRead/AsyncWrite`，并持有底层 connection 生命周期。
- `VirtualTcpListener` 提供 Tokio Stream 与 `accept()` 两种接入方式；通用 `connect()`/`tcp_server()` 已与 tonic 命名解耦。
- 虚拟 TCP 明确定义为可靠、有序、不重复的字节流：支持流量控制、EOF、读写半关闭、幂等 shutdown、shutdown 后 `BrokenPipe`，以及等待对端传输确认的 `finish_and_wait()`。
- 每条 QUIC stream 首先发送并由接收端消费版本化内部 open request，使服务端能在客户端尚未发送任何业务数据时完成 `accept()` 并先发消息；内部握手字节不进入应用字节流。
- `NetworkId` 已进入核心类型和 peer descriptor；stream open 请求携带网络 ID、客户端 `AppAddr + DeviceId` 和目标服务端 `AppAddr`，服务端按 QUIC/TLS 已认证的 EndpointId 查找预授权客户端地址，拒绝仅靠 wire 自称的身份。
- `connect()` 会在发网前本地拒绝 descriptor NetworkId 不一致；集成测试也验证了恶意跨网 open 和正确 EndpointId 冒充错误 DeviceId 均不能进入 listener。
- `weaver-store` 已实现可注入 `StateStore/SecretStore` SPI、内部 network/authority scope、版本前置条件和原子 batch；内存实现明确标记为非持久测试能力。
- `RedbStateStore` 使用 redb 4.2 ACID 事务和 durable commit，支持 schema 过新拒绝、持久重开、冲突批次全有或全无；成员与 authority namespace 不能串用。
- `EncryptedFileSecretStore` 使用外部注入且不落盘的 256-bit 主密钥，通过 AES-256-GCM、绑定 `SecretId` 的 AAD 和原子 create-if-absent 文件提交保护秘密；重启、错误主密钥与密文篡改测试已经覆盖。
- 客户端持久身份采用 secret-first 流程：先 seal 并回读 endpoint secret，再原子提交引用、EndpointId 和派生 DeviceId；重开 redb 后恢复同一身份，并发首次创建收敛到单一记录。
- `weaver-crypto` 已实现域分离 ID、网络成员证书、endpoint binding、应用注册和应用/设备 binding；验证固定覆盖收到的原始签名字节，并检查网络、派生身份、签发者、有效期、撤销、角色及绑定关系。
- `weaver-config` 已实现有界的 `NetworkConfigV1` 编码和完整凭据链验证，以及签名哈希链、XChaCha20-Poly1305 配置密文和匿名 X25519 HPKE 成员 key wraps。外层 envelope 与内层 network/epoch/revision/previous-hash 不一致时拒绝应用；回滚、跨网、撤销成员未来 epoch、篡改、重复对象和边界超限测试已经覆盖。
- `weaver-relay-core` 和独立二进制已实现 `keygen/init/status/serve/invite/revoke/app-register/app-bind/export-updates`。初始化在同级 staging 目录生成独立的离线根、在线管理员、成员签名、成员 HPKE 和 endpoint 密钥；root recovery 先以 create-new 语义写到 authority 目录之外，运行目录仅保存根签发的在线管理员。后续配置由在线管理员顺序签署，并通过 redb 精确版本前置条件原子提交 envelope、head 和不可变 revision history。
- `weaver-cli` 已实现 `prepare-join/join/app-prepare/app-bind/status/apply-updates/sync`。`.wjr` 把候选成员的签名、HPKE、EndpointId、nonce、角色和有效期绑定为一份精确签名请求；`.wjt` 验证 root → admin → ticket → member → endpoint 并携带候选成员可解密的已提交 checkpoint。节点配置 checkpoint 与重开所需 signer certificate 同批落盘。
- 配置传播已形成首个安全闭环：authority 保留每个 revision 的加密 envelope，`ConfigUpdateBatch` 最多携带 1024 个且总计不超过 16 MiB 的连续 revision；成员逐个验证 admin 签名、previous hash、revision、epoch、完整凭据链和 HPKE recipient，再一次性 compare-and-swap envelope/head/signer。任意伪造 base head、跳号、跨网批次、遗漏 history 或并发旧写者均 fail closed。
- `weaver-relay serve` 在数据中继旁以 authority 自身已签名 EndpointId 启动 network-scoped config-sync ALPN。请求方先由 QUIC/TLS 证明 EndpointId，服务端只允许当前配置中的 endpoint；响应仍是端到端签名和成员 HPKE 加密的 revision chain。真实进程测试已完成 `C(revision 1) -> B relay/config endpoint -> C(revision 2)` 的强制中继同步。
- `weaver-net` 已提供从 `ValidatedNetworkConfig` 构造 server/client 节点的入口：本地 endpoint 必须存在签名 binding 和对应 app binding，relay 只从已验证配置选择；一个 EndpointId 可以对应多个客户端 `AppAddr + DeviceId`，每条 stream-open 按实际源地址独立授权。开发 demo 仍保留手工 allowlist，等待 join/传播接入。
- tonic server A 通过 `serve_with_incoming` 接收虚拟流；tonic client C 通过自定义 connector 建立虚拟流。
- 服务端使用 EndpointId allowlist 且默认拒绝，`AppAddr` 编入 ALPN；iroh QUIC/TLS 提供 A↔C 传输身份和加密。
- 自动化测试关闭 A/C 的 IP transport，强制 `C -> B -> A` 后完成真实 tonic RPC；另一个原始流测试经中继发送 8 MiB+137 字节、使用不规则写边界并逐字节验证顺序和完整性，同时验证客户端半关闭后仍可读取服务端响应。本机手动测试也已验证允许候选时选择 A↔C IP 直连。
- 路径迁移自动化已用 relay-only descriptor 经 B 建立同一个可靠流，随后观察 Iroh 选择发现到的本地 IP path；迁移前后的请求/响应继续通过同一 `VirtualTcpStream` 和同一认证 EndpointId，应用层未重连。
- `VirtualUdpSocket/VirtualUdpListener` 已以 network/app 专属 ALPN 和认证 association 建立 QUIC DATAGRAM 通道，保留消息边界但明确不承诺送达或顺序、也不自行 ACK/重传；强制中继测试覆盖多种消息尺寸、双向 echo 和错误 DeviceId 拒绝。

当前已形成首版 A/B/C 实现闭环：公开 `NetworkMembership` 与 `NetworkHandle` 从注入存储恢复成员资格，远端 opaque presence、成员 anti-entropy、relay 注册/轮换、TLS 1.3 与动态访问策略均已实现；Linux netem 三种故障画像和 Android arm64 API 24 交叉编译通过。平台系统密钥库适配仍由宿主应用通过 `SecretStore` 注入，本仓库提供加密文件默认实现但不提供 JNI/Keystore 包装。运行方法见仓库根目录 [README.md](../README.md)。

数据面核心通过 `NetworkMembership`、`PersistedConfigState` 和 `NetworkHandle` 消费 `MemberCertificate + EndpointBinding + AppBinding + NetworkConfigV1` 的完整验证结果；配置更新会原子持久化并热更新新连接授权、LAN epoch tag、presence 与 anti-entropy 成员列表。tonic demo 的显式 allowlist 仅保留为无需 provisioning 即可手工启动的开发入口，不是正式 SDK 路径。

可靠性的边界必须保持清晰：同一 QUIC connection 内的 relay/direct 路径切换不会改变字节流；整个 QUIC connection 失效则向应用返回 I/O 错误。实现不能在断连后静默新建连接并重放未确认数据，否则可能产生重复写入，已不再是 TCP 语义。需要跨完整断连或进程重启恢复时，应由应用协议定义 session、幂等键和 resumption，而不是伪装成一个从未中断的 `TcpStream`。

## 1. 实现决策摘要

第一版采用以下方案：

1. 每个 `VirtualNetwork` 对应一个独立的 iroh `Endpoint`、端点密钥、发现器、配置存储和后台任务组；首版不要求跨流复用 QUIC connection。
2. `NetworkId`、`AppAddr`、`DeviceId` 都是自认证或密码学派生的 256-bit ID；应用地址只在一个网络内解析。
3. iroh 负责 QUIC、NAT 穿透、relay、路径发现和连接内迁移；Weaver 负责网络成员、地址映射、应用授权、配置传播和 Tokio socket 外观。
4. 业务数据使用 iroh 的 QUIC/TLS 1.3 端到端加密。网络配置另外使用随机内容密钥加密，再用 HPKE 分别封装给各有效成员。
5. 配置采用单写入者、签名哈希链和成员间 anti-entropy 传播。第一版不使用 CRDT 修改权威配置，也不允许普通成员写配置。
6. 新节点先生成网络专用密钥，再取得绑定该公钥的 `JoinTicket`；持 ticket 连接任一已有成员即可获取配置，不需要预装完整 relay 或拓扑。
7. 全局 presence 使用 relay/directory 上的“不透明键 + 加密值”；LAN 发现使用轮换 HMAC tag，不公开 `NetworkId`、`AppAddr` 或 `DeviceId`。
8. 一个虚拟 TCP 连接映射到同一 iroh QUIC connection 内的一条双向 stream；虚拟 UDP 映射到 QUIC datagram。
9. Android arm64 是首批编译目标：从第一阶段持续执行 NDK 构建，不要求仓库提供 JNI、Keystore 包装或真机测试。
10. 虚拟网络只能由独立的 `weaver-relay` 初始化。应用 SDK 不提供 `create` 或网络管理权威，只提供 `prepare_join`、`join`、`open` 和数据面 API。
11. 存储采用可注入 SPI，并提供官方默认实现：普通持久状态与秘密材料分开；relay 默认使用内置本地数据库，应用可接入自己的数据库和系统密钥库。
12. 每个网络内置独立 Virtual DNS zone。`*.virtual -> AppAddr` 记录属于加密签名配置，只有 authority 可修改；`NetworkHandle` 本地解析且永不查询系统 DNS，配置传播后现有 connector 自动看到新记录。

## 2. 总体架构

```text
weaver-relay (standalone process)
  ├─ authority: init / invite / signed config commits
  ├─ bootstrap + encrypted config replication
  ├─ opaque presence
  └─ data-relay: encrypted packet forwarding
                  │
                  ▼
Application
  │
  ├─ NetworkStore::prepare_join/join/open
  │       └─ NetworkHandle (exactly one NetworkId)
  │
  ├─ VirtualTcpListener / VirtualTcpStream
  └─ VirtualUdpSocket
          │
          ▼
  ServiceRegistry + ACL + Virtual Address Resolver
          │
          ▼
  PeerSessionManager ───── Config/Presence Replicator
          │                         │
          ▼                         ▼
  Per-network iroh Endpoint   Injected state + secret stores
      │          │                  │
      │          ├─ private presence directory
      │          └─ protected LAN discovery
      │
      ├─ direct UDP paths (LAN/WAN)
      └─ iroh relay paths
```

硬隔离点位于 `NetworkHandle`：所有向下调用必须携带内部 `NetworkContextId`，而不是依赖调用者传对 `NetworkId`。地址、peer session、listener、datagram 队列和任务都由该 handle 拥有。跨网络对象不能互相转换。

## 3. Rust workspace 划分

```text
weaver/
  Cargo.toml
  crates/
    weaver-core/             # ID、地址、错误、时钟、协议常量
    weaver-crypto/           # 签名、HPKE、AEAD、凭据校验
    weaver-config/           # 配置模型、哈希链、epoch、传播协议
    weaver-store/            # 公共存储 SPI、redb 默认实现、内存测试实现
    weaver-discovery/        # presence cache、LAN tag、AddressLookup
    weaver-transport-iroh/   # Endpoint、Router、PeerSession、路径事件
    weaver-net/              # 对外 Tokio 风格 API
    weaver-relay-core/       # authority、bootstrap、presence、data-relay 角色实现
    weaver-relay/            # 独立二进制：init/serve/invite/authorize-relay/status
    weaver-cli/              # 应用节点 join/status/doctor；不持有网络管理权威
    # Android 直接复用上述平台无关 crate；无专用 JNI crate
    weaver-testkit/          # 虚拟时钟、故障注入、拓扑测试工具
  apps/
    echo-server/
    echo-client/
    android-smoke/
  deploy/
    relay/
    docker-compose.yaml
```

依赖方向必须单向：

```text
core <- crypto <- config <- discovery <- transport-iroh <- net
                    ^             ^              ^
                    └── store ────┘              └── android
                    └── relay-core <- relay
```

`weaver-core` 和 `weaver-crypto` 不依赖 iroh，避免把产品身份模型绑死到单一传输实现。

### 3.1 关键依赖

建议第一版固定精确版本并由 Dependabot/Renovate 单独升级：

```toml
[workspace.package]
edition = "2024"
rust-version = "1.91"

[workspace.dependencies]
iroh = { version = "=1.0.3", default-features = false, features = ["metrics", "portmapper", "tls-ring"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time", "net", "io-util"] }
bytes = "1"
serde = { version = "1", features = ["derive"] }
postcard = { version = "1", features = ["use-std"] }
blake3 = "1"
ed25519-dalek = "3.0.0-rc.1"
x25519-dalek = "2"
chacha20poly1305 = "0.10"
hpke = "0.13"
hmac = "0.12"
sha2 = "0.10"
hkdf = "0.12"
redb = "3"
zeroize = "1"
secrecy = "0.10"
tracing = "0.1"
thiserror = "2"
```

版本号是起始建议，不应在未经 `cargo tree -d`、Android 编译和安全审计的情况下直接发布。`postcard` 只用于无 map、固定字段顺序的版本化 wire struct；签名验证针对收到的原始 payload bytes，禁止“反序列化后重新编码再验签”。

## 4. 身份、地址与密钥

### 4.1 域分离的 ID

所有派生都使用 BLAKE3 域分离：

```text
NetworkId = BLAKE3("weaver.network.v1" || network_root_public_key)
MemberId  = BLAKE3("weaver.member.v1"  || NetworkId || member_sign_public_key)
AppAddr   = BLAKE3("weaver.app.v1"     || app_root_public_key)
DeviceId  = BLAKE3("weaver.device.v1"  || NetworkId || AppAddr || member_sign_public_key)
ServiceId = BLAKE3("weaver.service.v1" || canonical_service_name)[0..16]
```

结果：

- 同一个 `AppAddr` 可以出现在不同网络中；完整地址仍因 `NetworkId` 不同而完全隔离，所有 app registration/binding 也必须分别由各网络授权。
- 同一设备在两个网络或两个应用中得到不同 `DeviceId`。
- 人类名称不参与认证；别名由签名配置映射到 `AppAddr`。

### 4.2 每个网络的密钥集合

```rust
struct NetworkSecrets {
    member_signing: Ed25519SecretKey,
    member_encryption: X25519SecretKey,
    endpoint: iroh::SecretKey,
}
```

- `member_signing`：签署 endpoint binding、presence 和运行时公告。
- `member_encryption`：接收 HPKE 封装的配置内容密钥。
- `endpoint`：仅用于 iroh QUIC/TLS 身份。
- 三把密钥必须独立生成，不能从同一个种子用未审计方式直接切片。
- 网络根密钥和应用根密钥默认不存放在普通客户端；普通节点只保存短期或可撤销凭据。

### 4.3 凭据结构

```rust
struct MemberCertificateV1 {
    network_id: NetworkId,
    member_id: MemberId,
    signing_public_key: [u8; 32],
    encryption_public_key: [u8; 32],
    roles: RoleSet,
    serial: u64,
    not_before_ms: u64,
    expires_at_ms: u64,
    issuer_key_id: KeyId,
    issuer_signature: Signature,
}

struct EndpointBindingV1 {
    network_id: NetworkId,
    member_id: MemberId,
    endpoint_id: iroh::EndpointId,
    sequence: u64,
    expires_at_ms: u64,
    member_signature: Signature,
}

struct AppRegistrationV1 {
    network_id: NetworkId,
    app_addr: AppAddr,
    app_root_public_key: [u8; 32],
    policy: AppPolicy,
    admin_signature: Signature,
}

struct AppBindingV1 {
    network_id: NetworkId,
    app_addr: AppAddr,
    subject: MemberId,
    role: AppRole, // Server 或 Client
    device_id: Option<DeviceId>,
    services: Vec<ServiceId>,
    expires_at_ms: u64,
    app_root_signature: Signature,
}
```

校验顺序固定为：网络根/管理键 → 成员证书 → endpoint binding → app registration → app binding。任一步失败都不能把连接交给应用。

## 5. 网络配置格式与加密

### 5.1 权威配置

```rust
struct NetworkConfigV1 {
    network_id: NetworkId,
    epoch: u64,
    revision: u64,
    previous_hash: [u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,

    admin_keys: Vec<AdminKey>,
    members: Vec<MemberCertificateV1>,
    revoked_serials: Vec<u64>,
    apps: Vec<AppRegistrationV1>,
    app_bindings: Vec<AppBindingV1>,
    relays: Vec<RelayDescriptor>,
    presence_services: Vec<PresenceServiceDescriptor>,
    epoch_secrets: EpochSecrets,
    policies: NetworkPolicy,
}
```

`EpochSecrets` 包含独立的 presence 索引、presence 加密、LAN discovery 和 relay access 派生种子。它们通过 HKDF 使用不同 label 派生，不得直接复用 `K_config`。撤销成员并提升 epoch 时同步轮换这些 secret。

第一版采用 authority relay 持有 online admin key 的单写入者顺序提交：

- `revision` 每次加一。
- `previous_hash` 指向上一版本原始 payload 的哈希。
- 相同 revision 出现两个合法签名的不同 hash 时进入 `Forked`，停止自动应用并报警。
- 每 128 个 revision 生成完整 snapshot；中间可以使用 delta，但持久化始终能够从最近 snapshot 重放。
- 单个 snapshot 默认上限 1 MiB，成员默认上限 256；超过后先重新评估 O(N) 密钥封装方案。

### 5.2 配置 envelope

每个 epoch 生成随机 256-bit `ConfigEpochKey`：

```rust
struct EncryptedConfigEnvelopeV1 {
    format_version: u16,
    epoch: u64,
    revision: u64,
    previous_hash: [u8; 32],
    payload_hash: [u8; 32],
    nonce: [u8; 24],
    ciphertext: Vec<u8>,              // XChaCha20-Poly1305
    member_key_wraps: Vec<KeyWrap>,   // anonymous HPKE wraps to active members
    signer_key_id: KeyId,
    signature: Signature,
}
```

处理过程：

1. 随机生成内容密钥 `K_config`。
2. 用 XChaCha20-Poly1305 加密 `NetworkConfigV1`。
3. 对每个有效成员的 X25519 公钥使用 HPKE 封装 `MemberEpochSecrets { K_config, member_presence_write_capabilities }`；每个成员只得到自己的写入 capability。
4. 管理密钥对 envelope header、ciphertext 和 wraps 的原始编码签名。
5. 任意成员可以原样缓存和转发 envelope；只有列入 wraps 的成员能够解密。
6. 撤销成员时提升 epoch、生成新 key，并从 wraps 中移除被撤销成员。

`KeyWrap` 不携带明文 `MemberId`。成员按固定随机顺序尝试解封装，成功后停止；在第一版 256 成员上限内接受这项低频 O(N) 成本，从而避免只观察 envelope 就得到成员清单。

这个方案是 O(N)，但简单、可审计且天然支持撤销。规模超过约 256 个活跃成员时，再评估 MLS；第一版不自行设计树形群组密钥协议。

边界：任何当前有效成员都能看到网络配置明文，因此无法阻止恶意成员在应用层截图、复制或转交明文。epoch 轮换保证的是外部观察者和已撤销成员不能解密未来配置，不提供历史数据追溯删除。

## 6. Relay 初始化与应用加入网络

### 6.1 由独立 relay 初始化网络

应用库没有 `NetworkStore::create`。创建网络是部署/管理动作，只能在独立二进制上执行：

```bash
weaver-relay init \
  --data-dir /var/lib/weaver/network-a \
  --relay-url https://relay.example.com \
  --listen 0.0.0.0:443 \
  --admin-listen 127.0.0.1:9443 \
  --recovery-out ./network-a-recovery.age \
  --recovery-recipient age1example...

weaver-relay serve --data-dir /var/lib/weaver/network-a
```

`init` 必须原子完成：

1. 生成 network root key、online admin key，以及 relay 自己的成员、加密和 iroh endpoint 密钥。
2. 从根公钥派生 `NetworkId`，创建管理员证书、relay 成员证书和 revision 0 配置。
3. 将首个进程配置为 `combined`，同时承担 `authority + bootstrap + presence + data-relay`。
4. 将根密钥导出为加密 recovery bundle；运行目录仅保留可轮换的 online admin key，并以严格文件权限保存。
5. 写入并 fsync 数据库、配置和 recovery 输出；任一步失败都不留下可被 `serve` 误认为有效的半初始化网络。

同一二进制支持 `--roles authority,data-relay,bootstrap,presence`。第一版首个 relay 默认 `combined`，附加公网节点推荐仅运行 `data-relay,bootstrap,presence`。纯 `data-relay` 只看见传输元数据和密文；`authority` 会解密并签署网络配置，因此 combined 主机属于控制面可信计算基。若要求 relay 托管方完全看不到拓扑，应把 authority 部署在自有主机，将公网 relay 设为纯数据角色。

网络也可以显式以零数据中继模式初始化：`weaver-relay init --roles authority --no-data-relay ...`。此时配置中的 relay 列表为空，authority 可在 provisioning 完成后退出；它仍是建网工具，但不是持续运行的转发节点。

管理接口默认只绑定 loopback 或 Unix domain socket；远程启用时必须使用独立 mTLS 管理身份，不与成员票据或业务端点凭据复用。

应用地址注册同样走 authority 管理事务，而不是由运行中的应用节点直接改网络配置。应用所有者离线生成由 app root key 签名的 `AppRegistrationRequest`，再执行：

```bash
weaver-relay app register --data-dir /var/lib/weaver/network-a \
  --request app-registration.war
```

relay 验证 app root 签名并把 `AppRegistrationV1` 提交到下一配置 revision；服务端和客户端运行时只保存各自的 app binding，不要求携带 app root key。

### 6.2 增加 relay 节点

新增 relay 先生成自己的网络专用密钥和请求，再由 authority 授权：

```bash
weaver-relay request --data-dir /var/lib/weaver/relay-2 --out relay-2.wrr
weaver-relay authorize-relay --data-dir /var/lib/weaver/network-a \
  --request relay-2.wrr --roles data-relay,bootstrap,presence \
  --out relay-2.wrt
weaver-relay join --data-dir /var/lib/weaver/relay-2 --ticket relay-2.wrt
weaver-relay serve --data-dir /var/lib/weaver/relay-2
```

authority 先把新 `RelayDescriptor`、访问凭据和端点绑定提交到新的配置 revision，再签发引用该 revision/hash 的 relay ticket。纯数据 relay 不获得 `ConfigEpochKey`；兼任 bootstrap/presence 的 relay 只保存其角色所需的 capability，不因此获得写配置权限。

### 6.3 生成应用节点 JoinTicket

为了确保 ticket 绑定实际加入设备，应用先本地生成网络专用候选密钥和自签名 endpoint binding：

```rust
let pending = NetworkStore::builder()
    .state_store(state_store)
    .secret_store(secret_store)
    .prepare_join()
    .await?;

pending.export_request("device.wjr").await?;
```

网络管理员在 authority relay 上签发邀请：

```bash
weaver-relay invite --data-dir /var/lib/weaver/network-a \
  --request device.wjr --role member --expires 10m --out device.wjt
```

`invite` 必须先验证候选 endpoint binding，再以一个原子管理事务创建包含新成员证书、endpoint binding 和 HPKE wrap 的配置 revision，最后生成引用该 revision/hash 的 ticket。普通成员能校验和转发票据对应的配置，但不能签发票据或提交配置。

`JoinTicketV1` 包含：

- `NetworkId` 和 network root public key。
- 候选 member signing/encryption public keys、iroh EndpointId 和由候选 member key 签署的 endpoint binding。
- 预签发 `MemberCertificateV1`。
- 至少一个 bootstrap `EndpointAddr`；它是唯一必须在加入前泄露的路径信息。
- 目标配置 revision/hash、有效期、唯一 nonce 和管理员签名。
- 可选的 `EmbeddedConfigUpdate`：候选成员可解密的已签名 snapshot/delta，用于零 relay、authority 离线或 bootstrap 成员尚未取得目标 revision 的场景。

### 6.4 加入

```rust
let network = NetworkStore::builder()
    .state_store(state_store)
    .secret_store(secret_store)
    .join(ticket, pending)
    .await?;
```

线上序列：

```text
Candidate                    Any existing member
    │                                  │
    │── iroh connect using ticket ────>│
    │<─ verify transport EndpointId ───│
    │── JoinHello(ticket, proof,       │
    │             config update?) ────>│
    │                                  ├─ verify/apply newer signed config
    │                                  ├─ verify root/admin/member cert
    │                                  ├─ verify key possession + expiry
    │<─ JoinAccept(config head) ───────│
    │── GetConfig(revision/hash) ─────>│
    │<─ encrypted snapshot/deltas ─────│
    │── ConfigApplied(hash) ──────────>│
    │<─ presence endpoints/peers ──────│
```

只有配置成功验签、解密并原子落盘后，`join()` 才返回 `NetworkHandle`。引导连接断开不回滚已经提交的成员状态。

加入时先用候选节点已经生成的网络专用 endpoint key 建立最小 iroh endpoint，并只配置 ticket 内的显式 bootstrap 路径。取得配置后，在同一个 endpoint 上通过 `insert_relay` 等动态接口加入正式 relay，避免因为重建 endpoint 改变 `EndpointId`。

### 6.5 两节点、零 data-relay 模式

零中继网络的运行期可以只有一个服务端应用节点和一个客户端应用节点：

1. 服务端先执行 `prepare_join`，管理员用 `weaver-relay init --roles authority --no-data-relay --first-member-request server.wjr` 生成网络和服务端 provisioning bundle。
2. 服务端导入 bundle，成为首个成员并监听服务；authority 无需持续在线。
3. 客户端生成 request；管理员执行 `weaver-relay invite --embed-config --bootstrap <server-endpoint-addr>`。
4. 客户端利用 ticket 中的服务端 EndpointId、直连地址或受保护 LAN join tag 建连，并把更新后的签名配置一并提交给服务端。
5. 服务端验签并原子应用新 revision 后认证客户端，双方直接建立 QUIC connection，不经过 data-relay。

这个模式只保证“存在直连路径时可工作”。同一 LAN 通常可通过显式地址或受保护 mDNS 建连；跨公网时至少一端必须可公开访问或已有有效端口映射。若双方都在不可穿透 NAT 后、UDP 被阻断，或唯一直接路径消失，则没有任何基础设施可以转发，连接必然失败或在超时后关闭。这是网络可达性的物理限制，不应伪装成实现缺陷。

### 6.6 Authority 离线语义

- 已加入成员继续使用最后一个有效配置，并可相互传播 snapshot/delta；现有直连和 data-relay 转发不依赖 authority 在线。
- 引用已提交 revision 且仍在有效期内的预签 ticket，可以经任一已同步成员完成加入。
- authority 离线期间不能签发新票据、撤销成员、注册应用或改变 relay 列表；这些操作必须明确失败，不能由普通成员临时接管。
- recovery bundle 可在受控流程中恢复或替换 authority。第一版坚持单写入者，不实现自动选主。

## 7. 配置传播协议

在成员 session 内预留 control stream，消息采用长度前缀的 postcard frame：

```rust
enum ConfigMessageV1 {
    Head { epoch: u64, revision: u64, hash: [u8; 32] },
    GetRange { from_revision: u64, max_items: u16 },
    Envelopes(Vec<EncryptedConfigEnvelopeV1>),
    GetSnapshot { at_or_after: u64 },
    Snapshot(EncryptedConfigEnvelopeV1),
    Ack { revision: u64, hash: [u8; 32] },
}
```

传播规则：

- 新 session 建立后双方交换 `Head`。
- 落后不超过 128 个 revision 时拉 delta，否则拉 snapshot。
- 每 30 秒随机选择最多 3 个在线成员做 anti-entropy；收到新 head 时立即拉取，不等待周期任务。
- frame 上限 1.25 MiB、range 上限 128，超限关闭 control stream。
- 数据落盘流程为 `verify signature -> verify chain -> unwrap key -> decrypt -> validate invariants -> transaction commit -> publish watch event`。
- 普通成员不能创造新 revision；收到无管理签名的“更新”直接丢弃并计安全指标。

## 8. 私有发现与 presence

### 8.1 AddressLookup 实现

实现 `WeaverAddressLookup` 并挂到每个网络的 iroh endpoint：

```rust
struct WeaverAddressLookup {
    network: Weak<NetworkRuntime>,
    cache: PresenceCache,
    lan: LanDiscovery,
    remote: OpaquePresenceClient,
}
```

`resolve(endpoint_id)` 合并并流式返回：

1. ticket 中的 bootstrap hint。
2. 本地已验证缓存。
3. LAN discovery 结果。
4. 网络配置指定的 opaque presence 服务。
5. 其他在线成员通过 control stream 返回的临时公告。

iroh 的 `AddressLookup::publish` 会在本机 endpoint 地址变化时被调用，Weaver 在其中签署并发布新的 presence；Android 网络切换还会显式调用 `Endpoint::network_change()`。

`resolve()` 返回的不是一次性 future，而是该 remote 存活期间保持打开的订阅 stream：先发缓存结果，后续 presence/mDNS 发现新地址时继续 yield。iroh 1.0.3 的 remote actor 会持续轮询正在运行的 address-lookup stream，并把后续地址加入 path state；如果 stream 提前结束，而当前已有 selected path，则不会为了普通更新自动重启 lookup。因此 Weaver 只有在订阅取消或 endpoint 关闭时才结束该 stream。这个行为必须用固定版本源码测试锁定，iroh 升级时作为兼容门禁。

### 8.2 PresenceRecord

```rust
struct PresenceRecordV1 {
    endpoint_binding: EndpointBindingV1,
    transport_addrs: Vec<TransportAddr>,
    sequence: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
    signature: Signature,
}
```

- presence key：`HMAC-SHA256(K_index, endpoint_id)[0..24]`。
- presence value：用 `K_presence` 加密后的 record。
- 默认 TTL 120 秒，每 45 秒刷新；离线缓存最多保留 10 分钟，仅作为尝试候选。
- presence 服务只能看到不透明 key、ciphertext、来源 IP 和流量时序。
- 签名在密文内部，解密后仍需验证成员证书、endpoint binding、sequence 和 TTL。

### 8.3 LAN discovery

- mDNS service type 固定为 `_weaver._udp.local`，不把网络名放入 service type。
- TXT 仅发布 `v=1` 和轮换 tag：

```text
tag = HMAC(K_lan, five_minute_slot || endpoint_id)[0..16]
```

- 成员根据配置中的已知 EndpointId 计算当前和相邻时间片的 tag，匹配后把 mDNS 返回的 socket 地址喂给本网络 `AddressLookup`。
- 非成员只能看到短期随机 tag 和本来就可观察到的 LAN IP，无法从 tag 得到 `NetworkId/AppAddr/DeviceId`。

### 8.4 Opaque presence 服务

`weaver-relay` 在 iroh relay 之外增加一个无业务语义的 TTL blob API：

```text
PUT /v1/presence/{opaque-key}   body: ciphertext, If-Match: sequence
GET /v1/presence/{opaque-key}   -> ciphertext + expiry
DELETE /v1/presence/{opaque-key}
```

- GET 使用配置 epoch 中的网络读取 capability；PUT/DELETE 使用绑定单个 opaque key 的成员写入 capability，防止一个合法成员覆盖其他成员的 presence。服务端只保存 capability hash，并把它们视为不透明权限域。
- relay 能关联同一读取 capability 下的请求以及同一写入 capability 的更新，但不知道 `NetworkId`、成员地址或 record 内容。
- 读取 capability、成员写入 capability、opaque-key seed 和 value encryption key 在成员撤销时随 epoch 轮换；新 epoch 使用新 opaque key，旧成员删除旧记录不会影响新记录。
- 服务端只校验鉴权、大小、sequence 条件和 TTL，不解析 ciphertext。
- 存储可以先用内存 + redb 单机实现；HA 部署使用 Redis/兼容 KV 保存短 TTL blob，relay 转发面本身仍保持无业务状态。

## 9. iroh 传输集成

### 9.1 Endpoint 构造

每个活跃网络独立构造：

```rust,no_run
let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
    .secret_key(network_secrets.endpoint.clone())
    .relay_mode(iroh::endpoint::RelayMode::Custom(relay_map))
    .address_lookup(weaver_address_lookup)
    .hooks(NetworkEndpointHooks::new(auth_snapshot))
    .alpns(vec![ALPN_JOIN.to_vec(), ALPN_SESSION.to_vec()])
    .bind()
    .await?;
```

不使用 `presets::N0`，因为它会配置公共 relay 和 DNS/Pkarr address lookup。relay map 只能来自已验证网络配置，bootstrap 阶段则使用 ticket 内的显式 `EndpointAddr`。

### 9.2 ALPN

```text
weaver/join/1       # 仅用于持 JoinTicket 的未加入节点
weaver/session/1    # 已有成员的业务、配置和 presence session
```

`NetworkId` 和 `ServiceId` 不放进 ALPN。每个网络已有独立 endpoint；service 在加密的 stream header 中分发，避免增加连接数量和泄露应用拓扑。

### 9.3 连接准入

`EndpointHooks` 分两层使用：

- `before_connect`：检查目标 EndpointId 是否来自当前网络 resolver，阻止本地代码误拨其他网络。
- `after_handshake`：对 `weaver/session/1` 检查远端 EndpointId 是否存在于当前有效 endpoint binding；否则立刻 reject。
- `weaver/join/1` 允许未知 EndpointId 完成 QUIC 握手，但只开放严格限速的 join handler，且必须在读取任何配置前验证 ticket。

随后 session control stream 再完成 `MemberCertificate + EndpointBinding + nonce signature` 认证。只有两层都通过才创建 `PeerSession`。

### 9.4 PeerSession 与连接去重

```rust
struct PeerSession {
    peer: MemberId,
    endpoint_id: EndpointId,
    connection: iroh::endpoint::Connection,
    state: watch::Receiver<SessionState>,
    datagram_rx: broadcast::Sender<ReceivedDatagram>,
}
```

- 每个网络、每个远端 EndpointId 最多保留一个主 session。
- 双方同时拨号时，以较小 EndpointId 作为规范发起方：保留由规范发起方建立的连接，另一条在没有应用 stream 后优雅关闭。
- 关闭重复连接前先等待主连接完成成员认证，避免两个连接都被关闭。
- 订阅 `Connection::paths_stream()`/`path_events()`，更新 `Relay/DirectLan/DirectWan/Mixed` 状态和迁移指标。
- path 变化不替换 `PeerSession` 或 stream；只有 QUIC connection 关闭才进入 reconnect/error 路径。

### 9.5 本地服务端 A、远程 relay B、客户端 C

这是第一版的标准部署拓扑，不需要 relay chaining：

```text
                     direct LAN/WAN
              ┌────────────────────────┐
              │                        │
              ▼                        │
      A service endpoint               C client endpoint
              │                        │
              └──────► B relay ◄───────┘
                    outbound sessions
```

1. A 即使位于 NAT 后也主动维持到 B 的 relay session，并发布签名的 `EndpointId + B RelayUrl + short-lived direct candidates`。
2. C 解析 A 的虚拟应用地址后，同时获得 A 的 EndpointId、B 和允许公开的直连候选；同 LAN 时，受保护 mDNS 追加 A 的 LAN 地址。
3. C 优先验证直连候选。直连尚不可用时，C 连接 B，B 因 A 已连接而把 A↔C 的加密 QUIC 包双向转发。
4. A 与 C 的 QUIC/TLS 身份直接互验；B 只看到 EndpointId、IP、时序和流量大小，不解密业务载荷。
5. C 后续进入 A 所在 LAN 时，`network_change()` 和持续的 `AddressLookup` 提供 LAN candidate；iroh 在原 connection 内验证新路径并优先切到直连。B 保持后备，直连失效时再回退。
6. 若 A 与 C 之间从一开始就存在直连路径，可以不经过 B 传业务数据；A 到 B 的连接仍可作为后备可达性路径。

第一版只支持“双方连接同一 B”或直接 A↔C，不实现 `C -> local relay -> B -> A`。同 connection 的 relay↔direct 迁移仍是固定 iroh 版本的 Go/No-Go 实测项，不能只凭 API 存在认定通过。

## 10. 虚拟 TCP 实现

### 10.1 Stream wire header

每条新 QUIC bi stream 首先发送：

```rust
struct OpenStreamV1 {
    protocol_version: u16,
    source: ScopedVirtualAddr,
    destination: ScopedVirtualAddr,
    service: ServiceId,
    app_binding_hash: [u8; 32],
    request_id: u64,
}

enum OpenResultV1 {
    Accepted,
    NoListener,
    NotAuthorized,
    AddressMismatch,
    UnsupportedVersion,
    Busy,
}
```

接收端先读有界 header，验证来源/目标 app binding 和 listener ACL，返回 `Accepted` 后才把 stream 放入 listener queue。业务字节绝不能在 `Accepted` 前交付。

### 10.2 公共 API

```rust
impl NetworkHandle {
    pub async fn bind_tcp(
        &self,
        local: ServerAddr,
        service: ServiceId,
        policy: AcceptPolicy,
    ) -> Result<VirtualTcpListener>;

    pub async fn bind_client(
        &self,
        local: ClientAddr,
        credential: AppBinding,
    ) -> Result<ClientEndpoint>;
}

impl ClientEndpoint {
    pub async fn connect(
        &self,
        remote: ServerAddr,
        service: ServiceId,
    ) -> Result<VirtualTcpStream>;
}

impl tokio::io::AsyncRead for VirtualTcpStream { /* delegate RecvStream */ }
impl tokio::io::AsyncWrite for VirtualTcpStream { /* delegate SendStream */ }
```

`VirtualTcpStream` 内部持有 iroh `RecvStream + SendStream + Arc<PeerSession>`。`poll_shutdown` 调用 QUIC stream finish，而不是关闭整个 peer connection。drop 时 reset 未完成的当前 stream，不影响同 connection 中的其他应用流。

### 10.3 错误映射

```rust
enum NetworkError {
    NetworkMismatch,
    NotMember,
    Revoked,
    AddressNotFound,
    NotAuthorized,
    NoListener,
    DatagramTooLarge { max: usize },
    ConnectionLost,
    TimedOut,
    ProtocolViolation,
    ConfigFork,
    ShuttingDown,
}
```

不要把所有错误压成 `std::io::ErrorKind::Other`。trait 方法返回 `io::Error` 时把稳定的 `NetworkError` 放入 error source；构造、bind、connect 和地址解析 API 直接返回 typed error。

## 11. 虚拟 UDP 实现

```rust
impl NetworkHandle {
    pub async fn bind_udp(
        &self,
        local: ScopedVirtualAddr,
        service: ServiceId,
        options: UdpOptions,
    ) -> Result<VirtualUdpSocket>;
}

impl VirtualUdpSocket {
    pub async fn connect(&self, peer: ScopedVirtualAddr) -> Result<()>;
    pub async fn send(&self, bytes: &[u8]) -> Result<usize>;
    pub async fn send_to(&self, bytes: &[u8], peer: ScopedVirtualAddr) -> Result<usize>;
    pub async fn recv_from(&self, out: &mut [u8]) -> Result<(usize, ScopedVirtualAddr)>;
}
```

datagram header：

```rust
struct DatagramV1 {
    version: u8,
    source: ScopedVirtualAddr,
    destination: ScopedVirtualAddr,
    service: ServiceId,
    payload: Bytes,
}
```

- 发送前减去 header 后再检查 `Connection::max_datagram_size()`。
- `send_to` 首次调用可以异步建 session；如果使用非 async `try_send_to`，无 session 时返回 `WouldBlock`。
- 每个 socket 使用有界 MPSC 接收队列；满时丢弃新包并增加指标，不挤掉已经交付排序中的旧包。
- source 必须由当前已认证 session 和 app binding 推导；忽略 wire 中任何与 session 不一致的来源声明。
- 第一版只做单播，不实现广播和组播。

## 12. 本地存储

### 12.1 边界与默认实现

存储是必需能力，但不硬编码成应用无法控制的私有数据库：

- `weaver-net` 只依赖公开的 `StateStore` 和 `SecretStore` SPI；宿主应用可以注入自己的实现。
- SDK 同时提供 `RedbStateStore`、平台默认 `SecretStore` 和仅测试使用的 `MemoryStateStore`，保证不接入自定义存储也能直接运行。
- 独立 `weaver-relay` 默认在 `--data-dir` 中使用 `RedbStateStore`，并使用操作系统密钥库或加密 key file 保护秘密；relay 管理事务不允许使用内存存储。
- 自定义实现只接管持久化机制，不接管编码、验签、加密、迁移或业务规则。上层看到的是带版本的 opaque bytes，不能伪造“已验证”对象。

普通状态与秘密材料必须使用两个接口，不能把私钥作为普通 KV value 交给应用数据库：

```rust
#[async_trait]
pub trait StateStore: Send + Sync + 'static {
    async fn read(&self, scope: StoreScope, key: StoreKey)
        -> Result<Option<VersionedBytes>, StoreError>;

    async fn scan_prefix(&self, scope: StoreScope, prefix: StorePrefix)
        -> Result<BoxStream<'static, Result<StoredEntry, StoreError>>, StoreError>;

    async fn commit(&self, batch: AtomicBatch)
        -> Result<CommitVersion, StoreError>;
}

#[async_trait]
pub trait SecretStore: Send + Sync + 'static {
    async fn seal(&self, id: SecretId, plaintext: SecretBytes)
        -> Result<(), SecretStoreError>;
    async fn open(&self, id: &SecretId)
        -> Result<SecretBytes, SecretStoreError>;
    async fn delete(&self, id: &SecretId)
        -> Result<(), SecretStoreError>;
}
```

`AtomicBatch` 支持 `Put/Delete + expected version/nonexistence` 前置条件。实现必须保证单批次原子性、进程崩溃后全有或全无、成功返回前达到 durable commit，并提供同一 scope 内的 read-your-writes。配置 head、对应 envelope、ticket nonce 状态和 epoch 指针依赖同一次提交，不能用多个普通 `put()` 拼接。SDK 启动时执行 schema version 检查和由 Weaver 提供的迁移；版本过新必须拒绝打开。

两个 store 之间无法假设分布式事务。新秘密采用“先以随机 `SecretId` seal 并回读确认，再原子提交引用”的顺序；崩溃最多留下无引用 secret，由启动 GC 在宽限期后删除。删除或轮换采用“先提交不再引用，再延迟删除 secret”，从而绝不产生已提交状态指向缺失密钥的窗口。`seal` 对同一 ID 必须幂等，且禁止用不同内容覆盖已有 ID。

`StoreScope` 由库从内部 `NetworkContextId` 构造，不接受应用随意传入裸字符串。多网络共用一个物理数据库时也必须分 namespace；relay authority 的管理状态使用独立 scope。

### 12.2 持久与临时数据

必须持久化：成员/endpoint 身份引用、`DeviceId`、证书、已验签的配置 envelope 与 current head、应用注册与绑定、epoch、撤销状态、authority 的 ticket nonce/管理序列，以及恢复同一 `EndpointId` 所需的 wrapped secret。只保存在内存或可丢弃缓存：活动 QUIC connection、stream/datagram 队列、LAN 候选、短 TTL presence、RTT/path 评分和派生后的明文会话密钥。

业务文档、CRDT、消息、文件和“断线后恢复同一应用字节流”的游标不属于网络层存储；由上层 local-first 应用自行持久化。

默认逻辑表：

```text
networks          NetworkId -> metadata/current head
config_envelopes  (NetworkId, revision) -> exact signed bytes
members           (NetworkId, MemberId) -> validated certificate
apps              (NetworkId, AppAddr) -> registration/bindings
endpoint_bindings (NetworkId, EndpointId) -> signed binding
join_tickets      ticket nonce -> issued/consumed/revoked/expiry (authority only)
secrets           opaque key id -> encrypted secret blob
```

presence cache 默认不持久化；如果自定义实现为了冷启动持久化，只能保存收到的加密原文和 expiry，且过期即删。

### 12.3 SecretStore 平台实现

- Android：本仓库只定义 `SecretStore` 注入边界；宿主可选择 Android Keystore wrapping。Rust 私钥使用时仍会进入进程内存，因此即使宿主采用 Keystore wrapping，也不是硬件内不可导出签名。
- Windows：DPAPI user scope，生产可选 TPM-backed CNG 扩展。
- macOS：Keychain。
- Linux：Secret Service；不可用时要求用户提供 passphrase，不允许无提示明文降级。

无桌面 keyring 的 relay 主机默认使用加密 key file，并从交互输入、受限文件描述符或外部 secret provider 获取解锁材料；不得把解锁口令写进同一 `--data-dir`。生产可扩展 HSM/KMS provider。

所有私钥容器使用 `zeroize`，日志类型手写 `Debug`，禁止 derive 后输出 secret bytes。

应用注入的 `SecretStore` 若无法提供系统级保护，必须返回明确的 capability/降级状态；生产配置默认拒绝 plaintext 实现。备份与恢复由上层显式触发，默认不把设备私钥同步到云备份。

## 13. Android 集成边界

Weaver 不提供专用 `weaver-android`、JNI/CDylib 或 Kotlin 包装。首批 Android
支持定义为核心客户端 crate 能以 NDK 为 `aarch64-linux-android` 构建。宿主应用
自行选择 UniFFI、JNI、Rust Activity 或其他集成方式，并通过现有 `StateStore`、
`SecretStore` 接口注入平台存储。

网络变化入口保持平台无关：宿主可在 Android 网络回调后调用
`WeaverEndpoint::network_change().await`，触发 iroh 地址重发、发现更新和路径探测。
本仓库不直接依赖 `ConnectivityManager`，也不规定前台服务、Doze 或 Keystore 策略。

固定构建验收命令使用 NDK r27c、API 24 和 `arm64-v8a`；更高 API level 也必须
保持兼容，但 x86_64、armeabi-v7a 和 Android 真机验收不属于首批门槛。

## 14. 后台状态机

### 14.1 NetworkRuntime

```text
Closed
  └─ open/join → Loading
       ├─ invalid/revoked → Rejected
       └─ valid → StartingEndpoint
            ├─ relay unavailable → Degraded
            └─ ready → Online
                         ├─ config expired → ReadOnlyDegraded
                         ├─ member revoked → Revoked → Closed
                         └─ shutdown → Draining → Closed
```

### 14.2 PeerSession

```text
Resolving → Connecting → TransportAuthenticated
    → MembershipAuthenticated → Ready
         ├─ path change → Ready
         ├─ all paths stalled → Degraded
         ├─ QUIC closed → Closed
         └─ peer revoked → Closing → Closed
```

路径变化不触发 session 状态回到 `Connecting`；只有整个 QUIC connection 死亡才关闭已有虚拟 stream。

## 15. 资源与限制

- 第一版默认最多同时激活 8 个虚拟网络；更多网络保持休眠，只保留加密配置和 secrets，不维持 endpoint/relay 连接。
- 每网络默认最多 256 个成员、64 个活跃 peer session、1024 条并发虚拟 TCP stream。
- 每 peer 默认最多 4 MiB 总接收窗口；配置和业务分别限流。
- join handler 每 IP 与每 endpoint ID 限速，最大并发 8，ticket header 最大 16 KiB。
- relay presence value 最大 16 KiB，TTL 最大 5 分钟。
- 所有限制都可配置，但提高限制必须同步评估内存和 DoS 面。

## 16. 实施阶段

### 阶段 0：仓库与协议骨架（约 1 周）

- 建 workspace、CI、lint、依赖锁定和 cargo-deny。
- 实现 ID、wire version、错误类型和 golden vectors。
- 建立可启动的独立 `weaver-relay` 二进制与 `init/serve` 命令骨架。
- 从第一周持续执行 Android arm64 NDK 交叉编译。

通过标准：桌面测试和 Android `arm64-v8a` 构建通过，wire golden vectors 稳定。

### 阶段 1：身份、配置和存储（约 2 周）

- 实现证书链、配置 envelope、HPKE wraps 和哈希链。
- 实现 `StateStore`/`SecretStore` SPI、redb 默认实现、原子提交与 crash recovery 测试。
- 实现 relay `init/invite` 与 SDK `prepare_join/join` 的纯内存 transport 测试。
- 验证应用注入的 `SecretStore` 不依赖桌面专用 API，并保持 Android arm64 可编译。

通过标准：篡改、回滚、错误网络、撤销成员、重复 ticket 和 crash recovery 测试通过。

### 阶段 2：iroh session 与配置传播（约 2 周）

- 每网络 Endpoint、hooks、join/session ALPN、PeerSession 去重。
- 任意成员 bootstrap、snapshot/delta、anti-entropy。
- relay authority 完成初始化、邀请和配置提交；桌面端完成申请、加入和配置更新，Android arm64 构建保持通过。

通过标准：关闭原 bootstrap 后，新成员仍能从其他节点追平配置；跨网络握手全部拒绝。

### 阶段 3：虚拟 TCP/UDP（约 2 周）

- listener registry、stream header、ACL、AsyncRead/AsyncWrite wrapper。
- connected/unconnected virtual UDP、队列和 MTU 错误。
- 用真实现有 codec 替换 Tokio `TcpStream` 做兼容测试。

通过标准：可靠流校验无丢失/重复/乱序，UDP 边界和丢包语义符合设计。

### 阶段 4：私有发现与路径迁移（约 2 周）

- protected mDNS、opaque presence、WeaverAddressLookup。
- path event 指标、LAN 优先、hysteresis 和 network-change 触发。
- 平台无关的 network-change、relay ↔ LAN 迁移测试，以及 Android arm64 构建。

通过标准：已有 stream 在 relay → LAN 迁移时 stable connection ID 不变；direct 失效可回 relay。

### 阶段 5：relay HA 与安全加固（约 2 周）

- 双 relay、鉴权、opaque presence API、配额和健康检查。
- 故障注入、fuzz、长稳、依赖/许可证审计和 qlog 诊断。
- 复现并判定 iroh 多 relay 故障 issue 对固定版本的影响。

通过标准：满足需求文档 Go/No-Go 条件；未满足时停止扩大 API，先修传输风险。

## 17. 测试矩阵

### 17.1 单元与属性测试

- 每种证书、绑定和 envelope 的 golden vector。
- 任意 bit flip、字段截断、未知版本和超长输入必须失败。
- 不同 NetworkId 下相同 AppAddr/DeviceId 不冲突，但任何凭据不能跨网验证。
- 配置链只接受合法后继，fork 不自动选择。
- 对所有 `StateStore` 实现运行同一 contract suite：CAS 冲突、批次原子性、durable reopen、schema 升降级和多网络 namespace 隔离。
- 在 secret seal、状态 commit 和延迟删除之间逐点注入崩溃，验证只可能产生可回收孤儿 secret，不能产生引用缺失 secret 的已提交状态。
- `VirtualTcpStream` partial read/write、shutdown、drop、cancel safety。

### 17.2 集成与网络测试

- 使用 Linux network namespaces/patchbay 覆盖 cone/symmetric NAT、UDP blocked、丢包、重排和 MTU。
- 两节点从 relay 建连后进入同 LAN，持续传输带序号数据并验证同一 QUIC connection。
- relay 故障、presence 服务故障和 config partition 分开注入。
- A 与 C 连接同一远程 B；验证 C 在 relay、LAN 直连和 relay 回退之间迁移时身份、connection ID、stream 数据与路径事件。
- 双向同时 connect 验证 session 去重不会误关主连接。

### 17.3 平台测试

- Android 使用 NDK 执行 `arm64-v8a` 构建；真机互通、Wi-Fi ↔ 5G、Doze 和进程恢复由宿主应用负责验收。
- 对默认 store 与宿主应用注入 store 执行重启测试，验证 `NetworkId`、成员身份、`EndpointId` 和 `DeviceId` 保持一致。
- Windows/macOS/Linux 跨公网和同 LAN。
- 验收证据同时记录应用数据连续性、path events、connection stable ID 和真实 relay 流量。

## 18. 首个可运行垂直切片

第一段代码只做一个端到端闭环：

1. `weaver-relay init` 初始化 Network A，注册服务端 `AppAddr`，随后以 `combined` 模式 `serve`。
2. Rust 客户端（可由 Android 宿主集成）生成 per-network keys 和 JoinRequest。
3. `weaver-relay invite` 签发绑定该 key 的 ticket，以二维码交给 Android。
4. Android 通过 ticket 中的一个节点加入，拿到双 relay 配置。
5. 服务端 `bind_tcp(AppAddr, echo_service)`；Android 以 `AppAddr + DeviceId` 连接并运行 echo。
6. 两端初始处于不同网络，经 relay 传输。
7. 客户端网络环境变化后，宿主通知 `network_change()`，presence/mDNS 产生 LAN candidate。
8. iroh 在同一 connection 中选中 LAN path，echo stream 不重建且数据序号连续。
9. 再断开 Wi-Fi，验证回到 relay。
10. 用另一个 relay data directory 执行 `weaver-relay init` 初始化 Network B，并复用相同 AppAddr，验证 Network A 客户端不能发现、认证或连接 Network B。

该切片先由平台无关集成测试验证；Android 侧以 arm64 NDK 构建作为本仓库门槛。

## 19. 与 iroh 1.0.3 的直接对应

- `AddressLookup::publish/resolve` 用于把 Weaver 的私有 presence 接入 iroh；iroh 会在本机地址变化时调用 publish，并可从多个 lookup 结果拨号。[AddressLookup API](https://docs.rs/iroh/latest/iroh/address_lookup/trait.AddressLookup.html)
- 1.0.3 的 remote actor 只在没有 selected path 时启动 lookup，但会持续消费尚未结束的 lookup stream；因此 Weaver 必须保持订阅 stream 存活，这一内部契约需要固定源码测试保护。[iroh v1.0.3 remote state source](https://github.com/n0-computer/iroh/blob/v1.0.3/iroh/src/socket/remote_map/remote_state.rs)
- `EndpointHooks::before_connect/after_handshake` 用于出站防串网和握手后的 EndpointId 准入拒绝。[EndpointHooks API](https://docs.rs/iroh/latest/iroh/endpoint/trait.EndpointHooks.html)
- `Endpoint::network_change()` 暴露平台无关的网络变化入口；Android 宿主若有 Java/Kotlin 网络回调可调用它，但本仓库不提供该桥接。[Endpoint API](https://docs.rs/iroh/latest/iroh/endpoint/struct.Endpoint.html)
- `Connection::open_bi/accept_bi`、`send_datagram/read_datagram` 实现虚拟 TCP/UDP；`paths_stream/path_events` 提供路径迁移证据。[Connection API](https://docs.rs/iroh/latest/iroh/endpoint/struct.Connection.html)
- `protocol::Router` 按 ALPN 分发 join 和 session handler，并要求持有 Router handle、显式 graceful shutdown。[Router API](https://docs.rs/iroh/latest/iroh/protocol/struct.Router.html)

## 20. 开工顺序

第一批 issue 建议按以下顺序建立：

1. Workspace + CI + Android arm64 交叉编译任务。
2. ID/domain separation + wire codec golden vectors。
3. Certificates + validation chain。
4. Encrypted config envelope + epoch rotation。
5. StateStore/SecretStore SPI + redb + 平台存储注入边界。
6. Relay init/serve/invite + SDK prepare-join/join state machines。
7. Per-network iroh Endpoint + hooks + Router。
8. Config anti-entropy over member session。
9. Virtual TCP echo vertical slice。
10. Virtual UDP echo vertical slice。
11. Protected LAN discovery + opaque presence。
12. Relay/LAN path migration instrumentation + Android arm64 build。
