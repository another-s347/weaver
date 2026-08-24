# HTTP 与 WebSocket 可读虚拟域名接入

`weaver-http-demo` 展示应用如何在指定 `NetworkHandle` 内使用可读域名：

```text
(NetworkId, weaver.virtual) -> ServerAddr(AppAddr)
```

它不修改系统 DNS、hosts 文件或 IP 路由。客户端 connector 从 HTTP URI 的 host 读取
`weaver.virtual`，通过 `NetworkHandle` 内置的 Virtual DNS 从当前网络的已验证签名配置
解析成 `AppAddr`，再调用可靠流连接。它不会查询操作系统 DNS。因此同一个名称可以在
不同 Network 中指向不同应用，且
不存在跨网络解析或通信。

`AppAddr` 仍然是应用的加密身份与授权边界；名称只负责可读寻址。Virtual DNS 记录由
Authority 写入加密、签名、单调递增的网络配置，通过已有配置 anti-entropy 跨成员传播。
名称唯一性、有效期和解析都仅在一个 `NetworkId` 内生效；普通应用节点不能自行覆盖记录。

注册应用后，由网络管理员发布名称：

```bash
weaver-relay dns-set \
  --data-dir /var/lib/weaver/network-a \
  --master-key-file /secure/network-a.master-key \
  --name weaver.virtual \
  --app-addr <APP_ADDR> \
  --valid-days 30
```

## 协议能力

- HTTP/1.1 keep-alive、headers、status、任意请求/响应 body；
- HTTP/2 prior knowledge 与多路复用；
- 流式响应 body；
- HTTP/1.1 WebSocket Upgrade、文本帧、二进制帧和关闭握手；
- 连接继续使用 Weaver 的端到端认证、加密、可靠有序传输和透明路径迁移。

URL 使用 `http://` 和 `ws://`，因为 Weaver 传输层已经提供端到端加密与身份认证；
数据不会以明文 TCP 形式离开 Weaver。该 demo 不实现 HTTP/3。

## 服务端

节点必须已经加入目标 Network，且当前 member 已获得指定 `AppAddr` 的 Server binding：

```bash
cargo run -p weaver-http-demo --bin weaver-http-server -- \
  --data-dir /var/lib/my-app/network-a \
  --master-key-file /secure/network-a.member-key \
  --root-public-key <NETWORK_ROOT_PUBLIC_HEX> \
  --app-addr <APP_ADDR> \
  --host weaver.virtual
```

服务端使用 Hyper 自动连接检测，在同一个虚拟 listener 上接受 HTTP/1.1 与 HTTP/2，
并为 HTTP/1.1 启用 Upgrade。

## 客户端

客户端和服务端属于同一应用，因此使用同一个 `AppAddr`；客户端通过已签名的
`DeviceId` 与服务端地址区分：

```bash
cargo run -p weaver-http-demo --bin weaver-http-client -- \
  --data-dir /var/lib/my-app/network-a \
  --master-key-file /secure/network-a.member-key \
  --root-public-key <NETWORK_ROOT_PUBLIC_HEX> \
  --client-app <APP_ADDR> \
  --device-id <DEVICE_ID> \
  --host weaver.virtual \
  get --path / --version http1
```

HTTP/2 POST：

```bash
cargo run -p weaver-http-demo --bin weaver-http-client -- \
  <相同网络与应用参数> \
  post --path /echo --body 'hello over HTTP/2' --version http2
```

WebSocket：

```bash
cargo run -p weaver-http-demo --bin weaver-http-client -- \
  <相同网络与应用参数> \
  websocket --message 'hello over Weaver WebSocket'
```

## Rust API

```rust
let connector = WeaverHttpConnector::new(network_handle);
let client = http1_client(connector);

let request = Request::builder()
    .uri("http://weaver.virtual/echo")
    .body(Full::new(Bytes::from_static(b"hello")))?;

let response = client.request(request).await?;
```

未知或过期名称、包含显式 TCP port 的 URI、非 `http`/`ws` scheme，以及不符合
`*.virtual` 小写 DNS label 规则的名称都会在本地拒绝，不触发网络连接。配置更新原子
生效，已创建的 connector 不需要重建。

## 自动验收

```bash
cargo test -p weaver-http-demo --test http_websocket
```

测试创建真实 Authority 和 Relay 配置，让 A/C 分别完成 `prepare_join`、ticket 验证和
原子 `join`，注册同一应用的 Server/Client binding，然后验证：

- `Host: weaver.virtual` 到达服务端；
- HTTP/1.1 GET 与 1 MiB POST 完整收发；
- status 与自定义 header 保持；
- 流式响应包含多个 DATA frame；
- HTTP/2 请求成功；
- 写入记录前名称解析失败，配置增量传播后同一个 connector 自动解析成功；
- 未知名称在 connector 内拒绝；
- WebSocket 文本、二进制与关闭握手成功。
