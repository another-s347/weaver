# Linux netem 可靠性与路径迁移验收

Weaver 使用 Linux `tc netem` 和独立 network namespace 对真实 QUIC 数据包进行
链路整形。测试不是在应用层随机丢弃写调用，因此 QUIC 的丢包检测、重传、拥塞控制、
流控和路径迁移都会经过真实内核网络路径。

## 拓扑

```text
初始：
 A namespace ── loss/delay/reorder/rate ── B relay
 C namespace ── loss/delay/reorder/rate ── B relay
 A 与 C 之间不启用 IP forwarding，连接只能 C -> B -> A

传输中：
 A namespace ── 新增受损 LAN veth ── C namespace
       protected mDNS 自动发现，原 QUIC connection 选择 direct path
```

A/C 是不同进程和不同 network namespace。脚本在可靠流传输开始后动态创建 LAN
链路，并发送平台无关的 network-change 通知。测试要求同一个 `VirtualTcpStream`
满足以下条件，否则退出码非零：

- 初始选中 relay，随后选中 direct；
- EndpointId 在路径变化前后保持不变；
- 接收端按绝对字节位置验证完整 payload，无丢失、重复或乱序；
- 至少观察到一次由受保护 mDNS 产生的服务端 LAN candidate；
- relay 和 direct 路径分别完成 RTT ping；
- 生成吞吐量、P50/P95 RTT 和 network-change 到 direct 的迁移耗时。

## 单场景运行

要求 Linux 内核支持 user/network namespace、veth 和 netem，并安装 `iproute2`。
默认通过 rootless user namespace 获得测试 namespace 内的 `CAP_NET_ADMIN`，不会修改
宿主网络配置：

```bash
bash scripts/netem-e2e.sh
```

可配置参数：

```bash
NETEM_DELAY=80ms \
NETEM_JITTER=20ms \
NETEM_LOSS=5% \
NETEM_REORDER=25% \
NETEM_CORRELATION=50% \
NETEM_RATE=10mbit \
BENCH_BYTES=67108864 \
bash scripts/netem-e2e.sh
```

测试本机 namespace/veth 拓扑在不施加任何 `netem` qdisc 时的极限吞吐量：

```bash
NETEM_DISABLED=1 \
BUILD_PROFILE=release \
BENCH_BYTES=1073741824 \
E2E_TIMEOUT=180 \
bash scripts/netem-e2e.sh
```

该模式仍从 Relay 路径建立连接并在传输中创建 LAN，但不会人为加入限速、延迟、
丢包或乱序；结果主要受 CPU、内存复制、QUIC 加密和本机 veth 性能限制。

输出目录包含：

- `report.json`：吞吐量、relay/direct RTT、迁移耗时、路径与完整性判定，
  以及 `protected_lan_observations` 自动发现观测数；
- `netem-stats.txt`：每条 WAN/LAN qdisc 的内核包数、丢包和 backlog 统计；
- `relay.log`、`server.log`、`client.log`：失败定位证据。

## 三种故障画像

```bash
bash scripts/netem-suite.sh
```

套件依次运行高延迟、严重丢包/乱序和低带宽画像。所有画像都执行完整的
relay→LAN 自动发现与透明路径切换，而不是只测静态吞吐量。

Android arm64 只要求交叉编译；这个 Linux netem harness 是传输层的确定性自动验收。
Android 真机网络行为仍由具体宿主应用负责。
