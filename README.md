# Weaver

Weaver is an experimental local-first network layer built on Rust, Tokio, iroh and QUIC. The first executable slice runs a tonic server A and tonic client C either directly or through the same standalone relay B.

```text
                     direct LAN/WAN
              ┌────────────────────────┐
              │                        │
              ▼                        │
      A tonic server                   C tonic client
              │                        │
              └──────► B relay ◄───────┘
```

## Current milestone

Implemented:

- standalone `weaver-relay` binary with `authority`, `data-relay`, and `combined`
  serving roles;
- stable `AppAddr` and `DeviceId` value types;
- stable `NetworkId` and network-scoped peer descriptors;
- injectable `StateStore` and `SecretStore` interfaces with explicit durability and
  secret-protection capabilities;
- a test-only in-memory store and a durable ACID `RedbStateStore` with version
  preconditions, atomic batches, schema checks and isolated member/authority namespaces;
- an `EncryptedFileSecretStore` using an externally supplied master key,
  authenticated encryption, secret-ID-bound AAD and tamper/wrong-key rejection;
- crash-safe secret-first client identity creation, restoring the same EndpointId and
  DeviceId after reopening persistent state;
- domain-separated IDs plus signed member certificates, endpoint bindings, application
  registrations and device/application bindings with validity and revocation checks;
- a bounded `NetworkConfigV1` format that validates the complete credential chain,
  relay/presence descriptors, duplicates and policy limits before use;
- signed configuration hash chains with XChaCha20-Poly1305 payload encryption,
  anonymous per-member X25519 HPKE key wraps and typed envelope/payload consistency;
- standalone `weaver-relay keygen/init/status/serve/invite/revoke/app-register/app-bind`
  commands and a crash-safe authority
  initializer that commits revision zero only after encrypted secrets, redb state and the
  public manifest have all been durably written;
- offline network-root recovery separated from the online root-signed administrator;
  post-genesis commits are signed by the bounded online admin certificate and the root
  secret is never stored in the serving authority directory;
- signed `.wjr` join requests and `.wjt` join tickets binding member signing, HPKE and
  Iroh EndpointId keys, plus a public crash-safe `NetworkMembership::prepare_join/join`
  API reused by `weaver-cli`;
- owner-signed application registration requests and server/client application bindings;
- full encrypted authority revision history and bounded `.wvu` update chains; members
  validate every consecutive signature/hash link, decrypt every revision and atomically
  compare-and-swap their persisted checkpoint;
- a network-scoped Iroh config-sync ALPN: B authenticates the requesting EndpointId
  against current membership and forwards only signed encrypted revisions; C derives B's
  relay URL from its last validated config and applies updates with `weaver-cli sync`;
- a background config-sync runtime that synchronizes immediately on startup, every 30
  seconds by default, or on an explicit trigger, with bounded exponential retry events;
- member-side encrypted revision history and multi-member anti-entropy; each round derives
  its peers from the latest signed topology so additions and revocations take effect live;
- iroh endpoint construction with public discovery disabled;
- protected `_weaver._udp.local` discovery using rotating network-keyed opaque tags;
- signed XChaCha20-Poly1305 encrypted presence records, TTL/sequence replay protection,
  and a network-scoped live Iroh address lookup that accepts late LAN/relay candidates;
- automatic background bridging of protected mDNS observations and Iroh address
  publications, including tag rotation, epoch-key hot rotation and network-change republishing;
- authenticated opaque remote presence publish/query with bounded TTL, ownership and storage;
- explicit zero/one/multiple custom relay configuration;
- relay registration, URL/role rotation and removal as signed topology revisions;
- TLS 1.3 relay serving, member access control, byte-rate/burst limits, bounded key cache,
  and live authority/access-policy reload after administrative revisions;
- formal `NetworkHandle`/`VirtualNetwork` entry points that open persisted membership,
  bind explicit `ServerAddr` or `ClientAddr`, discover peers and connect using only `VirtualAddr`;
- generic `VirtualTcpListener` plus reliable `VirtualTcpStream`, implementing Tokio
  `Stream` and `AsyncRead`/`AsyncWrite` rather than a tonic-specific transport;
- TCP-style write-half shutdown, EOF, idempotent shutdown, write-after-shutdown errors,
  and optional transport acknowledgement through `finish_and_wait()`;
- tonic server incoming adapter and tonic client connector;
- connected `VirtualUdpSocket` and `VirtualUdpListener` backed by QUIC DATAGRAM, with
  authenticated virtual-address association, preserved message boundaries and explicit
  unreliable/unordered/no-retransmit semantics;
- config-derived endpoint and application authorization on A, with deny-by-default behavior;
- server-side binding from the authenticated EndpointId to the permitted client
  `AppAddr + DeviceId`; client-provided virtual identity is never trusted by itself;
- config-derived client/server node constructors that require signed endpoint and app
  bindings, support multiple client application addresses per EndpointId, and derive relay
  selection only from a validated `NetworkConfigV1`;
- encrypted stream-open validation of NetworkId, source client address and destination
  server address before any application bytes are exposed;
- `AppAddr` bound into the negotiated ALPN;
- automated tonic RPC test with direct IP transports disabled, forcing `C -> B -> A`;
- readable network-local HTTP aliases such as `weaver.virtual`, with HTTP/1.1, HTTP/2,
  streaming bodies and WebSocket upgrade running over `NetworkHandle` without DNS;
- an 8 MiB reliable-stream test over the forced relay path using irregular write
  boundaries, exact byte/order verification and a response after client half-close;
- a live-path test that bootstraps one existing reliable stream through B, observes Iroh
  select the discovered direct IP path, and continues bidirectional traffic on the same
  stream and authenticated connection;
- a forced-relay UDP test covering message boundaries, echo traffic and rejection of an
  authenticated EndpointId that claims the wrong DeviceId;
- rejection tests for local cross-network dialing, a remote cross-network open request,
  and an authenticated EndpointId claiming the wrong DeviceId.
- successful `arm64-v8a` Android API 24 build of the core client stack with NDK r27c.

Android support in this repository means that the Rust client stack builds for
`aarch64-linux-android`; Weaver does not ship a JNI library or Android Keystore wrapper.
Android applications choose their own Rust integration and inject storage/platform services.

## Network fault simulation

Linux reliability acceptance uses real `tc netem` qdiscs and isolated network namespaces.
It measures throughput, relay/direct RTT and migration time while verifying every byte on
one reliable stream across automatic protected-mDNS relay-to-LAN path switching:

```bash
bash scripts/netem-e2e.sh
```

Run `bash scripts/netem-suite.sh` for high-latency, lossy/reordered and constrained-bandwidth
profiles. See [the netem test guide](docs/network-simulation.md) for topology and outputs.

The JSON endpoint descriptor and plaintext mode-0600 demo identity files are development scaffolding, not the final trust or storage model.

## Reliable stream contract

One `VirtualTcpStream` maps to one QUIC bidirectional stream. Its application-visible
contract is a reliable, ordered, non-duplicated byte stream with backpressure and
independent read/write halves. QUIC performs loss detection and retransmission; Weaver
must not add a second packet-level ACK/retransmit protocol on top.

Weaver writes and consumes a versioned internal stream-open request before exposing the stream.
This is necessary because a QUIC peer cannot accept an opened stream until its opener has
sent bytes. The preface makes server-first protocols work: after client `connect()`, the
server can `accept()` and send application bytes before the client sends any application
payload. The request carries the NetworkId, client `AppAddr + DeviceId` and destination
server AppAddr. A validates these fields against the authenticated EndpointId and its
local network configuration, then returns an explicit accepted/rejected response. Neither
the request nor response is returned by `AsyncRead`.

The production-facing data plane enters through `NetworkMembership` and `NetworkHandle`.
The small runnable tonic demo intentionally retains command-line development bootstrap so it
can be launched in three terminals without provisioning files; the signed-config path is
covered by `crates/weaver-net/tests/network_handle.rs`.

Each `VirtualTcpStream` currently owns an independent QUIC connection. Connection pooling is
not part of the first-version contract; this keeps lifecycle and revocation semantics simple
without changing reliable ordered delivery or transparent path migration.

## Storage boundary

`weaver-store` exposes ordinary state and secret storage as separate injectable traits.
State mutations use one scope-bound `AtomicBatch` with `Missing`, `Exact(version)` or
`Any` preconditions. `RedbStateStore` uses redb ACID transactions and durable commits;
`MemoryStateStore` explicitly reports that it is not durable and is test-only.

Client identity creation seals and reads back the endpoint secret before atomically
committing the state record that references it. A crash may leave an unreferenced secret
for later GC, but cannot commit state pointing to a secret that was never stored. Secret
stores must make repeated writes of identical bytes idempotent and refuse replacement by
different bytes. `EncryptedFileSecretStore` is the portable encrypted-file implementation,
but its master key must come from an external platform key provider and is never written
beside the ciphertext. `MemorySecretStore` reports `InMemoryTestOnly`; it is not a
production fallback.

Relay-to-direct or direct-to-relay path changes inside the same QUIC connection preserve
this stream and remain invisible to the application. If the entire QUIC connection is
lost, reads/writes return an error. Weaver deliberately does not silently create a new
connection and replay bytes because that could duplicate data and would violate TCP
semantics. Surviving process restarts or a fully expired connection requires an explicit
application session/resumption protocol above `VirtualTcpStream`.

## Run the A/B/C demo

Use three terminals. If the machine has HTTP proxy variables, ensure loopback is excluded:

```bash
export NO_PROXY=127.0.0.1,localhost
export no_proxy=127.0.0.1,localhost
```

Initialize a persistent virtual network separately from application code:

```bash
weaver-relay keygen --out /secure/path/network-a.master-key
weaver-relay init \
  --data-dir /var/lib/weaver/network-a \
  --relay-url https://relay.example.com \
  --master-key-file /secure/path/network-a.master-key \
  --recovery-root-out /offline/network-a.root
weaver-relay status \
  --data-dir /var/lib/weaver/network-a \
  --master-key-file /secure/path/network-a.master-key
```

The master-key file is external input and is never copied into `--data-dir`. Keep it in a
platform key store or separately protected location. `keygen` uses create-new semantics
and refuses to overwrite an existing file. The root recovery file also uses create-new
semantics and must be moved offline; the online authority retains only a root-signed,
bounded administrator key.

The implemented provisioning flow is:

```text
C: weaver-cli prepare-join -> member.wjr
B: weaver-relay invite member.wjr -> member.wjt (commits next revision/epoch)
C: weaver-cli join member.wjt --root-public-key ...
C: weaver-cli sync --peer-endpoint-id <B_ENDPOINT_ID> --root-public-key ...
```

`join` verifies root → online admin → ticket → member → endpoint, decrypts the embedded
checkpoint, and commits membership/config state atomically. `sync` uses the signed relay
descriptor already in that checkpoint, authenticates with C's Iroh EndpointId, downloads
an encrypted consecutive revision chain from B, and applies it atomically.

Generate C's persistent development identity and copy the printed endpoint ID:

```bash
cargo run -p weaver-tonic-demo --bin client -- identity
```

Start B:

```bash
cargo run -p weaver-relay -- --listen 127.0.0.1:3340
```

Start A, replacing `<CLIENT_ENDPOINT_ID>`:

```bash
cargo run -p weaver-tonic-demo --bin server -- \
  --relay-url http://127.0.0.1:3340 \
  --allow-client <CLIENT_ENDPOINT_ID>
```

Call A from C while allowing iroh to choose direct or relay:

```bash
cargo run -p weaver-tonic-demo --bin client -- call \
  --relay-url http://127.0.0.1:3340 \
  --message 'hello over Weaver'
```

Force the relay path for verification:

```bash
RUST_LOG='iroh::_events::path=debug' \
cargo run -p weaver-tonic-demo --bin client -- call \
  --relay-url http://127.0.0.1:3340 \
  --relay-only \
  --message 'hello through B'
```

## HTTP and WebSocket virtual-host demo

`weaver-http-demo` uses readable, network-local aliases instead of putting an IP address or
the hexadecimal `AppAddr` in an URL. For example:

```text
http://weaver.virtual/
http://weaver.virtual/echo
ws://weaver.virtual/ws
```

The name is resolved by Weaver's built-in virtual DNS inside the selected `NetworkHandle`; the
operating-system DNS resolver is never called. Authority-managed records are part of the signed,
encrypted network configuration and become live through normal config propagation. The name maps
to an authorized `AppAddr`, while the `AppAddr` remains the cryptographic application identity. See
[`docs/http-websocket-demo.md`](docs/http-websocket-demo.md) for provisioning and commands.

## Verification

```bash
cargo check --workspace
NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
  cargo test --workspace
```

The raw reliable-stream acceptance test is
`crates/weaver-net/tests/reliable_tcp.rs`; authenticated config transport is
`crates/weaver-net/tests/config_sync.rs`; path migration and UDP behavior are
`crates/weaver-net/tests/path_migration.rs` and `crates/weaver-net/tests/virtual_udp.rs`;
the tonic acceptance test is
`examples/tonic-demo/tests/abc_tonic.rs`; formal joined-network entry points are covered by
`crates/weaver-net/tests/membership.rs` and `crates/weaver-net/tests/network_handle.rs`.

Architecture and security requirements are in [the implementation design](docs/implementation-design.md) and [the requirements/iroh research](docs/network-infrastructure-requirements-and-iroh-research.md).
