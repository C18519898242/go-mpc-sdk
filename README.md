# go-mpc-sdk

面向 `mpc-node-api` 的 Go 客户端。以 [Builder Vault Go SDK 教程](https://builder-vault-tsm.docs.blockdaemon.com/docs/getting-started-demo-tsm-golang) 和 SDK v73.5.2 为兼容基准，首版提供普通分布式建钥和公钥查询。

| SDK 调用 | mpc-node-api | Builder Vault HTTP |
| --- | --- | --- |
| `client.ECDSA().GenerateKey(ctx, session, threshold, "secp256k1", keyID)` | `POST /ecdsa/keys` | `POST /ecdsa/keys` |
| `client.Schnorr().GenerateKey(ctx, session, threshold, "Ed25519", keyID)` | `POST /frost/keys` | `POST /schnorr/keys` |
| `client.ECDSA().PublicKey(ctx, keyID, path)` | `POST /ecdsa/keys/{keyID}/publickey` | 同左 |
| `client.Schnorr().PublicKey(ctx, keyID, path)` | `POST /frost/keys/{keyID}/publickey` | `POST /schnorr/keys/{keyID}/publickey` |

`Configuration{URL: ...}.WithAPIKeyAuthentication(...)`、`NewClient`、`GenerateSessionID`、`NewSessionConfig` 和 `NewStaticSessionConfig` 沿用 Blockdaemon 的调用形状。每个客户端连接一个节点，初始化读取 `/version` 和 `/info/protocols`。会话玩家采用教程里的零起始索引。本机默认的 `mpc-node-api` 节点 ID 是 `1,2,3`，SDK 探测到对象格式的协议描述时自动转换编号。

```go
import "github.com/C18519898242/go-mpc-sdk/tsm"

// 对每个节点创建一个客户端，向所有参与者并发执行同一场会话。
cfg := tsm.Configuration{URL: "http://127.0.0.1:8081"}.WithAPIKeyAuthentication(apiKey)
client, err := tsm.NewClient(cfg)
if err != nil {
    return err
}
session := tsm.NewSessionConfig(tsm.GenerateSessionID(), []int{0, 1, 2}, nil, nil)
keyID, err := client.ECDSA().GenerateKey(ctx, session, 1, "secp256k1", "")
```

用同一个 `session`、算法、阈值和自定义 ID 并发请求全部参与节点。空 `keyID` 由节点生成。三节点 `threshold=1` 表示 2 签，`threshold=2` 表示 3 签。`PublicKey` 返回 v73.5.2 格式的 JSON 字节（`scheme`、`curve`、`point`），`nil` 派生路径表示查根公钥。

对于教程的建钥和公钥查询代码，可以在应用的 `go.mod` 里用本地 `replace` 保持原 `/tsm` import 路径。

```go
require gitlab.com/Blockdaemon/go-tsm-sdkv2/v73 v73.5.2
replace gitlab.com/Blockdaemon/go-tsm-sdkv2/v73 => ../go-mpc-sdk
```

本地示例在 [`examples/keygen`](examples/keygen)。先启动 `mpc-node-api` 三节点，并把各节点的 API Key 放在 `MPC_NODE_API_KEY_1`、`MPC_NODE_API_KEY_2`、`MPC_NODE_API_KEY_3`。三个凭据必须对应相同应用。然后在本仓库运行：

```powershell
go run ./examples/keygen -algorithm ecdsa -threshold 1
go run ./examples/keygen -algorithm ed25519 -threshold 1
```

示例会统一生成 MPC 会话、并发建钥、核对三个节点返回的密钥 ID 和公钥。`-nodes` 接受按玩家顺序排列的逗号分隔 URL，`-key-id` 可指定业务 ID。

此版本的兼容范围是 API Key 认证、Secp256k1 与 Ed25519 的普通建钥和公钥查询。
