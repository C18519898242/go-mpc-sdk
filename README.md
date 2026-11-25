# go-mpc-sdk

面向 `mpc-node-api` 的 Go 客户端，提供普通分布式建钥、公钥查询、在线签名和预签名。兼容基准为 SDK v73.5.2。 [Builder Vault Go SDK 教程](https://builder-vault-tsm.docs.blockdaemon.com/docs/getting-started-demo-tsm-golang)

| SDK 调用 | mpc-node-api | Builder Vault HTTP |
| --- | --- | --- |
| `client.ECDSA().GenerateKey(ctx, session, threshold, "secp256k1", keyID)` | `POST /ecdsa/keys` | `POST /ecdsa/keys` |
| `client.Schnorr().GenerateKey(ctx, session, threshold, "Ed25519", keyID)` | `POST /frost/keys` | `POST /schnorr/keys` |
| `client.ECDSA().PublicKey(ctx, keyID, path)` | `POST /ecdsa/keys/{keyID}/publickey` | 同左 |
| `client.Schnorr().PublicKey(ctx, keyID, path)` | `POST /frost/keys/{keyID}/publickey` | `POST /schnorr/keys/{keyID}/publickey` |
| `client.ECDSA().Sign(ctx, session, keyID, path, digest)` | `POST /ecdsa/keys/{keyID}/sign` | 同左 |
| `client.Schnorr().Sign(ctx, session, keyID, path, message)` | `POST /frost/keys/{keyID}/sign` | `POST /schnorr/keys/{keyID}/sign` |
| `client.ECDSA().GeneratePresignatures(ctx, session, keyID, count)` | `POST /ecdsa/keys/{keyID}/{count}/presiggen` | 同左 |
| `client.Schnorr().GeneratePresignatures(ctx, session, keyID, count)` | `POST /frost/keys/{keyID}/{count}/presiggen` | `POST /schnorr/keys/{keyID}/{count}/presiggen` |
| `client.ECDSA().SignWithPresignature(ctx, keyID, id, path, digest)` | `POST /ecdsa/keys/{keyID}/signwithpresig` | 同左 |
| `client.Schnorr().SignWithPresignature(ctx, keyID, id, path, message)` | `POST /frost/keys/{keyID}/signwithpresig` | `POST /schnorr/keys/{keyID}/signwithpresig` |
| `client.KeyManagement().CountPresignatures(ctx, keyID)` | `POST /key/{keyID}/count/presigs` | 同左 |
| `client.KeyManagement().DeletePresignatures(ctx, keyID)` | `DELETE /key/{keyID}/presigs` | 同左 |
| `client.KeyManagement().DeleteKeyShare(ctx, keyID)` | `DELETE /key/{keyID}` | 同左 |
| `client.ECDSA().Reshare(ctx, session, keyID)` | `POST /ecdsa/keys/{keyID}/reshare` | 同左 |
| `client.Schnorr().Reshare(ctx, session, keyID)` | `POST /frost/keys/{keyID}/reshare` | `POST /schnorr/keys/{keyID}/reshare` |
| `client.ECDSA().CopyKey(ctx, session, sourceID, curve, threshold, targetID)` | `POST /ecdsa/keys/{sourceKeyID}/keycopy` | 同左 |
| `client.Schnorr().CopyKey(ctx, session, sourceID, variant, threshold, targetID)` | `POST /frost/keys/{sourceKeyID}/keycopy` | `POST /schnorr/keys/{sourceKeyID}/keycopy` |

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

对于教程中的这些调用，可以在应用的 `go.mod` 里用本地 `replace` 保持原 `/tsm` import 路径。

```go
require gitlab.com/Blockdaemon/go-tsm-sdkv2/v73 v73.5.2
replace gitlab.com/Blockdaemon/go-tsm-sdkv2/v73 => ../go-mpc-sdk
```

## 在线签名

每次签名创建新的会话。向所有选中的玩家并发调用 `Sign`，使用相同的会话、`keyID`、派生路径和消息。收齐本次会话所有玩家的 `PartialSignature` 后，在调用端合成。三节点 `threshold=1` 的密钥可以选两个玩家签名。根密钥使用 `nil` 路径，非硬化子密钥使用对应的索引数组。

- ECDSA 传入 32 字节摘要，调用 `tsm.ECDSAFinalizeSignature(digest, parts)`，可读取 `ASN1()`、`R()`、`S()` 和 `RecoveryID()`。用同一路径的 `PublicKey` 和摘要调用 `tsm.ECDSAVerifySignature`。
- Ed25519 传入原始消息，调用 `tsm.SchnorrFinalizeSignature(message, parts)` 得到 64 字节签名。用同一路径的 `PublicKey` 和原始消息调用 `tsm.SchnorrVerifySignature`。

连接 `mpc-node-api` 时，SDK 会请求 `signatureFormat: "partial"`。签名前请将所有参与节点升级到支持此选项的版本。

## 预签名

1. 用一个新会话向同组节点并发调用 `GeneratePresignatures`。各节点保存各自的预签名材料，调用方核对各节点返回的有序 ID 列表一致。`mpc-node-api` 单批支持 1 至 8 份。
2. 从本组的批次中选一个共同的 ID，每个节点分别调用 `SignWithPresignature`。这一步无需 MPC 会话或节点间通讯。各节点使用相同的 ID、路径和待签数据。如果首个节点的所有可用预签名都属于本组，也可以传空 ID，再把它返回的 `PresignatureID` 传给其余节点。
3. 收齐该 ID 对应的所有分片，调用 `ECDSAFinalizeSignature` 或 `SchnorrFinalizeSignature`。验签时使用同一路径的公钥。每个预签名 ID 在每个节点只能消费一次。如果消费请求超时且签名分片未收到，整组换一个 ID 重签。

`client.KeyManagement().CountPresignatures(ctx, keyID)` 查询当前节点的可用库存，`DeletePresignatures(ctx, keyID)` 清理当前节点该密钥的库存。清理整组库存时，分别调用各节点的客户端。两个方法都无需 MPC 会话，密钥分片可以继续签名和生成新的预签名。

## 删除密钥分片

`client.KeyManagement().DeleteKeyShare(ctx, keyID)` 删除当前节点上该密钥的分片和预签名。节点按 API Key 对应的应用执行删除。若同一应用内 ECDSA 和 Ed25519 共用该 `keyID`，两种算法的本地分片都会删除。删除整组分片时，分别调用持有分片的节点。

## 刷新和复制密钥分片

**刷新。** 用一个新会话向所有原分片持有者并发调用 `Reshare(ctx, session, keyID)`。全部节点返回成功后继续签名。刷新保留原 `keyID`、根公钥、派生公钥和阈值，原预签名失效，分片需要重新备份。若仅部分节点返回成功，用原会话向全组重发。

**复制。** 用一个新会话向目标组全员并发调用 `CopyKey`。目标组至少包含 `原阈值 + 1` 位原持有者。所有节点传同一个目标阈值和目标 ID，全员传空目标 ID 时由节点生成。收齐成功响应并核对返回的副本 ID 一致后，再用新 ID 签名。

例如原分片在 1、3 号节点，复制到 1、2、3 号节点。会话的 SDK 玩家索引是 `[]int{0, 1, 2}`。下表省略前两个参数 `ctx, session`。

| 算法 | 原持有者 1、3 | 新加入节点 2 |
| --- | --- | --- |
| ECDSA | `CopyKey(sourceID, "", 2, targetID)` | `CopyKey("", "secp256k1", 2, targetID)` |
| Ed25519 | `CopyKey(sourceID, "", 2, targetID)` | `CopyKey("", tsm.SchnorrEd25519, 2, targetID)` |

示例中的新阈值 `2` 要求三个节点共同签名。副本使用独立分片，原密钥和副本对应相同的根公钥及派生公钥。

## 本地示例

先启动 `mpc-node-api` 三节点，并把各节点的 API Key 放在 `MPC_NODE_API_KEY_1`、`MPC_NODE_API_KEY_2`、`MPC_NODE_API_KEY_3`。三个凭据必须对应相同应用。以下命令在本仓库运行。

```powershell
go run ./examples/keygen -algorithm ecdsa -threshold 1
go run ./examples/keygen -algorithm ecdsa -threshold 1 -message "hello" -chain-path 0,1
go run ./examples/keygen -algorithm ed25519 -threshold 1 -message "hello" -chain-path 0,1
go run ./examples/keygen -algorithm ecdsa -threshold 1 -message "hello" -chain-path 0,1 -presign
go run ./examples/keygen -algorithm ed25519 -threshold 1 -message "hello" -chain-path 0,1 -presign
```

示例会并发建钥并核对三个节点返回的密钥 ID 和公钥。传入 `-message` 后，示例用 `threshold + 1` 个节点签名，在 SDK 合成并验签。加 `-presign` 会先生成并消费一份预签名。`-nodes` 接受按玩家顺序排列的逗号分隔 URL，`-key-id` 可指定业务 ID。
