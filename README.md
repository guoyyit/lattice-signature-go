# latticesig — 本地确定性格基短签名服务

`latticesig` 是一个**仅通过本地函数接口**提供能力的短签名/验签库，签名方案构造在
环格（Ring-SIS）困难假设之上，采用 Lyubashevsky 风格的 *Fiat–Shamir with abort*
（“先提交后挑战 + 拒绝采样”）结构。

- 不进行任何网络或外部服务调用；所有能力均为进程内纯函数式接口。
- **确定性**：同一 `(种子, 参数集, 消息)` 永远产生同一密钥 / 同一签名，便于复现与审计。
- **可序列化**：公钥、私钥、签名均为带版本、带校验和的自描述二进制，可落盘并在重启后恢复。
- **并发安全**：验签为只读操作，可被任意 goroutine 并发调用；签名掩码按消息确定性派生，
  并发签署不同消息绝不复用随机数，并有运行时复用检测器兜底。

> ⚠️ **安全警示**：当前内置参数集（`toy128` / `lite256`）面向**测试与教学演示**，
> 体积小、未经第三方密码学审计，**不得用于保护真实资产**。详见 [SECURITY.md](./SECURITY.md)。

## 安装

```go
import "github.com/guoyyit/lattice-signature-go/latticesig"
```

仅依赖 Go 标准库（`crypto/sha256`、`crypto/hmac` 等）。需要 Go 1.25+。

## 快速上手

```go
package main

import (
    "crypto/rand"
    "fmt"

    "github.com/guoyyit/lattice-signature-go/latticesig"
)

func main() {
    // 1) 准备高熵种子（至少 16 字节，推荐 32 字节，来自 crypto/rand）。
    seed := make([]byte, 32)
    if _, err := rand.Read(seed); err != nil {
        panic(err)
    }

    // 2) 由种子确定性派生密钥对（相同种子 + 相同参数 => 相同密钥）。
    kp, err := latticesig.GenerateKey(seed, latticesig.Toy128)
    if err != nil {
        panic(err)
    }

    // 3) 对任意长度消息做确定性签名。
    msg := []byte("任意长度的消息")
    sig, err := latticesig.Sign(kp.Secret, msg)
    if err != nil {
        panic(err)
    }

    // 4) 验签（只读，可并发）。
    if err := latticesig.Verify(kp.Public, msg, sig); err != nil {
        panic(err)
    }
    fmt.Println("signature OK")
}
```

## 序列化与重启恢复

```go
pubBlob, _ := kp.Public.MarshalBinary()
skBlob, _ := kp.Secret.MarshalBinary()
sigBlob, _ := sig.MarshalBinary()

// 重启后：
pub, _ := latticesig.UnmarshalPublicKey(pubBlob)
sk,  _ := latticesig.UnmarshalSecretKey(skBlob)

// 直接对字节签名验签（内部先解码再校验）：
if err := latticesig.VerifyEncoded(pub, msg, sigBlob); err != nil {
    // 拒绝
}
// 用恢复后的私钥再次签名，结果与重启前完全一致：
sig2, _ := latticesig.Sign(sk, msg)
```

## 有状态签名句柄与随机数复用检测

无状态的 `Sign` 已通过“掩码 = H(私钥种子, 消息, 尝试计数器)”在设计上消除了
Schnorr 类随机数复用导致私钥泄露的路径。若需要额外的**运行时显式检测**，使用
`Signer`：

```go
signer := latticesig.NewSigner(kp.Secret) // 并发安全
sig1, err := signer.Sign(msgA)
sig2, err := signer.Sign(msgB)            // 不同消息 => 不同掩码
_,    err = signer.Sign(msgA)             // 相同消息 => 得到相同签名（允许）
```

若检测到“同一掩码被用于不同消息”这一泄露前提，会返回包装了
`ErrNonceReuse` 的错误。

## Service 门面

```go
svc := latticesig.NewService(latticesig.Toy128) // 或 latticesig.DefaultService()
kp, _ := svc.GenerateKey(seed)
sig, _ := svc.Sign(kp.Secret, msg)
err := svc.Verify(kp.Public, msg, sig)
```

## 参数含义

| 字段 | 含义 |
| --- | --- |
| `N` | 环 `Z_q[x]/(x^N+1)` 的次数，2 的幂 |
| `Q` | 模数（奇数） |
| `Eta` | 掩码 `y` 系数均匀分布于 `[-Eta, Eta]` |
| `Tau` | 挑战多项式 `c` 中恰为非零（`±1`）的系数个数 |
| `AcceptSq` | 拒绝采样的接受半径平方（`‖z‖²` 上界） |
| `MaxIters` | 单次签名最大尝试次数，防止异常参数导致死循环 |
| `MaxMsg` | 验签/签名接受的最大消息字节数（默认 16 MiB） |

内置参数：

| 名称 | N | Q | Eta | Tau | 用途 |
| --- | --- | --- | --- | --- | --- |
| `toy128` | 128 | 3329 | 64 | 16 | 单测 / 演示（快） |
| `lite256` | 256 | 7681 | 64 | 24 | 稍大的互通实验 |

## 错误模型

所有失败都返回可区分的哨兵错误，可用 `errors.Is` 判定；验签失败额外包装为
`*VerifyError`（可用 `errors.As` 取出，`.Detail` 给出拒绝原因）：

- `ErrUnknownVersion`：编码版本未知 / 超出兼容范围。
- `ErrMalformedEncoding`：结构损坏、截断、魔数错误、校验和不符等。
- `ErrUnsupportedParams`：参数集标识不被本构建识别。
- `ErrMessageTooLarge`：消息超过 `MaxMsg`。
- `ErrInvalidSignature`：密码学校验未通过（签名或公钥被篡改、消息不符等）。

## 编码格式（版本 1）

```
4  magic "LSG1"
1  kind   (1=公钥, 2=私钥, 3=签名)
1  ver    载荷版本
2  param  参数集稳定 ID
4  plen   载荷长度（大端）
plen      载荷
4  checksum = SHA256(以上所有字节)[:4]
```

兼容范围 `[minAcceptedVer, payloadVersion]` 内的旧编码仍可验签；更旧 / 更新的
版本返回 `ErrUnknownVersion`；任何字节损坏在校验和或密码学校验处被拒绝。

## 运行测试

```bash
go test ./...            # 全部测试
go test ./... -race      # 带竞态检测
go test ./... -run Tamper
```

测试覆盖：可复现性、逐位篡改拒绝、并发签名 / 验签、随机数复用检测、版本兼容、
未知版本 / 参数、损坏与超大 / 恶意输入。
