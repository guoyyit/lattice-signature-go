# latticesig — 本地确定性格基短签名服务

`latticesig` 是一个**仅通过本地函数接口**提供能力的短签名/验签库，签名方案构造在
环格（Ring-SIS）困难假设之上，采用 Lyubashevsky 风格的 *Fiat–Shamir with abort*
（“先提交后挑战 + 拒绝采样”）结构。

- 不进行任何网络或外部服务调用；所有能力均为进程内纯函数式接口。
- **确定性**：同一 `(种子, 参数集, 消息)` 永远产生同一密钥 / 同一签名，便于复现与审计。
- **可序列化**：公钥、私钥、签名均为带版本、带校验和的自描述二进制，可落盘并在重启后恢复。
- **并发安全（含首次使用）**：从字节恢复出的公钥**无需任何预热调用**即可被任意数量的
  goroutine 立即并发验签；首次使用与后续使用行为完全一致。验签全程只读，签名掩码按
  消息确定性派生，并发签署不同消息绝不复用随机数，并有运行时复用检测器兜底。

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

### 并发使用约束

- **公钥**：`Verify` / `VerifyEncoded` 对接收方完全只读。从 `UnmarshalPublicKey`
  返回的那一刻起，所有内部派生状态（如展开的公共环元素 `a`）就已就绪；恢复实例后
  **不需要也不应当**先串行调用一次来“初始化”。任意数量 goroutine 可在同一实例上
  立即并发验证同一签名或不同签名，结果与调用顺序、并发程度、是否首次使用无关。
- **私钥**：`Sign` 不修改密钥对象，恢复出的私钥首次签名与并发验签同时发生也是安全的。
  同一消息的并发签名逐字节一致；不同消息产出不同掩码。
- **共享 `Signature`**：验签不修改签名对象，同一 `*Signature` 可被多 goroutine 共享；
  若调用方各自持有独立字节切片，则可直接并发使用 `VerifyEncoded`。
- 以上约束由 `go test -race` 下的首次并发使用测试锁定，见
  `latticesig/firstuse_concurrent_test.go`。

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

- `ErrUnsupportedVersion`：版本**低于**本构建支持的最低版本（历史过旧，无法解析）。
- `ErrNewerVersion`：版本**高于**本构建产生的当前版本（可能需要更新的实现）。
- `ErrUnknownVersion`：版本不匹配的**通用族标记**；上面两种具体版本错误都可用
  `errors.Is(err, ErrUnknownVersion)` 统一判定，需要精确原因时再分别判定。
- `ErrMalformedEncoding`：结构损坏、截断、魔数错误、校验和不符等。
- `ErrUnsupportedParams`：参数集标识不被本构建识别。
- `ErrMessageTooLarge`：消息超过 `MaxMsg`。
- `ErrInvalidSignature`：密码学校验未通过（签名或公钥被篡改、消息不符等）。

## 编码格式与版本兼容

### 信封（所有版本通用，所有整数大端）

```
偏移   长度   字段
0      4      magic "LSG1"（格式族标识）
4      1      kind   (1=公钥, 2=私钥, 3=签名)
5      1      ver    载荷版本（按**有符号** int8 解释：0x00..0x7F 为非负版本，
                     0x80..0xFF 为早于一切已发布格式的负版本）
6      2      param  参数集稳定 ID
8      4      plen   载荷长度
12     plen   载荷
12+plen 4      checksum = SHA256(字节[0 : 12+plen]) 的前 4 字节
```

校验和在信任任何内容（包括版本字段）之前验证。因此**篡改版本字节而不重算校验和**
一律得到 `ErrMalformedEncoding`，它与版本错误彼此可区分。

### 当前版本（version 1，写入器唯一产出的版本）

```
公钥 : uint16 aSeedLen || aSeed || 2*N 个 int16（大端、对称区间）系数 t
私钥 : uint16 seedLen || seed || 2*N 个 int16（大端）系数 s
       || uint32 内嵌公钥 blob 长度 || 内嵌公钥 blob
签名 : ch[32]（挑战种子） || 2*N 个 int16（大端）系数 z
```

当前版本系数为大端、**有符号** int16，取值在 `[-(q-1)/2, (q-1)/2]`。

### 历史版本（version 0，仅读、仅供向后兼容）

版本 0 是真实发布过的历史布局，与版本 1 的**载荷布局不同**，不是“只换版本号”。
信封相同，载荷规则如下：

- 环系数编码为**小端、无符号** uint16 规范余数，取值在 `[0, q)`；v1 使用大端有符号。
  两种表示对所有已支持模数是精确一一对应，解析后得到完全相同的内存对象。
- 变长字节串（`aSeed`、`seed`）在 v0 中是**固定 32 字节、无长度前缀**的字段；
  v1 带 uint16 长度前缀。
- 签名载荷字段顺序不同：v0 为 `z` 在前、`ch[32]` 在后；v1 为 `ch` 在前、`z` 在后。
- 私钥载荷字段顺序不同：v0 为“内嵌公钥 blob 在前，随后固定宽度 `seed[32]` 与
  `s`”；v1 为 `seed`、`s`、随后长度前缀 + 公钥 blob。

v0 精确载荷布局：

```
公钥 : aSeed[32] || leU16(t)[2*N]
私钥 : 内嵌公钥 blob（长度隐式为去掉尾部固定字段后的剩余部分）
       || seed[32] || leU16(s)[2*N]
签名 : leU16(z)[2*N] || ch[32]
```

实现见 `latticesig/legacy_v0.go`；随测试提交的**固定字节向量**（独立于当前写入器
生成、运行时绝不重新生成）见 `latticesig/legacy_vectors_test.go`，生成器是带构建标签
的离线工具：`go run -tags genlegacyv0 ./cmd/genlegacyv0`。

### 版本边界与互操作

兼容范围为 `[minAcceptedVer=0, payloadVersion=1]`：

| 版本字节 | 含义 | 行为 |
| --- | --- | --- |
| 有符号负值（如 `0xFF` = -1） | 低于最低支持版本 | `ErrUnsupportedVersion` |
| `0x00` | 兼容范围内最低旧版本 | **接受**，按 v0 布局解析 |
| `0x01` | 当前版本 | **接受** |
| `>= 0x02` | 高于当前版本 | `ErrNewerVersion` |
| 版本字节被篡改（校验和未修复） | 完整性失败 | `ErrMalformedEncoding` |

互操作性（由 `latticesig/legacy_compat_test.go` 锁定）：v0 公钥 + v1 签名可验签；
v1 公钥 + v0 签名可验签；从 v0 私钥恢复出的密钥签出的签名可验签且与确定性参考输出
逐字节一致；v0 签名对正确消息通过、对篡改消息拒绝。

## 运行测试

```bash
go test ./...                 # 全部测试
go test -race ./...           # 带竞态检测（并发安全的权威验证，必须无任何报告）
go test -race -count=5 ./...  # 多轮压测，提高首次并发使用竞态的暴露概率
go test ./... -run 'Legacy|CrossVersion|Version'  # 旧版互操作与版本边界
go test ./... -run Tamper     # 逐位篡改拒绝
```

测试覆盖：

- **首次并发使用（`-race`）**：从字节恢复公钥后无任何预热即并发验证同一签名 /
  不同签名、多个恢复实例同时首次验证、直接对签名字节并发 `VerifyEncoded`、恢复后
  并发签名与验签混合，以及并发结果与串行结果完全一致（`firstuse_concurrent_test.go`）。
- **历史版本兼容**：公钥 / 私钥 / 签名三类 v0 固定字节向量全部可解析，v0 与 v1
  双向互操作，正确消息通过、篡改消息拒绝（`legacy_compat_test.go`）。
- **版本边界**：低于最低版本、v0、当前 v1、高于当前版本、版本字段篡改五种情形，
  拒绝原因彼此可区分（`version_boundary_test.go`）。
- **当前版本编码锁定**：公钥 / 私钥 / 签名的固定黄金字节，确保修复前后逐字节一致、
  确定性密钥派生与签名不变（`golden_v1_test.go`）。
- 可复现性、逐位篡改拒绝、随机数复用检测、未知参数、损坏与超大 / 恶意输入。
