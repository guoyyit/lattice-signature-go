# lattice-signature-go

一套**纯本地**的短签名 / 验证服务，签名方案基于格（lattice）困难假设，
以 Fiat–Shamir 变换构造，结果完全可复现。仅通过 Go 进程内函数接口提供能力，
**不依赖任何外部服务、网络或系统随机源**（只使用 Go 标准库 `crypto/sha256`、
`crypto/hmac`）。

> ⚠️ **安全边界 / 免责声明**
>
> 本实现是**教学与演示性质**的格签名（Module-SIS 风格、无噪声构造，
> 思路接近 Dilithium/Falcon 一类基于拒绝采样的格签名，但**未实现也不声称**
> 达到任何 NIST 标准参数集的安全强度；参数为自行选取的玩具参数，
> 且**未经过第三方密码学审计**。
>
> **不要**用于保护生产数据、金融交易或任何真实世界安全场景。
> 生产用途请使用经过标准化与审计的实现（如 ML-DSA / FIPS 204）。

## 快速开始

```go
svc, _ := lattice.NewService(nil)                 // nil = 默认参数 ToyParams256
pk, sk, _ := svc.KeyGenFromSeed([]byte("seed"))   // 种子 -> 密钥对
sig, _ := svc.Sign(sk, []byte("message"))          // 确定性签名（字节编码）
err := svc.Verify(pk, []byte("message"), sig)      // 验证

// 重启恢复
encPK, _ := svc.MarshalPublicKey(pk)
encSK, _ := svc.MarshalSecretKey(sk)
pk2, _ := svc.UnmarshalPublicKey(encPK)
sk2, _ := svc.UnmarshalSecretKey(encSK)
```

完整可运行示例见 `lattice/example_test.go`。

## 功能与需求对应

| 需求 | 实现方式 |
|---|---|
| 种子确定性生成密钥；公钥/私钥可序列化恢复 | `KeyGenFromSeed`（SHA-256/HMAC 派生 PRG）；`Marshal/Unmarshal*` |
| 任意长度消息；未篡改通过、单点篡改拒绝 | 消息长度仅受 `MaxMessageBytes` 限制；签名绑定 `H(pk‖m)` 与 `H(mu‖w1)`，范数检查 |
| 确定性签名、重复结果一致 | 掩码由 `(rho, mu, attempt)` 派生，无随机状态 |
| 并发签名不复用随机数、杜绝复用泄露 | 随机数流按 `(密钥, 消息承诺, 尝试序号)` 域分隔；设计上隔离，而非事后检测 |
| 版本化编码；旧编码兼容；未知版本/损坏可区分错误 | 统一帧头 `magic/version/kind/length + SHA-256 校验和`；`ErrUnknownVersion` vs `ErrCorruptEncoding` |
| 验证并发安全；恶意/超大输入不崩溃不死循环；明确拒绝原因 | 无共享可变状态；全部解析边界检查 + 有界循环 + `recover()` 兜底；哨兵错误 |
| 自动化测试与文档 | `go test -race ./...`，含可复现性、篡改、并发、版本、异常输入、fuzz |

## 密码学构造概述

在多项式环 `R_q = Z_q[X]/(X^n+1)` 上（`n=256, q=8380417`）：

- 密钥生成：从种子派生 `rho`（展开公开矩阵 `A ∈ (R_q)^{k×l}`）与小向量
  `s1 ∈ R^l`（系数 ∈ {−2,…,2}），计算 `t = A·s1`（NTT 域）。公钥 `(rho, t)`，
  私钥 `(rho, s1, t)`。
- 签名（拒绝采样 Fiat–Shamir）：
  1. `mu0 = H("mu" ‖ t ‖ rho ‖ m)`；
  2. 采样掩码 `y`（系数 ∈ [−2^17, 2^17)），计算 `w = A·y`，取高位 `w1`；
  3. 挑战承诺 `ch = H(mu0 ‖ w1)`，展开含 `tau=39` 个 ±1 的稀疏挑战 `c`；
  4. `z = y + c·s1`；仅当 `‖z‖∞ < gamma1 − tau·eta` 时接受，否则换独立掩码重试；
  5. 签名 `(mu0, ch, z)`。
- 验证：检查 `‖z‖∞` 界，重算 `w' = A·z − c·t` 的高位并核对
  `ch = H(mu0 ‖ HighBits(w'))` 与 `mu0 = H(pk ‖ m)`。

其不可伪造性（直觉上）归约到 Module-SIS：伪造者需要找到满足线性关系的短向量。
NTT（数论变换）用于把多项式乘法从 `O(n²)` 降到 `O(n log n)`；
NTT 正确性由与朴素负循环卷积对拍的测试锁定。

## 参数含义（`lattice.Params` / `ToyParams256`）

| 字段 | 值 | 含义 |
|---|---|---|
| `N` | 256 | 多项式系数个数（环维度） |
| `Q` | 8380417 | 模数（NTT 友好素数） |
| `K` | 2 | 公钥/承诺向量高度 |
| `L` | 2 | 掩码/私钥向量宽度 |
| `Eta` | 2 | 私钥小系数界 `s1 ∈ [−eta, eta]` |
| `Gamma1` | 2^17 | 掩码系数界 `y ∈ [−gamma1, gamma1)` |
| `Tau` | 39 | 挑战多项式中 ±1 的个数 |
| `MaxMessageBytes` | 16 MiB | 单次签名/验证消息上限（防资源滥用） |

派生界：`beta = tau·eta = 78`，响应界 `zBound = gamma1 − beta = 130994`。
签名长度约 `64 + 2·256·20/8 ≈ 1344` 字节。

## 为什么不存在“随机数复用导致私钥泄露”

类似 ECDSA/格签名中 `k` 复用会泄露私钥。本实现**没有任何易失随机状态**：

- 掩码流 = `PRG(rho, "sign-y-v1" ‖ mu0 ‖ attempt)`；
- `mu0` 绑定消息与公钥，**不同消息必然产生不同掩码流**；
- 每次拒绝重试带单调递增的 `attempt` 域，重试之间也不复用；
- 因此跨消息/跨尝试复用在设计层面被消除，无需也不存在可被绕过的运行期检测开关。

## 版本化编码格式

```
magic "LTTC" (4B) | version u8 | kind u8 | length u32 | payload | checksum (SHA-256 前 8B)
```

- `kind`：1=公钥，2=私钥，3=签名；
- 当前 `version=1`；未来兼容版本会在同一解析窗口内接受；
- 未知版本 → `ErrUnknownVersion`；魔数/长度/校验和/载荷非法 → `ErrCorruptEncoding`；
  类型错配 → `ErrWrongObjectKind`。三者可用 `errors.Is` 区分。

## 错误处理与健壮性

- 所有服务方法在内部 `recover()` 兜底，畸形字节、nil 参数、超大输入均返回错误，
  不会 panic 到调用方；所有解析都有长度边界，循环次数由固定维度/重试上限界
  （`maxSignAttempts=256`），不存在无限循环路径。
- 消息超过 `MaxMessageBytes` 返回 `ErrMessageTooLarge`。
- 公钥、签名任一字节被篡改：要么校验和失败，要么范数检查/承诺重算失败。

## 测试

```bash
go test -race ./...          # 全部单元/并发/示例测试
go test -fuzz=FuzzVerify ./...   # 模糊测试（验证畸形输入不崩溃）
```

测试覆盖：NTT 与朴素卷积对拍、密钥/签名可复现性、篡改 `z`/公钥/消息拒绝、
不同密钥跨签拒绝、64 路并发签名不重复且同消息确定性、100 路并发验证、
序列化往返与“重启”恢复、未知版本/损坏/类型错配错误区分、空/超大消息、
随机字节 fuzz 不 panic。
