// Package lattice implements a small local lattice-based signature service.
//
// 安全边界说明见同包 doc.go 与仓库 README。
package lattice

// Params 是一组签名安全参数。当前仅提供 ToyParams256 一组参数，
// 用于教学/演示性质的 Module-SIS 风格 Fiat-Shamir 签名。
type Params struct {
	Name            string
	N               int // 多项式系数个数（2 的幂）
	Q               int // 模数（NTT 友好素数）
	K               int // 公钥向量高度
	L               int // 掩码/私钥向量宽度
	Eta             int // 小私钥 s1,s2 的无穷范数界
	Gamma1          int // 掩码 y 的无穷范数上界（不含）
	Tau             int // 挑战 c 的非零系数个数
	MaxMessageBytes int // 允许签名/验证的最大消息长度
}

// ToyParams256 是当前唯一支持的参数集（教学强度，未经第三方审计）。
var ToyParams256 = &Params{
	Name:            "Toy-ModSIS-256-v1",
	N:               nConst,
	Q:               qConst,
	K:               kConst,
	L:               ellConst,
	Eta:             etaConst,
	Gamma1:          gamma1Const,
	Tau:             tauConst,
	MaxMessageBytes: maxMessageBytes,
}

// 固定维度常量：数组长度必须是编译期常量，故与 Params 解耦。
const (
	nConst          = 256
	qConst          = 8380417
	kConst          = 2
	ellConst        = 2
	etaConst        = 2
	gamma1Const     = 1 << 17
	tauConst        = 39
	maxMessageBytes = 16 << 20
)
