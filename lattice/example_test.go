package lattice_test

import (
	"fmt"
	"log"

	"github.com/guoyyit/lattice-signature-go/lattice"
)

// ExampleService 展示完整的本地签名/验证与序列化恢复流程。
func ExampleService() {
	svc, err := lattice.NewService(nil) // nil 使用默认参数集 ToyParams256
	if err != nil {
		log.Fatal(err)
	}

	// 1. 从种子确定性生成密钥对；相同种子得到相同密钥。
	pk, sk, err := svc.KeyGenFromSeed([]byte("my-unique-seed"))
	if err != nil {
		log.Fatal(err)
	}

	// 2. 密钥可序列化并在重启后恢复。
	encPK, err := svc.MarshalPublicKey(pk)
	if err != nil {
		log.Fatal(err)
	}
	encSK, err := svc.MarshalSecretKey(sk)
	if err != nil {
		log.Fatal(err)
	}
	pkRestored, err := svc.UnmarshalPublicKey(encPK)
	if err != nil {
		log.Fatal(err)
	}
	skRestored, err := svc.UnmarshalSecretKey(encSK)
	if err != nil {
		log.Fatal(err)
	}

	// 3. 确定性签名：同一密钥+消息恒得到相同字节。
	message := []byte("any length message ...")
	sig1, err := svc.Sign(skRestored, message)
	if err != nil {
		log.Fatal(err)
	}
	sig2, err := svc.Sign(skRestored, message)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("deterministic:", string(sig1) == string(sig2))

	// 4. 验证。
	if err := svc.Verify(pkRestored, message, sig1); err != nil {
		log.Fatal(err)
	}
	fmt.Println("verified:", true)

	// 5. 篡改会被拒绝。
	tampered := make([]byte, len(sig1))
	copy(tampered, sig1)
	tampered[len(tampered)-9] ^= 0x01
	err = svc.Verify(pkRestored, message, tampered)
	fmt.Println("tampered rejected:", err != nil)
	// Output:
	// deterministic: true
	// verified: true
	// tampered rejected: true
}
