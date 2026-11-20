// Package smcrypto 封装国密 SM2/SM3/SM4、口令派生与敏感内存清零。
package smcrypto

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"runtime"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// KeySize 为 SM4 密钥长度（字节），SM4 固定 128 位。
	KeySize = 16
	// BlockSize 为 SM4 分组长度（字节）。
	BlockSize = sm4.BlockSize
	// ScalarSize 为 SM2 私钥标量长度（字节）。
	ScalarSize = 32
	// PublicKeySize 为未压缩 SM2 公钥长度：0x04 || X(32) || Y(32)。
	PublicKeySize = 65
)

// DeriveKey 以 SM3 为 PRF 运行 PBKDF2，从口令与盐派生 16 字节 SM4 密钥。
func DeriveKey(passphrase, salt []byte, iter int) []byte {
	if iter <= 0 {
		iter = 100000
	}
	return pbkdf2.Key(passphrase, salt, iter, KeySize, sm3.New)
}

// Digest 返回数据的 SM3 摘要。
func Digest(data []byte) []byte {
	sum := sm3.Sum(data)
	return sum[:]
}

// Encrypt 使用 SM4-CBC 加密明文，返回随机 IV 与带 PKCS#7 填充的密文。
func Encrypt(key, plaintext []byte) (iv, ciphertext []byte, err error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	iv = make([]byte, BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}
	padded := pkcs7Pad(plaintext, BlockSize)
	ciphertext = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	Zero(padded)
	return iv, ciphertext, nil
}

// Decrypt 解密 SM4-CBC 密文并去除 PKCS#7 填充。
func Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	if len(iv) != BlockSize {
		return nil, fmt.Errorf("smcrypto: IV 长度应为 %d，实际 %d", BlockSize, len(iv))
	}
	if len(ciphertext) == 0 || len(ciphertext)%BlockSize != 0 {
		return nil, errors.New("smcrypto: 密文长度非法")
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	return pkcs7Unpad(plain, BlockSize)
}

// GenerateKey 生成 SM2 密钥对。
func GenerateKey() (*sm2.PrivateKey, error) {
	return sm2.GenerateKey(rand.Reader)
}

// Sign 对原始消息做 SM2 签名，返回 ASN.1 DER 编码签名（含 ZA）。
func Sign(priv *sm2.PrivateKey, msg []byte) ([]byte, error) {
	return priv.SignWithSM2(rand.Reader, nil, msg)
}

// Verify 校验原始消息的 SM2 DER 签名。
func Verify(pub *ecdsa.PublicKey, msg, sig []byte) bool {
	return sm2.VerifyASN1WithSM2(pub, nil, msg, sig)
}

// MarshalPublic 将公钥编码为 65 字节未压缩格式。
func MarshalPublic(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(sm2.P256(), pub.X, pub.Y)
}

// ParsePublic 解析 65 字节未压缩格式的 SM2 公钥。
func ParsePublic(data []byte) (*ecdsa.PublicKey, error) {
	if len(data) != PublicKeySize {
		return nil, fmt.Errorf("smcrypto: 公钥长度应为 %d，实际 %d", PublicKeySize, len(data))
	}
	return sm2.NewPublicKey(data)
}

// PrivateScalar 取私钥标量 D 的 32 字节大端编码。
func PrivateScalar(priv *sm2.PrivateKey) []byte {
	out := make([]byte, ScalarSize)
	d := priv.D.Bytes()
	copy(out[ScalarSize-len(d):], d)
	return out
}

// PrivateFromScalar 由 32 字节标量重建 SM2 私钥。
func PrivateFromScalar(d []byte) (*sm2.PrivateKey, error) {
	if len(d) != ScalarSize {
		return nil, fmt.Errorf("smcrypto: 私钥标量长度应为 %d，实际 %d", ScalarSize, len(d))
	}
	return sm2.NewPrivateKey(d)
}

// Zero 尽力清零敏感切片；配合 runtime.KeepAlive 避免被编译器优化掉。
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+n)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(n)
	}
	return padded
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("smcrypto: 填充长度非法")
	}
	n := int(data[len(data)-1])
	if n == 0 || n > blockSize || n > len(data) {
		// 口令错误时极大概率落到这里
		return nil, errors.New("smcrypto: 填充校验失败")
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, errors.New("smcrypto: 填充校验失败")
		}
	}
	out := make([]byte, len(data)-n)
	copy(out, data[:len(data)-n])
	Zero(data)
	return out, nil
}
