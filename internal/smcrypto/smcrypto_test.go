package smcrypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := DeriveKey([]byte("correct horse"), []byte("salt"), 1000)
	message := []byte("ukey private material")
	iv, ct, err := Encrypt(key, message)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(iv) != BlockSize {
		t.Fatalf("IV 长度 = %d, want %d", len(iv), BlockSize)
	}
	got, err := Decrypt(key, iv, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, message) {
		t.Fatalf("解密结果不一致: %q", got)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	key := DeriveKey([]byte("pass-a"), []byte("salt"), 1000)
	other := DeriveKey([]byte("pass-b"), []byte("salt"), 1000)
	iv, ct, err := Encrypt(key, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(other, iv, ct); err == nil {
		t.Fatal("错误密钥不应解密成功")
	}
}

func TestDeriveKeyDependsOnSalt(t *testing.T) {
	a := DeriveKey([]byte("pass"), []byte("salt-1"), 1000)
	b := DeriveKey([]byte("pass"), []byte("salt-2"), 1000)
	if bytes.Equal(a, b) {
		t.Fatal("不同盐应派生不同密钥")
	}
	if len(a) != KeySize {
		t.Fatalf("密钥长度 = %d, want %d", len(a), KeySize)
	}
}

func TestSM2SignVerify(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("machine-code-binding")
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(&priv.PublicKey, msg, sig) {
		t.Fatal("签名验签失败")
	}
	if Verify(&priv.PublicKey, []byte("tampered"), sig) {
		t.Fatal("被篡改的消息不应验签通过")
	}

	pubBytes := MarshalPublic(&priv.PublicKey)
	if len(pubBytes) != PublicKeySize {
		t.Fatalf("公钥长度 = %d, want %d", len(pubBytes), PublicKeySize)
	}
	pub, err := ParsePublic(pubBytes)
	if err != nil {
		t.Fatalf("ParsePublic: %v", err)
	}
	if !Verify(pub, msg, sig) {
		t.Fatal("序列化往返后验签失败")
	}
}

func TestPrivateScalarRoundTrip(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	scalar := PrivateScalar(priv)
	if len(scalar) != ScalarSize {
		t.Fatalf("标量长度 = %d, want %d", len(scalar), ScalarSize)
	}
	restored, err := PrivateFromScalar(scalar)
	if err != nil {
		t.Fatalf("PrivateFromScalar: %v", err)
	}
	if restored.D.Cmp(priv.D) != 0 {
		t.Fatal("还原私钥标量不一致")
	}
}

func TestZero(t *testing.T) {
	b := []byte("sensitive")
	Zero(b)
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatal("Zero 未清零")
	}
}
