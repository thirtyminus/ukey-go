package format

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ukey/internal/smcrypto"
	"ukey/internal/ukerr"
)

var testFP = Fingerprint{Type: SaltTypeNone}

func newTestMedia(t *testing.T) (root string, data *UKeyData) {
	t.Helper()
	root = t.TempDir()
	data, err := NewUKeyData()
	if err != nil {
		t.Fatalf("NewUKeyData: %v", err)
	}
	if err := Create(root, []byte("pass-123"), testFP, 0, data); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return root, data
}

func TestCreateUnlockRoundTrip(t *testing.T) {
	root, created := newTestMedia(t)
	got, err := Unlock(root, []byte("pass-123"), testFP)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if got.KeyID != created.KeyID || got.PublicKey != created.PublicKey {
		t.Fatal("解锁得到的密钥材料与创建时不一致")
	}
	priv, err := got.PrivateKey()
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}
	sig, err := smcrypto.Sign(priv, []byte("challenge"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pub, err := got.ParsePublicKey()
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !smcrypto.Verify(pub, []byte("challenge"), sig) {
		t.Fatal("解锁后的私钥无法完成签名验证")
	}
}

func TestUnlockWrongPassphrase(t *testing.T) {
	root, _ := newTestMedia(t)
	if _, err := Unlock(root, []byte("wrong"), testFP); !errors.Is(err, ukkerr.ErrBadPassphrase) {
		t.Fatalf("err = %v, want ErrBadPassphrase", err)
	}
}

func TestUnlockMediaMismatch(t *testing.T) {
	root, _ := newTestMedia(t)
	// 同类型但不同指纹（模拟拷到另一块盘）
	other := Fingerprint{Type: SaltTypeNone, Value: []byte("another-media")}
	if _, err := Unlock(root, []byte("pass-123"), other); !errors.Is(err, ukkerr.ErrMediaMismatch) {
		t.Fatalf("err = %v, want ErrMediaMismatch", err)
	}
	// 介质类型不同
	if _, err := Unlock(root, []byte("pass-123"), Fingerprint{Type: SaltTypeVolumeUUID, Value: []byte("x")}); !errors.Is(err, ukkerr.ErrMediaMismatch) {
		t.Fatalf("err = %v, want ErrMediaMismatch", err)
	}
}

func TestUnlockLockoutAndRecovery(t *testing.T) {
	root, _ := newTestMedia(t)
	for i := 0; i < MaxFailCount; i++ {
		_, err := Unlock(root, []byte("bad"), testFP)
		if i < MaxFailCount-1 && !errors.Is(err, ukkerr.ErrBadPassphrase) {
			t.Fatalf("第 %d 次错误口令 err = %v", i+1, err)
		}
		if i == MaxFailCount-1 && !errors.Is(err, ukkerr.ErrLocked) {
			t.Fatalf("第 %d 次错误口令 err = %v, want ErrLocked", i+1, err)
		}
	}
	// 锁定后仍然可以用正确口令解锁（安全性来自口令本身）
	if _, err := Unlock(root, []byte("pass-123"), testFP); err != nil {
		t.Fatalf("锁定后正确口令应可解锁: %v", err)
	}
	info, err := Inspect(root)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.FailCount != 0 || info.Locked {
		t.Fatalf("解锁后应清空失败计数, got=%+v", info)
	}
}

func TestUnlockClockTamper(t *testing.T) {
	root, _ := newTestMedia(t)
	data, err := Unlock(root, []byte("pass-123"), testFP)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	// 把 lastSeen 改到未来 1 小时，模拟时间回拨
	data.LastSeen = time.Now().Add(time.Hour).Unix()
	dir := filepath.Join(root, UKeyDir)
	raw, err := readRaw(dir)
	if err != nil {
		t.Fatalf("readRaw: %v", err)
	}
	fresh, err := encryptUKey(raw.salt, raw.iter, []byte("pass-123"), testFP, data)
	if err != nil {
		t.Fatalf("encryptUKey: %v", err)
	}
	if err := writeRaw(dir, fresh); err != nil {
		t.Fatalf("writeRaw: %v", err)
	}
	if _, err := Unlock(root, []byte("pass-123"), testFP); !errors.Is(err, ukkerr.ErrClockTamper) {
		t.Fatalf("err = %v, want ErrClockTamper", err)
	}
}

func TestUnlockCorruptFile(t *testing.T) {
	root, _ := newTestMedia(t)
	path := filepath.Join(root, UKeyDir, UKeyFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	raw[4] = 0xFF // 破坏版本号
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Unlock(root, []byte("pass-123"), testFP); !errors.Is(err, ukkerr.ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
}

func TestInspectDoesNotNeedPassphrase(t *testing.T) {
	root, _ := newTestMedia(t)
	info, err := Inspect(root)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.Version != FormatVersion || info.Iter != DefaultIter || info.SaltType != SaltTypeNone {
		t.Fatalf("头信息异常: %+v", info)
	}
}

func TestLocate(t *testing.T) {
	root, _ := newTestMedia(t)
	got, err := Locate(root)
	if err != nil || got != root {
		t.Fatalf("Locate = %q, %v", got, err)
	}
	if _, err := Locate(t.TempDir()); !errors.Is(err, ukkerr.ErrMediaNotFound) {
		t.Fatalf("空目录 err = %v, want ErrMediaNotFound", err)
	}
}

func TestLicenseIssueVerifyAndValidate(t *testing.T) {
	root, data := newTestMedia(t)
	vendor, err := smcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	lic := &License{
		KeyID:       data.KeyID,
		MachineCode: "ABCD1234",
		Features:    []string{"pro"},
		NotAfter:    "2099-12-31",
		Serial:      "L-0001",
	}
	if err := IssueLicense(root, lic, vendor); err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}
	pub, err := smcrypto.ParsePublic(smcrypto.MarshalPublic(&vendor.PublicKey))
	if err != nil {
		t.Fatalf("ParsePublic: %v", err)
	}
	got, err := VerifyLicense(root, pub)
	if err != nil {
		t.Fatalf("VerifyLicense: %v", err)
	}
	if err := got.Validate(data.KeyID, "abcd1234", time.Now()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !got.HasFeature("pro") || got.HasFeature("enterprise") {
		t.Fatal("功能位判断异常")
	}
	if err := got.Validate("other-key", "abcd1234", time.Now()); !errors.Is(err, ukkerr.ErrKeyIDMismatch) {
		t.Fatalf("err = %v, want ErrKeyIDMismatch", err)
	}
	if err := got.Validate(data.KeyID, "deadbeef", time.Now()); !errors.Is(err, ukkerr.ErrMachineMismatch) {
		t.Fatalf("err = %v, want ErrMachineMismatch", err)
	}
	if err := got.Validate(data.KeyID, "abcd1234", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ukkerr.ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestLicenseTamperedBody(t *testing.T) {
	root, data := newTestMedia(t)
	vendor, err := smcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	lic := &License{KeyID: data.KeyID, MachineCode: "AA", Features: []string{"basic"}}
	if err := IssueLicense(root, lic, vendor); err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}
	// 直接把 Features 改成 pro（不重新签名）
	path := filepath.Join(root, UKeyDir, LicenseFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	bodyLen := int(raw[5])<<24 | int(raw[6])<<16 | int(raw[7])<<8 | int(raw[8])
	body := string(raw[9 : 9+bodyLen])
	body = replaceFirst(body, "basic", "pro!!")
	copy(raw[9:9+bodyLen], []byte(body))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	pub := &vendor.PublicKey
	if _, err := VerifyLicense(root, pub); !errors.Is(err, ukkerr.ErrLicenseInvalid) {
		t.Fatalf("err = %v, want ErrLicenseInvalid", err)
	}
}

func TestVendorPublicRoundTrip(t *testing.T) {
	root := t.TempDir()
	vendor, err := smcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := WriteVendorPublic(root, &vendor.PublicKey); err != nil {
		t.Fatalf("WriteVendorPublic: %v", err)
	}
	pub, err := ReadVendorPublic(root)
	if err != nil {
		t.Fatalf("ReadVendorPublic: %v", err)
	}
	if pub.X.Cmp(vendor.PublicKey.X) != 0 || pub.Y.Cmp(vendor.PublicKey.Y) != 0 {
		t.Fatal("公钥往返不一致")
	}
}

func TestParseLicenseTime(t *testing.T) {
	got, err := ParseLicenseTime("2027-12-31")
	if err != nil {
		t.Fatalf("ParseLicenseTime: %v", err)
	}
	if want := mustTime(t, "2027-12-31T23:59:59Z"); !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if _, err := ParseLicenseTime("not-a-date"); err == nil {
		t.Fatal("非法时间应报错")
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return tm
}

func replaceFirst(s, old, new string) string {
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + new + s[i+len(old):]
		}
	}
	return s
}

// 确保测试未使用未导出结构体字段时序列化仍可读
var _ = json.Marshal
