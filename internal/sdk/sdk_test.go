package sdk

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ukey/internal/format"
	"ukey/internal/machine"
	"ukey/internal/smcrypto"
	"ukey/internal/ukerr"
)

var testFP = format.Fingerprint{Type: format.SaltTypeNone}

type fixture struct {
	root   string
	data   *format.UKeyData
	vendor *format.License
}

func setup(t *testing.T, lic *format.License) *fixture {
	t.Helper()
	root := t.TempDir()
	data, err := format.NewUKeyData()
	if err != nil {
		t.Fatalf("NewUKeyData: %v", err)
	}
	if err := format.Create(root, []byte("pass-123"), testFP, 0, data); err != nil {
		t.Fatalf("Create: %v", err)
	}
	vendor, err := smcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := format.WriteVendorPublic(root, &vendor.PublicKey); err != nil {
		t.Fatalf("WriteVendorPublic: %v", err)
	}
	code, err := machine.Code()
	if err != nil {
		t.Fatalf("machine.Code: %v", err)
	}
	if lic == nil {
		lic = &format.License{}
	}
	if lic.KeyID == "" {
		lic.KeyID = data.KeyID
	}
	if lic.MachineCode == "" {
		lic.MachineCode = code
	}
	if err := format.IssueLicense(root, lic, vendor); err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}
	return &fixture{root: root, data: data, vendor: lic}
}

func TestOpenAndVerifyLicense(t *testing.T) {
	f := setup(t, &format.License{Features: []string{"pro"}, NotAfter: "2099-12-31"})
	s, err := OpenWith(f.root, []byte("pass-123"), testFP)
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	defer s.Close()

	if s.KeyID() != f.data.KeyID {
		t.Fatalf("KeyID = %s, want %s", s.KeyID(), f.data.KeyID)
	}
	lic, err := s.VerifyLicense()
	if err != nil {
		t.Fatalf("VerifyLicense: %v", err)
	}
	if !lic.HasFeature("pro") {
		t.Fatal("应授权 pro")
	}
	if err := s.RequireFeature("pro"); err != nil {
		t.Fatalf("RequireFeature(pro): %v", err)
	}
	if err := s.RequireFeature("enterprise"); !errors.Is(err, ukkerr.ErrFeatureDenied) {
		t.Fatalf("RequireFeature(enterprise) = %v, want ErrFeatureDenied", err)
	}

	challenge := []byte("nonce-123456")
	sig, err := s.Sign(challenge)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !smcrypto.Verify(s.PublicKey(), challenge, sig) {
		t.Fatal("挑战响应签名校验失败")
	}
}

func TestVerifyLicenseMachineMismatch(t *testing.T) {
	f := setup(t, &format.License{MachineCode: "0123456789abcdef"})
	s, err := OpenWith(f.root, []byte("pass-123"), testFP)
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	defer s.Close()
	if _, err := s.VerifyLicense(); !errors.Is(err, ukkerr.ErrMachineMismatch) {
		t.Fatalf("err = %v, want ErrMachineMismatch", err)
	}
}

func TestVerifyLicenseExpired(t *testing.T) {
	f := setup(t, &format.License{NotAfter: "2020-01-01"})
	s, err := OpenWith(f.root, []byte("pass-123"), testFP)
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	defer s.Close()
	if _, err := s.VerifyLicense(); !errors.Is(err, ukkerr.ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestVerifyLicenseKeyIDMismatch(t *testing.T) {
	f := setup(t, &format.License{KeyID: "someone-else"})
	s, err := OpenWith(f.root, []byte("pass-123"), testFP)
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	defer s.Close()
	if _, err := s.VerifyLicense(); !errors.Is(err, ukkerr.ErrKeyIDMismatch) {
		t.Fatalf("err = %v, want ErrKeyIDMismatch", err)
	}
}

func TestOpenWrongPassphrase(t *testing.T) {
	f := setup(t, nil)
	if _, err := OpenWith(f.root, []byte("bad"), testFP); !errors.Is(err, ukkerr.ErrBadPassphrase) {
		t.Fatalf("err = %v, want ErrBadPassphrase", err)
	}
}

func TestWatchDetectsRemoval(t *testing.T) {
	f := setup(t, nil)
	s, err := OpenWith(f.root, []byte("pass-123"), testFP)
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	defer s.Close()
	if err := s.CheckAlive(); err != nil {
		t.Fatalf("CheckAlive: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lost := make(chan struct{})
	go s.Watch(ctx, func() { close(lost) })

	// 模拟拔盘：移除整个 .ukey 目录
	if err := os.RemoveAll(filepath.Join(f.root, format.UKeyDir)); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	select {
	case <-lost:
	case <-ctx.Done():
		t.Fatal("Watch 未在超时前检测到介质移除")
	}
	if err := s.CheckAlive(); !errors.Is(err, ukkerr.ErrMediaNotFound) {
		t.Fatalf("CheckAlive = %v, want ErrMediaNotFound", err)
	}
}

func TestOpenMediaMismatch(t *testing.T) {
	f := setup(t, nil)
	other := format.Fingerprint{Type: format.SaltTypeNone, Value: []byte("other-disk")}
	if _, err := OpenWith(f.root, []byte("pass-123"), other); !errors.Is(err, ukkerr.ErrMediaMismatch) {
		t.Fatalf("err = %v, want ErrMediaMismatch", err)
	}
}

func TestCloseClearsSigning(t *testing.T) {
	f := setup(t, nil)
	s, err := OpenWith(f.root, []byte("pass-123"), testFP)
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := s.Sign([]byte("x")); !errors.Is(err, ukkerr.ErrMediaNotFound) {
		t.Fatalf("Sign after Close = %v, want ErrMediaNotFound", err)
	}
}
