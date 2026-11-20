// Package sdk 提供给业务侧集成的 UKey 授权校验 API。
//
// 典型用法：
//
//	s, err := sdk.Open("/Volumes/KEY", passphrase)
//	defer s.Close()
//	lic, err := s.VerifyLicense()
//	go s.Watch(ctx, func() { 进入受限模式() })
package sdk

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/emmansun/gmsm/sm2"

	"ukey/internal/format"
	"ukey/internal/machine"
	"ukey/internal/media"
	"ukey/internal/smcrypto"
	"ukey/internal/ukerr"
)

// VendorPublicKeyHex 是签发方验签公钥（65 字节未压缩，hex）。
//
// 生产构建应通过
//
//	go build -ldflags "-X ukey/internal/sdk.VendorPublicKeyHex=<hex>"
//
// 注入，避免信任根落在可写的 U 盘上。为空时才回退读取介质内的 vendor.pub。
var VendorPublicKeyHex = ""

// Session 表示一次已解锁的 UKey 会话。
type Session struct {
	root        string
	fingerprint format.Fingerprint
	data        *format.UKeyData
	priv        *sm2.PrivateKey
	vendorPub   *ecdsa.PublicKey
	license     *format.License
}

// Open 定位介质并解锁；volume 为空时自动扫描挂载点。
func Open(volume string, passphrase []byte) (*Session, error) {
	root, err := media.Locate(volume)
	if err != nil {
		return nil, err
	}
	fp, err := media.Fingerprint(root)
	if err != nil {
		return nil, err
	}
	return OpenWith(root, passphrase, fp)
}

// OpenWith 使用显式介质指纹解锁，供测试与特殊部署使用。
func OpenWith(root string, passphrase []byte, fp format.Fingerprint) (*Session, error) {
	data, err := format.Unlock(root, passphrase, fp)
	if err != nil {
		return nil, err
	}
	priv, err := data.PrivateKey()
	if err != nil {
		return nil, err
	}
	vendorPub, err := loadVendorPublic(root)
	if err != nil {
		return nil, err
	}
	return &Session{
		root:        root,
		fingerprint: fp,
		data:        data,
		priv:        priv,
		vendorPub:   vendorPub,
	}, nil
}

// KeyID 返回当前介质的 KeyID。
func (s *Session) KeyID() string { return s.data.KeyID }

// PublicKey 返回当前 UKey 的 SM2 公钥。
func (s *Session) PublicKey() *ecdsa.PublicKey { return &s.priv.PublicKey }

// Root 返回介质挂载点。
func (s *Session) Root() string { return s.root }

// VendorPublicKey 返回签发方验签公钥。
func (s *Session) VendorPublicKey() *ecdsa.PublicKey { return s.vendorPub }

// MachineCode 返回本机机器码。
func MachineCode() (string, error) { return machine.Code() }

// VerifyLicense 验签 License 并校验机器码、KeyID 与有效期。
func (s *Session) VerifyLicense() (*format.License, error) {
	lic, err := format.VerifyLicense(s.root, s.vendorPub)
	if err != nil {
		return nil, err
	}
	code, err := machine.Code()
	if err != nil {
		return nil, err
	}
	if err := lic.Validate(s.data.KeyID, code, time.Now()); err != nil {
		return nil, err
	}
	s.license = lic
	return lic, nil
}

// RequireFeature 确认已授权指定功能项。
func (s *Session) RequireFeature(name string) error {
	if s.license == nil {
		if _, err := s.VerifyLicense(); err != nil {
			return err
		}
	}
	if !s.license.HasFeature(name) {
		return ukkerr.ErrFeatureDenied
	}
	return nil
}

// Sign 用 UKey 私钥对消息做 SM2 签名（挑战响应场景）。
func (s *Session) Sign(msg []byte) ([]byte, error) {
	if s.priv == nil {
		return nil, ukkerr.ErrMediaNotFound
	}
	return smcrypto.Sign(s.priv, msg)
}

// CheckAlive 检查介质仍在且 ukey.dat 可读。
func (s *Session) CheckAlive() error {
	path := filepath.Join(s.root, format.UKeyDir, format.UKeyFileName)
	f, err := os.Open(path)
	if err != nil {
		return ukkerr.ErrMediaNotFound
	}
	defer f.Close()
	header := make([]byte, 4)
	if _, err := f.Read(header); err != nil {
		return ukkerr.ErrMediaNotFound
	}
	return nil
}

// Watch 轮询介质可用性，连续两次读取失败后回调 onLost 并返回。
func (s *Session) Watch(ctx context.Context, onLost func()) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.CheckAlive(); err != nil {
				failures++
				if failures >= 2 {
					onLost()
					return
				}
				continue
			}
			failures = 0
		}
	}
}

// Close 释放会话内的私钥引用。
func (s *Session) Close() error {
	if s.data != nil {
		s.data.D = ""
	}
	s.priv = nil
	s.license = nil
	return nil
}

func loadVendorPublic(root string) (*ecdsa.PublicKey, error) {
	if VendorPublicKeyHex != "" {
		raw, err := hex.DecodeString(VendorPublicKeyHex)
		if err != nil {
			return nil, ukkerr.ErrLicenseInvalid
		}
		return smcrypto.ParsePublic(raw)
	}
	// 开发期回退：信任根在介质上意味着持有介质写权限者可自行签发 License，
	// 因此生产环境务必通过 -ldflags 注入 VendorPublicKeyHex。
	fmt.Fprintln(os.Stderr, "[ukey] 警告: 未内置厂商公钥，回退读取介质上的 vendor.pub，仅建议开发期使用")
	return format.ReadVendorPublic(root)
}
