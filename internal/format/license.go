package format

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"

	"ukey/internal/smcrypto"
	"ukey/internal/ukerr"
)

const (
	licenseMagic   = "LIC1"
	LicenseVersion = 1

	// LicenseFile 是介质内的 License 文件名。
	LicenseFile = "license.dat"
	// VendorPubFile 是介质内的厂商验签公钥文件名。
	VendorPubFile = "vendor.pub"
)

// License 是签发出去的授权内容，签名字节覆盖其 JSON 原文。
type License struct {
	Version     int      `json:"v"`
	KeyID       string   `json:"keyId"`
	MachineCode string   `json:"machineCode"`
	Features    []string `json:"features"`
	NotBefore   string   `json:"notBefore,omitempty"`
	NotAfter    string   `json:"notAfter,omitempty"`
	IssuedAt    string   `json:"issuedAt"`
	Serial      string   `json:"serial"`
}

// IssueLicense 用厂商私钥签发 License 并写入介质。
func IssueLicense(root string, lic *License, vendor *sm2.PrivateKey) error {
	lic.Version = LicenseVersion
	if lic.IssuedAt == "" {
		lic.IssuedAt = time.Now().UTC().Format(time.RFC3339)
	}
	body, err := json.Marshal(lic)
	if err != nil {
		return err
	}
	sig, err := smcrypto.Sign(vendor, body)
	if err != nil {
		return err
	}
	if len(body) > 0xFFFFFFFF || len(sig) > 0xFFFF {
		return ukkerr.ErrCorrupt
	}

	payload := make([]byte, 0, 11+len(body)+len(sig))
	payload = append(payload, licenseMagic...)
	payload = append(payload, LicenseVersion)
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(body)))
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(sig)))
	payload = append(payload, body...)
	payload = append(payload, sig...)

	if err := os.MkdirAll(filepath.Join(root, UKeyDir), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, UKeyDir, LicenseFile), payload, 0o600)
}

// VerifyLicense 读取并验签介质内的 License。
func VerifyLicense(root string, vendorPub *ecdsa.PublicKey) (*License, error) {
	body, sig, err := readLicenseFile(root)
	if err != nil {
		return nil, err
	}
	if !smcrypto.Verify(vendorPub, body, sig) {
		return nil, ukkerr.ErrLicenseInvalid
	}
	var lic License
	if err := json.Unmarshal(body, &lic); err != nil {
		return nil, ukkerr.ErrLicenseInvalid
	}
	if lic.Version != LicenseVersion {
		return nil, ukkerr.ErrLicenseInvalid
	}
	return &lic, nil
}

// PeekLicense 读取 License 明文，不验签，仅用于展示。
func PeekLicense(root string) (*License, error) {
	body, _, err := readLicenseFile(root)
	if err != nil {
		return nil, err
	}
	var lic License
	if err := json.Unmarshal(body, &lic); err != nil {
		return nil, ukkerr.ErrLicenseInvalid
	}
	return &lic, nil
}

// Validate 校验 License 与当前 UKey、机器、时间的匹配关系。
func (l *License) Validate(keyID, machineCode string, now time.Time) error {
	if !strings.EqualFold(l.KeyID, keyID) {
		return ukkerr.ErrKeyIDMismatch
	}
	if !strings.EqualFold(l.MachineCode, machineCode) {
		return ukkerr.ErrMachineMismatch
	}
	if l.NotBefore != "" {
		t, err := ParseLicenseTime(l.NotBefore)
		if err != nil {
			return ukkerr.ErrLicenseInvalid
		}
		if now.Before(t) {
			return ukkerr.ErrNotYetValid
		}
	}
	if l.NotAfter != "" {
		t, err := ParseLicenseTime(l.NotAfter)
		if err != nil {
			return ukkerr.ErrLicenseInvalid
		}
		if now.After(t) {
			return ukkerr.ErrExpired
		}
	}
	return nil
}

// HasFeature 判断授权是否包含指定功能项；空 Features 表示全部开放。
func (l *License) HasFeature(name string) bool {
	if len(l.Features) == 0 {
		return true
	}
	for _, f := range l.Features {
		if f == name {
			return true
		}
	}
	return false
}

// ParseLicenseTime 解析 RFC3339 或 YYYY-MM-DD；纯日期按当天 23:59:59 处理。
func ParseLicenseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, err
	}
	return t.Add(24*time.Hour - time.Second), nil
}

// WriteVendorPublic 把厂商公钥写入介质。
func WriteVendorPublic(root string, pub *ecdsa.PublicKey) error {
	encoded := hex.EncodeToString(smcrypto.MarshalPublic(pub))
	if err := os.MkdirAll(filepath.Join(root, UKeyDir), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, UKeyDir, VendorPubFile), []byte(encoded), 0o600)
}

// ReadVendorPublic 从介质读取厂商公钥。
func ReadVendorPublic(root string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(filepath.Join(root, UKeyDir, VendorPubFile))
	if err != nil {
		return nil, ukkerr.ErrLicenseInvalid
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, ukkerr.ErrLicenseInvalid
	}
	return smcrypto.ParsePublic(raw)
}

func readLicenseFile(root string) (body, sig []byte, err error) {
	data, err := os.ReadFile(filepath.Join(root, UKeyDir, LicenseFile))
	if err != nil {
		return nil, nil, ukkerr.ErrLicenseInvalid
	}
	rd := &reader{data: data}
	magic, err := rd.take(4)
	if err != nil || !bytes.Equal(magic, []byte(licenseMagic)) {
		return nil, nil, ukkerr.ErrLicenseInvalid
	}
	version, err := rd.u8()
	if err != nil || version != LicenseVersion {
		return nil, nil, ukkerr.ErrLicenseInvalid
	}
	bodyLen, err := rd.u32()
	if err != nil || bodyLen == 0 || int(bodyLen) > rd.remaining() {
		return nil, nil, ukkerr.ErrLicenseInvalid
	}
	sigLen, err := rd.u16()
	if err != nil || sigLen == 0 || int(sigLen) > rd.remaining() {
		return nil, nil, ukkerr.ErrLicenseInvalid
	}
	if body, err = rd.take(int(bodyLen)); err != nil {
		return nil, nil, ukkerr.ErrLicenseInvalid
	}
	if sig, err = rd.take(int(sigLen)); err != nil {
		return nil, nil, ukkerr.ErrLicenseInvalid
	}
	return body, sig, nil
}
