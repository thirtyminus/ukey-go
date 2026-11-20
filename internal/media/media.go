// Package media 负责定位 UKey 介质并计算参与密钥派生的介质指纹。
package media

import (
	"strings"

	"ukey/internal/format"
	"ukey/internal/ukerr"
)

// Locate 返回包含 .ukey 目录的挂载点；volume 为空时按平台扫描候选挂载点。
func Locate(volume string) (string, error) {
	if volume != "" {
		return format.Locate(volume)
	}
	for _, root := range candidates() {
		if found, err := format.Locate(root); err == nil {
			return found, nil
		}
	}
	return "", ukkerr.ErrMediaNotFound
}

// Fingerprint 计算介质指纹：物理序列号优先，取不到时回退卷 UUID/卷序列号。
func Fingerprint(root string) (format.Fingerprint, error) {
	if serial, err := physicalSerial(root); err == nil && strings.TrimSpace(serial) != "" {
		return format.Fingerprint{Type: format.SaltTypePhysicalSerial, Value: []byte(strings.TrimSpace(serial))}, nil
	}
	if uuid, err := volumeUUID(root); err == nil && strings.TrimSpace(uuid) != "" {
		return format.Fingerprint{Type: format.SaltTypeVolumeUUID, Value: []byte(strings.TrimSpace(uuid))}, nil
	}
	return format.Fingerprint{}, ukkerr.ErrMediaFingerprint
}

// Resolve 按 mode 计算指纹，供 keygen --salt 使用。
//
// mode: auto（默认）| serial | volume | none。
func Resolve(root, mode string) (format.Fingerprint, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		return Fingerprint(root)
	case "none":
		return format.Fingerprint{Type: format.SaltTypeNone}, nil
	case "serial":
		serial, err := physicalSerial(root)
		if err != nil || strings.TrimSpace(serial) == "" {
			return format.Fingerprint{}, ukkerr.ErrMediaFingerprint
		}
		return format.Fingerprint{Type: format.SaltTypePhysicalSerial, Value: []byte(strings.TrimSpace(serial))}, nil
	case "volume":
		uuid, err := volumeUUID(root)
		if err != nil || strings.TrimSpace(uuid) == "" {
			return format.Fingerprint{}, ukkerr.ErrMediaFingerprint
		}
		return format.Fingerprint{Type: format.SaltTypeVolumeUUID, Value: []byte(strings.TrimSpace(uuid))}, nil
	default:
		return format.Fingerprint{}, ukkerr.ErrMediaFingerprint
	}
}
