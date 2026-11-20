// Package machine 计算用于 License 绑定的机器码。
//
// 机器码 = SM3("ukey-machine-v1|" + 平台UUID + "|" + 硬件序列号) 的前 16 字节。
// 刻意不使用网卡 MAC：换网卡或插 USB 网卡会导致授权误杀。
package machine

import (
	"encoding/hex"
	"strings"

	"ukey/internal/smcrypto"
)

// Code 返回 32 位小写十六进制机器码。
func Code() (string, error) {
	platform, serial, err := identifiers()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(serial) == "" {
		serial = "no-serial"
	}
	material := "ukey-machine-v1|" + strings.ToLower(strings.TrimSpace(platform)) + "|" + strings.ToLower(strings.TrimSpace(serial))
	sum := smcrypto.Digest([]byte(material))
	return hex.EncodeToString(sum[:16]), nil
}
