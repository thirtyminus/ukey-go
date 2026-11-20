//go:build darwin

package machine

import (
	"errors"
	"os/exec"
	"strings"
)

// identifiers 依次返回 (平台UUID, 硬件序列号)。
func identifiers() (string, string, error) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", "", errors.New("无法执行 ioreg 读取设备信息: " + err.Error())
	}
	text := string(out)
	platform := ioProperty(text, "IOPlatformUUID")
	serial := ioProperty(text, "IOPlatformSerialNumber")
	if platform == "" {
		return "", "", errors.New("无法读取 IOPlatformUUID")
	}
	return platform, serial, nil
}

// ioProperty 从 ioreg 文本输出中提取形如 `"Key" = "Value"` 的值。
func ioProperty(out, key string) string {
	prefix := `"` + key + `" = `
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			value := strings.TrimPrefix(line, prefix)
			return strings.TrimSpace(strings.Trim(value, `"`))
		}
	}
	return ""
}
