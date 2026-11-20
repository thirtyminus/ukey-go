//go:build linux

package machine

import (
	"errors"
	"os"
	"strings"
)

// identifiers 依次返回 (平台UUID, 硬件序列号)。
func identifiers() (string, string, error) {
	platform := firstNonEmpty(
		readTrimmed("/sys/class/dmi/id/product_uuid"),
		readTrimmed("/etc/machine-id"),
	)
	if platform == "" {
		return "", "", errors.New("无法读取 product_uuid 或 machine-id")
	}
	serial := firstNonEmpty(
		readTrimmed("/sys/class/dmi/id/product_serial"),
		readTrimmed("/sys/class/dmi/id/board_serial"),
	)
	return platform, serial, nil
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" && v != "None" && v != "To Be Filled By O.E.M." {
			return v
		}
	}
	return ""
}
