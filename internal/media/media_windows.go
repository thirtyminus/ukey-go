//go:build windows

package media

import (
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var volumeSerialPattern = regexp.MustCompile(`(?i)serial number is\s+([0-9A-F-]+)`)

// candidates 枚举 D: 到 Z: 的盘符。
func candidates() []string {
	var roots []string
	for c := 'D'; c <= 'Z'; c++ {
		root := string(c) + `:\`
		if _, err := os.Stat(root); err == nil {
			roots = append(roots, root)
		}
	}
	return roots
}

// physicalSerial Windows 上多块 USB 盘容易取错，统一走卷序列号。
func physicalSerial(root string) (string, error) {
	return "", errors.New("windows: 不提供物理序列号")
}

// volumeUUID 通过 vol 命令读取卷序列号。
func volumeUUID(root string) (string, error) {
	drive := strings.TrimSuffix(strings.TrimSuffix(root, `\`), ":")
	if drive == "" {
		return "", errors.New("windows: 盘符为空")
	}
	out, err := exec.Command("cmd", "/c", "vol", drive+":").Output()
	if err != nil {
		return "", err
	}
	m := volumeSerialPattern.FindStringSubmatch(string(out))
	if len(m) < 2 {
		return "", errors.New("windows: vol 未返回卷序列号")
	}
	return m[1], nil
}
