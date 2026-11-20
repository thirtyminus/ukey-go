//go:build darwin

package media

import (
	"errors"
	"os"
	"os/exec"
	"strings"
)

// candidates 枚举可能挂载 UKey 的路径。
func candidates() []string {
	entries, err := os.ReadDir("/Volumes")
	if err != nil {
		return nil
	}
	roots := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			roots = append(roots, "/Volumes/"+e.Name())
		}
	}
	return roots
}

// physicalSerial macOS 上多数 U 盘不暴露可靠串号，统一走卷 UUID。
func physicalSerial(root string) (string, error) {
	return "", errors.New("darwin: 不提供物理序列号")
}

// volumeUUID 读取 diskutil 输出的 Volume UUID（回退 Disk / Partition UUID）。
func volumeUUID(root string) (string, error) {
	out, err := exec.Command("diskutil", "info", root).Output()
	if err != nil {
		return "", err
	}
	for _, key := range []string{"Volume UUID:", "Disk / Partition UUID:"} {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, key) {
				if v := strings.TrimSpace(strings.TrimPrefix(line, key)); v != "" {
					return v, nil
				}
			}
		}
	}
	return "", errors.New("darwin: diskutil 未返回卷 UUID")
}
