//go:build linux

package media

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var baseDevicePattern = regexp.MustCompile(`^(nvme\d+n\d+|mmcblk\d+|sd[a-z]+|vd[a-z]+|hd[a-z]+)`)

// candidates 枚举可能挂载 UKey 的路径。
func candidates() []string {
	var roots []string
	for _, pattern := range []string{"/media/*/*", "/run/media/*/*", "/mnt/*"} {
		matches, _ := filepath.Glob(pattern)
		roots = append(roots, matches...)
	}
	return roots
}

// physicalSerial 从 /sys/block/<设备>/device/serial 读取 U 盘物理序列号。
func physicalSerial(root string) (string, error) {
	device := mountDevice(root)
	if device == "" {
		return "", errors.New("linux: 未找到挂载设备")
	}
	base := baseDevicePattern.FindString(filepath.Base(device))
	if base == "" {
		return "", errors.New("linux: 无法解析块设备名")
	}
	for _, path := range []string{
		"/sys/block/" + base + "/device/serial",
		"/sys/block/" + base + "/serial",
	} {
		if data, err := os.ReadFile(path); err == nil {
			if v := strings.TrimSpace(string(data)); v != "" {
				return v, nil
			}
		}
	}
	return "", errors.New("linux: 设备未暴露序列号")
}

// volumeUUID 通过 lsblk 读取文件系统 UUID。
func volumeUUID(root string) (string, error) {
	device := mountDevice(root)
	if device == "" {
		return "", errors.New("linux: 未找到挂载设备")
	}
	out, err := exec.Command("lsblk", "-no", "UUID", device).Output()
	if err != nil {
		return "", err
	}
	uuid := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	if uuid == "" {
		return "", errors.New("linux: 卷没有 UUID")
	}
	return uuid, nil
}

// mountDevice 从 /proc/mounts 找到挂载点对应的设备。
func mountDevice(root string) string {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		mountPoint := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`).Replace(fields[1])
		if strings.TrimSuffix(mountPoint, "/") == strings.TrimSuffix(root, "/") {
			return fields[0]
		}
	}
	return ""
}
