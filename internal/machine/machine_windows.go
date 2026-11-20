//go:build windows

package machine

import (
	"errors"
	"os/exec"
	"strings"
)

// identifiers 依次返回 (平台UUID, 硬件序列号)。
func identifiers() (string, string, error) {
	const script = `$g=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid; ` +
		`$s=(Get-CimInstance Win32_BIOS).SerialNumber; Write-Output $g; Write-Output $s`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return "", "", errors.New("无法通过 PowerShell 读取 MachineGuid: " + err.Error())
	}
	lines := strings.Split(strings.ReplaceAll(strings.TrimSpace(string(out)), "\r\n", "\n"), "\n")
	platform := strings.TrimSpace(lines[0])
	if platform == "" {
		return "", "", errors.New("MachineGuid 为空")
	}
	serial := ""
	if len(lines) > 1 {
		serial = strings.TrimSpace(lines[1])
	}
	return platform, serial, nil
}
