//go:build darwin

package media

import "testing"

// TestVolumeUUIDOnRoot 用真实挂载点验证 diskutil 解析路径。
func TestVolumeUUIDOnRoot(t *testing.T) {
	uuid, err := volumeUUID("/")
	if err != nil {
		t.Fatalf("volumeUUID(/): %v", err)
	}
	if uuid == "" {
		t.Fatal("根卷 Volume UUID 为空")
	}
	t.Logf("根卷 Volume UUID = %s", uuid)
}

// TestPhysicalSerialUnavailable 确认 darwin 走卷 UUID 回退路径。
func TestPhysicalSerialUnavailable(t *testing.T) {
	if _, err := physicalSerial("/"); err == nil {
		t.Fatal("darwin 不应返回物理序列号")
	}
}
