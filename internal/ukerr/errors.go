// Package ukkerr 定义 UKey 机制的哨兵错误码，供 keygen、sdk 与业务方统一判断。
package ukkerr

import "errors"

var (
	// ErrMediaNotFound 找不到 UKey 介质（缺少 .ukey 目录）。
	ErrMediaNotFound = errors.New("ukey: 未检测到 UKey 介质")

	// ErrMediaMismatch 介质指纹与 ukey.dat 绑定的介质不一致（多半是拷贝到别的盘）。
	ErrMediaMismatch = errors.New("ukey: 介质校验失败")

	// ErrMediaFingerprint 无法计算介质指纹（挂载点不可识别或缺少工具）。
	ErrMediaFingerprint = errors.New("ukey: 无法读取介质指纹")

	// ErrBadPassphrase 口令错误，或密文无法解密。
	ErrBadPassphrase = errors.New("ukey: 口令错误")

	// ErrLocked 连续口令失败次数超限，介质已锁定。
	ErrLocked = errors.New("ukey: 介质已锁定，失败次数超限")

	// ErrCorrupt 文件结构损坏或格式不受支持。
	ErrCorrupt = errors.New("ukey: 数据损坏或格式不支持")

	// ErrClockTamper 检测到系统时间回拨。
	ErrClockTamper = errors.New("ukey: 检测到系统时间回拨")

	// ErrLicenseInvalid License 签名无效或被篡改。
	ErrLicenseInvalid = errors.New("ukey: License 签名无效")

	// ErrMachineMismatch License 绑定的机器码与本机不一致。
	ErrMachineMismatch = errors.New("ukey: 机器码不符")

	// ErrExpired License 已过期。
	ErrExpired = errors.New("ukey: License 已过期")

	// ErrNotYetValid License 尚未生效。
	ErrNotYetValid = errors.New("ukey: License 尚未生效")

	// ErrKeyIDMismatch License 与当前 UKey 不是同一套。
	ErrKeyIDMismatch = errors.New("ukey: License 与当前 UKey 不匹配")

	// ErrFeatureDenied 当前 License 未授权所需功能项。
	ErrFeatureDenied = errors.New("ukey: 当前授权不包含该功能")
)
