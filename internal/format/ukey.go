// Package format 定义 UKey 介质与 License 的磁盘格式、加解密与校验逻辑。
package format

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"

	"ukey/internal/smcrypto"
	"ukey/internal/ukerr"
)

const (
	ukeyMagic     = "UKY1"
	FormatVersion = 1

	// UKeyDir 是介质根目录下的隐藏目录名。
	UKeyDir = ".ukey"
	// UKeyFileName 存放加密后的私钥材料。
	UKeyFileName = "ukey.dat"
	// MediaIDFile 存放明文介质指纹摘要，用于快速区分「错盘」与「错口令」。
	MediaIDFile = "media.id"
	// KeyIDFile 存放明文 KeyID，供签发端在不需要口令的情况下识别介质。
	KeyIDFile = "keyid"

	// DefaultIter 为 PBKDF2-SM3 的默认迭代次数。
	DefaultIter = 100000
	// MaxFailCount 为连续口令失败上限，超出后锁定。
	MaxFailCount = 5
	// ClockTolerance 为时间回拨检测的容差。
	ClockTolerance = 5 * time.Minute
	// rewriteInterval 控制 lastSeen 的落盘节流，避免频繁写 U 盘。
	rewriteInterval = time.Hour

	saltSize = 16
)

// 介质指纹类型。
const (
	SaltTypeNone           uint8 = iota // 无介质绑定（仅测试）
	SaltTypePhysicalSerial              // 介质物理序列号
	SaltTypeVolumeUUID                  // 卷 UUID 回退
)

// Fingerprint 描述 UKey 介质的指纹，参与密钥派生。
type Fingerprint struct {
	Type  uint8
	Value []byte
}

// Summary 返回可写入 media.id 的明文摘要。
func (f Fingerprint) Summary() string {
	h := smcrypto.Digest(append([]byte{f.Type, '|'}, f.Value...))
	return hex.EncodeToString(h[:8])
}

// UKeyData 是存放在 ukey.dat 加密区内的私有材料。
type UKeyData struct {
	KeyID     string `json:"keyId"`
	D         string `json:"d"`
	PublicKey string `json:"publicKey"`
	CreatedAt int64  `json:"createdAt"`
	LastSeen  int64  `json:"lastSeen"`
}

// HeaderInfo 是无需口令即可读取的明文头信息。
type HeaderInfo struct {
	Version   uint8
	SaltType  uint8
	Iter      uint32
	FailCount uint16
	Locked    bool
}

// PrivateKey 还原 SM2 私钥，并校验公私钥一致性。
func (d *UKeyData) PrivateKey() (*sm2.PrivateKey, error) {
	scalar, err := hex.DecodeString(d.D)
	if err != nil {
		return nil, ukkerr.ErrCorrupt
	}
	priv, err := smcrypto.PrivateFromScalar(scalar)
	smcrypto.Zero(scalar)
	if err != nil {
		return nil, ukkerr.ErrCorrupt
	}
	pubBytes, err := hex.DecodeString(d.PublicKey)
	if err != nil || !bytes.Equal(smcrypto.MarshalPublic(&priv.PublicKey), pubBytes) {
		return nil, ukkerr.ErrCorrupt
	}
	return priv, nil
}

// ParsePublicKey 解析 UKeyData 中的公钥。
func (d *UKeyData) ParsePublicKey() (*ecdsa.PublicKey, error) {
	raw, err := hex.DecodeString(d.PublicKey)
	if err != nil {
		return nil, ukkerr.ErrCorrupt
	}
	return smcrypto.ParsePublic(raw)
}

// NewUKeyData 生成一套全新的 UKey 密钥材料。
func NewUKeyData() (*UKeyData, error) {
	priv, err := smcrypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	keyID := make([]byte, 16)
	if _, err := rand.Read(keyID); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	data := &UKeyData{
		KeyID:     hex.EncodeToString(keyID),
		D:         hex.EncodeToString(smcrypto.PrivateScalar(priv)),
		PublicKey: hex.EncodeToString(smcrypto.MarshalPublic(&priv.PublicKey)),
		CreatedAt: now,
		LastSeen:  now,
	}
	return data, nil
}

// Create 在 root 下建立 .ukey 目录并写入加密的 ukey.dat。
// iter 为 0 时使用 DefaultIter。
func Create(root string, passphrase []byte, fp Fingerprint, iter int, data *UKeyData) error {
	if iter <= 0 {
		iter = DefaultIter
	}
	dir := filepath.Join(root, UKeyDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建 UKey 目录失败: %w", err)
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	raw, err := encryptUKey(salt, uint32(iter), passphrase, fp, data)
	if err != nil {
		return err
	}
	if err := writeRaw(dir, raw); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, MediaIDFile), []byte(fp.Summary()), 0o600); err != nil {
		return fmt.Errorf("写入 media.id 失败: %w", err)
	}
	if err := WriteKeyID(root, data.KeyID); err != nil {
		return err
	}
	return nil
}

// WriteKeyID 写入明文 KeyID。
func WriteKeyID(root, keyID string) error {
	dir := filepath.Join(root, UKeyDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, KeyIDFile), []byte(keyID), 0o600)
}

// ReadKeyID 读取明文 KeyID。
func ReadKeyID(root string) (string, error) {
	data, err := os.ReadFile(filepath.Join(root, UKeyDir, KeyIDFile))
	if err != nil {
		return "", ukkerr.ErrMediaNotFound
	}
	return strings.TrimSpace(string(data)), nil
}

// Unlock 解密 ukey.dat 并刷新 lastSeen / 失败计数。
func Unlock(root string, passphrase []byte, fp Fingerprint) (*UKeyData, error) {
	dir := filepath.Join(root, UKeyDir)
	raw, err := readRaw(dir)
	if err != nil {
		return nil, err
	}
	if raw.saltType != fp.Type {
		return nil, ukkerr.ErrMediaMismatch
	}
	if mediaID, err := os.ReadFile(filepath.Join(dir, MediaIDFile)); err == nil {
		if string(mediaID) != fp.Summary() {
			return nil, ukkerr.ErrMediaMismatch
		}
	}

	key := deriveKey(passphrase, raw.salt, fp.Value, raw.iter)
	plain, derr := smcrypto.Decrypt(key, raw.iv, raw.cipher)
	smcrypto.Zero(key)
	if derr != nil {
		raw.failCount++
		if raw.failCount >= MaxFailCount {
			raw.locked = true
		}
		_ = writeRaw(dir, raw)
		if raw.locked {
			return nil, ukkerr.ErrLocked
		}
		return nil, ukkerr.ErrBadPassphrase
	}
	defer smcrypto.Zero(plain)

	var data UKeyData
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, ukkerr.ErrCorrupt
	}
	if _, err := data.PrivateKey(); err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	if data.LastSeen > 0 && now < data.LastSeen-int64(ClockTolerance.Seconds()) {
		return nil, ukkerr.ErrClockTamper
	}
	previous := data.LastSeen
	if now > data.LastSeen {
		data.LastSeen = now
	}
	// 口令正确即视为解锁成功，顺带清空失败计数；lastSeen 按小时节流落盘。
	if raw.failCount != 0 || raw.locked || now-previous >= int64(rewriteInterval.Seconds()) {
		if fresh, err := encryptUKey(raw.salt, raw.iter, passphrase, fp, &data); err == nil {
			_ = writeRaw(dir, fresh)
		}
	}
	return &data, nil
}

// Inspect 只读取明文头，不需要口令。
func Inspect(root string) (*HeaderInfo, error) {
	raw, err := readRaw(filepath.Join(root, UKeyDir))
	if err != nil {
		return nil, err
	}
	return &HeaderInfo{
		Version:   raw.version,
		SaltType:  raw.saltType,
		Iter:      raw.iter,
		FailCount: raw.failCount,
		Locked:    raw.locked,
	}, nil
}

// Locate 检查某个挂载点是否含有 UKey 介质，返回 UKey 根目录。
func Locate(root string) (string, error) {
	info, err := os.Stat(filepath.Join(root, UKeyDir, UKeyFileName))
	if err != nil || info.IsDir() {
		return "", ukkerr.ErrMediaNotFound
	}
	return root, nil
}

func deriveKey(passphrase, salt, fingerprint []byte, iter uint32) []byte {
	combined := make([]byte, 0, len(salt)+len(fingerprint))
	combined = append(combined, salt...)
	combined = append(combined, fingerprint...)
	return smcrypto.DeriveKey(passphrase, combined, int(iter))
}

func encryptUKey(salt []byte, iter uint32, passphrase []byte, fp Fingerprint, data *UKeyData) (*rawUKey, error) {
	key := deriveKey(passphrase, salt, fp.Value, iter)
	defer smcrypto.Zero(key)
	plain, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	defer smcrypto.Zero(plain)
	iv, ct, err := smcrypto.Encrypt(key, plain)
	if err != nil {
		return nil, err
	}
	return &rawUKey{
		version:  FormatVersion,
		saltType: fp.Type,
		iter:     iter,
		salt:     append([]byte(nil), salt...),
		iv:       iv,
		cipher:   ct,
	}, nil
}

type rawUKey struct {
	version   uint8
	saltType  uint8
	iter      uint32
	salt      []byte
	iv        []byte
	failCount uint16
	locked    bool
	cipher    []byte
}

func (r *rawUKey) marshal() []byte {
	buf := make([]byte, 0, 32+len(r.salt)+len(r.iv)+len(r.cipher))
	buf = append(buf, ukeyMagic...)
	buf = append(buf, r.version, r.saltType)
	buf = binary.BigEndian.AppendUint32(buf, r.iter)
	buf = append(buf, byte(len(r.salt)))
	buf = append(buf, r.salt...)
	buf = append(buf, byte(len(r.iv)))
	buf = append(buf, r.iv...)
	buf = binary.BigEndian.AppendUint16(buf, r.failCount)
	if r.locked {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(r.cipher)))
	buf = append(buf, r.cipher...)
	return buf
}

func parseRaw(data []byte) (*rawUKey, error) {
	rd := &reader{data: data}
	magic, err := rd.take(4)
	if err != nil || !bytes.Equal(magic, []byte(ukeyMagic)) {
		return nil, ukkerr.ErrCorrupt
	}
	r := &rawUKey{}
	if r.version, err = rd.u8(); err != nil || r.version != FormatVersion {
		return nil, ukkerr.ErrCorrupt
	}
	if r.saltType, err = rd.u8(); err != nil {
		return nil, ukkerr.ErrCorrupt
	}
	if r.iter, err = rd.u32(); err != nil || r.iter == 0 {
		return nil, ukkerr.ErrCorrupt
	}
	saltLen, err := rd.u8()
	if err != nil || saltLen == 0 {
		return nil, ukkerr.ErrCorrupt
	}
	if r.salt, err = rd.take(int(saltLen)); err != nil {
		return nil, ukkerr.ErrCorrupt
	}
	ivLen, err := rd.u8()
	if err != nil || ivLen != smcrypto.BlockSize {
		return nil, ukkerr.ErrCorrupt
	}
	if r.iv, err = rd.take(int(ivLen)); err != nil {
		return nil, ukkerr.ErrCorrupt
	}
	if r.failCount, err = rd.u16(); err != nil {
		return nil, ukkerr.ErrCorrupt
	}
	locked, err := rd.u8()
	if err != nil {
		return nil, ukkerr.ErrCorrupt
	}
	r.locked = locked == 1
	cipherLen, err := rd.u32()
	if err != nil || cipherLen == 0 || int(cipherLen) > rd.remaining() {
		return nil, ukkerr.ErrCorrupt
	}
	if r.cipher, err = rd.take(int(cipherLen)); err != nil {
		return nil, ukkerr.ErrCorrupt
	}
	return r, nil
}

func readRaw(dir string) (*rawUKey, error) {
	data, err := os.ReadFile(filepath.Join(dir, UKeyFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ukkerr.ErrMediaNotFound
		}
		return nil, err
	}
	return parseRaw(data)
}

func writeRaw(dir string, r *rawUKey) error {
	path := filepath.Join(dir, UKeyFileName)
	tmp := path + ".tmp"
	payload := r.marshal()
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		// 部分 FAT/exFAT 卷不支持通过重命名覆盖，回退为直接写
		_ = os.Remove(tmp)
		return os.WriteFile(path, payload, 0o600)
	}
	return nil
}

type reader struct {
	data []byte
	off  int
}

func (r *reader) remaining() int { return len(r.data) - r.off }

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.off+n > len(r.data) {
		return nil, errors.New("short read")
	}
	out := r.data[r.off : r.off+n]
	r.off += n
	return out, nil
}

func (r *reader) u8() (uint8, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *reader) u16() (uint16, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *reader) u32() (uint32, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}
