// Command keygen 是 UKey 的签发与自检工具。
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/emmansun/gmsm/sm2"
	"golang.org/x/term"

	"ukey/internal/format"
	"ukey/internal/machine"
	"ukey/internal/media"
	"ukey/internal/sdk"
	"ukey/internal/smcrypto"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "issue":
		cmdIssue(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "info":
		cmdInfo(os.Args[2:])
	case "machine-code":
		code, err := machine.Code()
		if err != nil {
			fatal(err)
		}
		fmt.Println(code)
	case "version", "-v", "--version":
		fmt.Println("keygen " + version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `keygen —— UKey 签发与自检工具

用法:
  keygen init   --dir <挂载点> [--vendor ./vendor.key] [--salt auto|serial|volume|none] [--iter N] [--force]
  keygen issue  --key <挂载点> [--vendor ./vendor.key] [--machine-code HEX] [--features a,b]
                [--expire 2027-12-31] [--not-before 2026-01-01] [--serial S] [--key-id ID] [-o license.dat]
  keygen verify --dir <挂载点> [--salt auto|serial|volume|none]
  keygen info   --dir <挂载点>
  keygen machine-code
  keygen version

说明:
  init    在介质根目录建立 .ukey/，生成 UKey 密钥对并写入加密的 ukey.dat
  issue   用厂商私钥签发 license.dat（默认绑定本机机器码）
  verify  校验口令、介质指纹、私钥可用性与 License 全部约束
  info    只读展示明文头与 License 内容，不需要口令
`)
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "", "UKey 挂载点，例如 /Volumes/KEY")
	vendorPath := fs.String("vendor", "./vendor.key", "厂商签名密钥文件，不存在则自动生成")
	saltMode := fs.String("salt", "auto", "介质指纹模式: auto|serial|volume|none")
	iter := fs.Int("iter", format.DefaultIter, "PBKDF2-SM3 迭代次数")
	force := fs.Bool("force", false, "覆盖已存在的 UKey")
	fs.Parse(args)

	if *dir == "" {
		fatal(errors.New("必须指定 --dir"))
	}
	info, err := os.Stat(*dir)
	if err != nil || !info.IsDir() {
		fatal(fmt.Errorf("挂载点不可用: %s", *dir))
	}
	if !*force {
		if _, err := os.Stat(filepath.Join(*dir, format.UKeyDir, format.UKeyFileName)); err == nil {
			fatal(errors.New("该介质已存在 UKey，如需重建请加 --force"))
		}
	}

	vendor, created, err := loadOrCreateVendor(*vendorPath)
	if err != nil {
		fatal(err)
	}
	fp, err := media.Resolve(*dir, *saltMode)
	if err != nil {
		fatal(fmt.Errorf("计算介质指纹失败: %w（本地目录测试可加 --salt none）", err))
	}
	data, err := format.NewUKeyData()
	if err != nil {
		fatal(err)
	}
	pass := readNewPassphrase()
	if err := format.Create(*dir, pass, fp, *iter, data); err != nil {
		fatal(err)
	}
	if err := format.WriteVendorPublic(*dir, &vendor.PublicKey); err != nil {
		fatal(err)
	}

	vendorPubHex := hex.EncodeToString(smcrypto.MarshalPublic(&vendor.PublicKey))
	fmt.Println("UKey 初始化完成")
	fmt.Printf("  挂载点        : %s\n", *dir)
	fmt.Printf("  KeyID         : %s\n", data.KeyID)
	fmt.Printf("  指纹类型      : %s\n", saltTypeName(fp.Type))
	fmt.Printf("  迭代次数      : %d\n", *iter)
	if created {
		fmt.Printf("  厂商密钥      : %s（请离线保管，丢失后无法再签发 License）\n", *vendorPath)
	} else {
		fmt.Printf("  厂商密钥      : 复用 %s\n", *vendorPath)
	}
	fmt.Printf("  厂商公钥(hex) : %s\n", vendorPubHex)
	fmt.Println()
	fmt.Println("生产构建注入信任根：")
	fmt.Printf("  go build -ldflags \"-X ukey/internal/sdk.VendorPublicKeyHex=%s\" ./cmd/demo-app\n", vendorPubHex)
}

func cmdIssue(args []string) {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	key := fs.String("key", "", "UKey 挂载点")
	vendorPath := fs.String("vendor", "./vendor.key", "厂商签名密钥文件")
	machineCode := fs.String("machine-code", "", "绑定机器码，留空取本机")
	features := fs.String("features", "", "功能项，逗号分隔；留空表示全部开放")
	expire := fs.String("expire", "", "到期时间 YYYY-MM-DD 或 RFC3339；留空为永久")
	notBefore := fs.String("not-before", "", "生效时间，格式同上")
	serial := fs.String("serial", "", "授权序列号")
	out := fs.String("out", "", "额外导出一份 license.dat 的路径")
	keyID := fs.String("key-id", "", "覆盖 KeyID，默认读取介质内 keyid 文件")
	fs.Parse(args)

	if *key == "" {
		fatal(errors.New("必须指定 --key"))
	}
	vendor, err := readVendor(*vendorPath)
	if err != nil {
		fatal(fmt.Errorf("读取厂商密钥失败: %w（请先执行 keygen init 生成）", err))
	}

	id := strings.TrimSpace(*keyID)
	if id == "" {
		if id, err = format.ReadKeyID(*key); err != nil {
			fatal(fmt.Errorf("读取 KeyID 失败: %w", err))
		}
	}
	code := strings.TrimSpace(*machineCode)
	if code == "" {
		if code, err = machine.Code(); err != nil {
			fatal(err)
		}
	}
	for name, value := range map[string]string{"--expire": *expire, "--not-before": *notBefore} {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if _, err := format.ParseLicenseTime(value); err != nil {
			fatal(fmt.Errorf("%s 时间格式错误: %w", name, err))
		}
	}

	lic := &format.License{
		KeyID:       id,
		MachineCode: code,
		Features:    splitList(*features),
		NotBefore:   strings.TrimSpace(*notBefore),
		NotAfter:    strings.TrimSpace(*expire),
		Serial:      strings.TrimSpace(*serial),
	}
	if err := format.IssueLicense(*key, lic, vendor); err != nil {
		fatal(err)
	}

	fmt.Println("License 签发完成")
	fmt.Printf("  KeyID       : %s\n", lic.KeyID)
	fmt.Printf("  机器码      : %s\n", lic.MachineCode)
	fmt.Printf("  功能项      : %s\n", featureText(lic.Features))
	fmt.Printf("  有效期      : %s\n", periodText(lic.NotBefore, lic.NotAfter))
	fmt.Printf("  序列号      : %s\n", emptyText(lic.Serial, "-"))
	fmt.Printf("  写入位置    : %s\n", filepath.Join(*key, format.UKeyDir, format.LicenseFile))

	if *out != "" {
		src := filepath.Join(*key, format.UKeyDir, format.LicenseFile)
		if err := copyFile(src, *out); err != nil {
			fatal(err)
		}
		fmt.Printf("  额外导出    : %s\n", *out)
	}
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dir := fs.String("dir", "", "UKey 挂载点")
	saltMode := fs.String("salt", "auto", "介质指纹模式: auto|serial|volume|none")
	fs.Parse(args)

	if *dir == "" {
		fatal(errors.New("必须指定 --dir"))
	}
	pass := readPassword("UKey 口令: ")

	var session *sdk.Session
	var err error
	if strings.ToLower(*saltMode) == "auto" {
		session, err = sdk.Open(*dir, pass)
	} else {
		var fp format.Fingerprint
		fp, err = media.Resolve(*dir, *saltMode)
		if err != nil {
			fatal(fmt.Errorf("计算介质指纹失败: %w", err))
		}
		session, err = sdk.OpenWith(*dir, pass, fp)
	}
	if err != nil {
		fatal(err)
	}
	defer session.Close()

	lic, err := session.VerifyLicense()
	if err != nil {
		fatal(err)
	}

	// 挑战响应自检：确认私钥确实可用于签名
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		fatal(err)
	}
	sig, err := session.Sign(challenge)
	if err != nil {
		fatal(err)
	}
	if !smcrypto.Verify(session.PublicKey(), challenge, sig) {
		fatal(errors.New("私钥签名自检失败"))
	}

	fmt.Println("校验通过")
	fmt.Printf("  KeyID       : %s\n", session.KeyID())
	fmt.Printf("  功能项      : %s\n", featureText(lic.Features))
	fmt.Printf("  有效期      : %s\n", periodText(lic.NotBefore, lic.NotAfter))
	fmt.Printf("  序列号      : %s\n", emptyText(lic.Serial, "-"))
	fmt.Printf("  机器码      : %s\n", lic.MachineCode)
	fmt.Println("  挑战响应    : 通过")
}

func cmdInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	dir := fs.String("dir", "", "UKey 挂载点")
	fs.Parse(args)

	if *dir == "" {
		fatal(errors.New("必须指定 --dir"))
	}
	info, err := format.Inspect(*dir)
	if err != nil {
		fatal(err)
	}
	keyID, _ := format.ReadKeyID(*dir)

	fmt.Println("UKey 信息")
	fmt.Printf("  挂载点      : %s\n", *dir)
	fmt.Printf("  格式版本    : %d\n", info.Version)
	fmt.Printf("  KeyID       : %s\n", emptyText(keyID, "-"))
	fmt.Printf("  指纹类型    : %s\n", saltTypeName(info.SaltType))
	fmt.Printf("  迭代次数    : %d\n", info.Iter)
	fmt.Printf("  失败次数    : %d/%d\n", info.FailCount, format.MaxFailCount)
	fmt.Printf("  锁定状态    : %s\n", boolText(info.Locked, "已锁定", "正常"))

	lic, err := format.PeekLicense(*dir)
	if err != nil {
		fmt.Println("  License     : 未签发")
		return
	}
	fmt.Println("  License     :")
	fmt.Printf("    机器码    : %s\n", lic.MachineCode)
	fmt.Printf("    功能项    : %s\n", featureText(lic.Features))
	fmt.Printf("    有效期    : %s\n", periodText(lic.NotBefore, lic.NotAfter))
	fmt.Printf("    签发时间  : %s\n", emptyText(lic.IssuedAt, "-"))
	fmt.Printf("    序列号    : %s\n", emptyText(lic.Serial, "-"))
}

type vendorFile struct {
	D         string `json:"d"`
	PublicKey string `json:"publicKey"`
}

func loadOrCreateVendor(path string) (*sm2.PrivateKey, bool, error) {
	if _, err := os.Stat(path); err == nil {
		priv, err := readVendor(path)
		return priv, false, err
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}
	priv, err := smcrypto.GenerateKey()
	if err != nil {
		return nil, false, err
	}
	payload, err := json.MarshalIndent(vendorFile{
		D:         hex.EncodeToString(smcrypto.PrivateScalar(priv)),
		PublicKey: hex.EncodeToString(smcrypto.MarshalPublic(&priv.PublicKey)),
	}, "", "  ")
	if err != nil {
		return nil, false, err
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, false, err
		}
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return nil, false, err
	}
	return priv, true, nil
}

func readVendor(path string) (*sm2.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f vendorFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	scalar, err := hex.DecodeString(f.D)
	if err != nil {
		return nil, fmt.Errorf("解析厂商私钥失败: %w", err)
	}
	priv, err := smcrypto.PrivateFromScalar(scalar)
	smcrypto.Zero(scalar)
	if err != nil {
		return nil, err
	}
	if f.PublicKey != "" {
		expected, err := hex.DecodeString(f.PublicKey)
		if err != nil || !bytes.Equal(expected, smcrypto.MarshalPublic(&priv.PublicKey)) {
			return nil, errors.New("厂商密钥文件公私钥不匹配")
		}
	}
	return priv, nil
}

func readPassword(prompt string) []byte {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fatal(fmt.Errorf("读取口令失败: %w", err))
		}
		return b
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		fatal(fmt.Errorf("读取口令失败: %w", err))
	}
	return []byte(strings.TrimRight(line, "\r\n"))
}

func readNewPassphrase() []byte {
	if v := os.Getenv("UKEY_PASSPHRASE"); v != "" {
		return []byte(v)
	}
	pass := readPassword("设置 UKey 口令（至少 8 位）: ")
	if len(pass) < 8 {
		fatal(errors.New("口令至少 8 个字符"))
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return pass
	}
	confirm := readPassword("再次输入确认: ")
	if !bytes.Equal(pass, confirm) {
		fatal(errors.New("两次输入不一致"))
	}
	return pass
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if dir := filepath.Dir(dst); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func saltTypeName(t uint8) string {
	switch t {
	case format.SaltTypePhysicalSerial:
		return "物理序列号"
	case format.SaltTypeVolumeUUID:
		return "卷 UUID"
	default:
		return "无（仅测试）"
	}
}

func featureText(features []string) string {
	if len(features) == 0 {
		return "全部开放"
	}
	return strings.Join(features, ",")
}

func periodText(notBefore, notAfter string) string {
	start := emptyText(notBefore, "即刻")
	end := emptyText(notAfter, "永久")
	return start + " ~ " + end
}

func emptyText(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func boolText(v bool, yes, no string) string {
	if v {
		return yes
	}
	return no
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "错误: %v\n", err)
	os.Exit(1)
}
