// Command ukey-web 是 UKey 网页登录的认证服务端。
package main

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"ukey/internal/smcrypto"
	"ukey/internal/weblogin"
)

//go:embed index.html
var indexHTML []byte

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "监听地址")
	pubkeyHex := flag.String("pubkey", "", "注册的 UKey 公钥（65 字节 hex），生产必须显式指定")
	agentURL := flag.String("agent", "http://127.0.0.1:18765", "本机 Agent 地址，仅在未指定 -pubkey 时用于拉取公钥")
	subject := flag.String("subject", "ukey-user", "登录成功后的用户标识")
	flag.Parse()

	hexKey := strings.TrimSpace(*pubkeyHex)
	if hexKey == "" {
		var err error
		hexKey, err = fetchAgentPublicKey(*agentURL)
		if err != nil {
			fatal(fmt.Errorf("未指定 -pubkey，且无法从 Agent 获取公钥: %w", err))
		}
		fmt.Fprintf(os.Stderr, "警告: 公钥来自本机 Agent（演示便利），生产请用 -pubkey 静态注册\n")
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		fatal(fmt.Errorf("公钥不是合法 hex: %w", err))
	}
	pub, err := smcrypto.ParsePublic(raw)
	if err != nil {
		fatal(fmt.Errorf("公钥格式错误: %w", err))
	}

	srv := weblogin.New(weblogin.Config{
		PublicKey: pub,
		IndexHTML: indexHTML,
		Subject:   *subject,
	})
	fmt.Printf("UKey 登录页: http://%s/\n", *listen)
	fmt.Printf("已注册 UKey 标识: %s\n", hex.EncodeToString(smcrypto.Digest(raw))[:16])
	if err := http.ListenAndServe(*listen, srv.Handler()); err != nil {
		fatal(err)
	}
}

func fetchAgentPublicKey(agentURL string) (string, error) {
	resp, err := http.Get(strings.TrimRight(agentURL, "/") + "/ping")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Agent 返回 HTTP %d", resp.StatusCode)
	}
	var body struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.PublicKey == "" {
		return "", fmt.Errorf("Agent 未返回公钥")
	}
	return body.PublicKey, nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "错误: %v\n", err)
	os.Exit(1)
}
