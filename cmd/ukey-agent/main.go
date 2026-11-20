// Command ukey-agent 是本机 UKey 签名服务，供网页登录页调用。
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"ukey/internal/localagent"
	"ukey/internal/media"
	"ukey/internal/sdk"
)

func main() {
	vol := flag.String("vol", "", "UKey 挂载点，留空自动扫描")
	saltMode := flag.String("salt", "auto", "介质指纹模式: auto|serial|volume|none")
	listen := flag.String("listen", "127.0.0.1:18765", "监听地址，仅建议绑定本机回环")
	origins := flag.String("allow-origin", "http://127.0.0.1:8080,http://localhost:8080", "允许的页面来源，逗号分隔")
	flag.Parse()

	pass := readPassword("UKey 口令: ")
	var session *sdk.Session
	var err error
	if strings.ToLower(*saltMode) == "auto" {
		session, err = sdk.Open(*vol, pass)
	} else {
		resolved, ferr := media.Resolve(*vol, *saltMode)
		if ferr != nil {
			fatal(fmt.Errorf("计算介质指纹失败: %w", ferr))
		}
		session, err = sdk.OpenWith(*vol, pass, resolved)
	}
	if err != nil {
		fatal(err)
	}
	defer session.Close()

	agent := localagent.New(localagent.Config{
		Signer:         session,
		AllowedOrigins: splitList(*origins),
	})
	fmt.Printf("UKey Agent 已启动: http://%s\n", *listen)
	fmt.Printf("  KeyID    : %s\n", session.KeyID())
	fmt.Printf("  允许来源 : %s\n", *origins)

	// 拔盘时在终端给出提示；签名请求本身也会被 CheckAlive 拒绝。
	go session.Watch(context.Background(), func() {
		fmt.Println("[!] UKey 已移除，登录签名将被拒绝")
	})

	srv := &http.Server{Addr: *listen, Handler: agent.Handler()}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		fatal(err)
	}
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

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "错误: %v\n", err)
	os.Exit(1)
}
