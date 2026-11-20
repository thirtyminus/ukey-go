// Command demo-app 演示业务侧如何集成 UKey 授权校验。
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"ukey/internal/media"
	"ukey/internal/sdk"
)

func main() {
	vol := flag.String("vol", "", "UKey 挂载点，留空自动扫描")
	feature := flag.String("feature", "", "需要额外校验的功能项")
	saltMode := flag.String("salt", "auto", "介质指纹模式: auto|serial|volume|none（本地目录调试用 none）")
	flag.Parse()

	pass := readPassword("UKey 口令: ")
	var session *sdk.Session
	var err error
	if strings.ToLower(*saltMode) == "auto" {
		session, err = sdk.Open(*vol, pass)
	} else {
		fp, ferr := media.Resolve(*vol, *saltMode)
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "计算介质指纹失败: %v\n", ferr)
			os.Exit(1)
		}
		session, err = sdk.OpenWith(*vol, pass, fp)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开 UKey 失败: %v\n", err)
		os.Exit(1)
	}
	defer session.Close()

	lic, err := session.VerifyLicense()
	if err != nil {
		fmt.Fprintf(os.Stderr, "授权校验失败: %v\n", err)
		os.Exit(1)
	}
	if *feature != "" {
		if err := session.RequireFeature(*feature); err != nil {
			fmt.Fprintf(os.Stderr, "功能校验失败: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("[启动] KeyID=%s 有效期=%s ~ %s\n", session.KeyID(), orDash(lic.NotBefore), orDash(lic.NotAfter))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go session.Watch(ctx, func() {
		fmt.Println("[!] UKey 已移除，进入受限模式")
		cancel()
	})

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	round := 0
	for {
		select {
		case <-ctx.Done():
			fmt.Println("[退出] 受限模式，业务已停止")
			return
		case <-ticker.C:
			round++
			// 敏感操作前复核介质仍然可用
			if err := session.CheckAlive(); err != nil {
				fmt.Println("[!] 介质不可用，业务已停止")
				return
			}
			fmt.Printf("[业务] 第 %d 轮运行中\n", round)
		}
	}
}

func readPassword(prompt string) []byte {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取口令失败: %v\n", err)
			os.Exit(1)
		}
		return b
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintf(os.Stderr, "读取口令失败: %v\n", err)
		os.Exit(1)
	}
	return []byte(strings.TrimRight(line, "\r\n"))
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
