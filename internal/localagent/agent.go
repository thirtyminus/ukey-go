// Package localagent 实现本机 UKey 签名服务，供浏览器登录页调用。
package localagent

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"ukey/internal/smcrypto"
	"ukey/internal/weblogin"
)

// Signer 是签名能力的最小接口，便于测试替换。
type Signer interface {
	Sign(msg []byte) ([]byte, error)
	PublicKey() *ecdsa.PublicKey
	KeyID() string
	// CheckAlive 检查密钥介质是否仍然可用，拔盘后签名必须失败。
	CheckAlive() error
}

// Config 是 Agent 配置。
type Config struct {
	Signer Signer
	// AllowedOrigins 是允许调用本服务的页面来源白名单。
	AllowedOrigins []string
	// MessagePrefix 是允许签名的消息前缀，默认登录消息前缀。
	MessagePrefix string
}

// Agent 是本机签名 HTTP 服务。
type Agent struct {
	cfg Config
}

// New 构造 Agent。
func New(cfg Config) *Agent {
	if cfg.MessagePrefix == "" {
		cfg.MessagePrefix = weblogin.MessagePrefix
	}
	for i, o := range cfg.AllowedOrigins {
		cfg.AllowedOrigins[i] = weblogin.NormalizeOrigin(o)
	}
	return &Agent{cfg: cfg}
}

// Handler 返回带 CORS 与 Origin 校验的路由。
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", a.handlePing)
	mux.HandleFunc("POST /sign", a.handleSign)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := weblogin.NormalizeOrigin(r.Header.Get("Origin"))
		if origin != "" {
			if !a.originAllowed(origin) {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *Agent) originAllowed(origin string) bool {
	for _, allowed := range a.cfg.AllowedOrigins {
		if allowed == origin {
			return true
		}
	}
	return false
}

func (a *Agent) handlePing(w http.ResponseWriter, r *http.Request) {
	// 拔盘后 ping 也报不可用，登录页据此快速给出提示。
	if err := a.cfg.Signer.CheckAlive(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": "UKey 介质不可用: " + err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"keyId":     a.cfg.Signer.KeyID(),
		"publicKey": hex.EncodeToString(smcrypto.MarshalPublic(a.cfg.Signer.PublicKey())),
	})
}

func (a *Agent) handleSign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MessageHex string `json:"messageHex"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体格式错误"})
		return
	}
	msg, err := hex.DecodeString(req.MessageHex)
	if err != nil || len(msg) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "消息编码错误"})
		return
	}
	// 只签登录消息，避免本服务变成任意内容签名机。
	if !strings.HasPrefix(string(msg), a.cfg.MessagePrefix) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "不支持的消息类型"})
		return
	}
	// 私钥虽已在内存，但拔盘后必须拒绝签名，否则 U 盘形同虚设。
	if err := a.cfg.Signer.CheckAlive(); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "UKey 介质不可用: " + err.Error()})
		return
	}
	sig, err := a.cfg.Signer.Sign(msg)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "签名失败: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"signature": hex.EncodeToString(sig)})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
