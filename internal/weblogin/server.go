// Package weblogin 实现 UKey 挑战-响应网页登录的服务端逻辑。
package weblogin

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"ukey/internal/smcrypto"
)

const (
	// MessagePrefix 是登录签名消息的固定前缀，Agent 据此拒绝盲签。
	MessagePrefix = "ukey-web-login|"
	// CookieName 是会话 Cookie 名。
	CookieName = "ukey_session"
)

// Config 是服务端配置。
type Config struct {
	// PublicKey 是唯一被信任的 UKey 公钥，启动时静态注册。
	PublicKey *ecdsa.PublicKey
	// IndexHTML 是登录页内容。
	IndexHTML []byte
	// Subject 是登录成功后的用户标识。
	Subject string
	// LoginTTL 是 challenge 有效期，默认 5 分钟。
	LoginTTL time.Duration
	// SessionTTL 是会话有效期，默认 8 小时。
	SessionTTL time.Duration
	// Now 便于测试注入时钟。
	Now func() time.Time
}

// Server 持有内存态的 challenge 与 session。
type Server struct {
	cfg        Config
	mu         sync.Mutex
	challenges map[string]*challenge
	sessions   map[string]*sessionInfo
}

type challenge struct {
	nonce   []byte
	expires time.Time
}

type sessionInfo struct {
	expires time.Time
}

// New 构造服务端并填充默认值。
func New(cfg Config) *Server {
	if cfg.LoginTTL <= 0 {
		cfg.LoginTTL = 5 * time.Minute
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 8 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Subject == "" {
		cfg.Subject = "ukey-user"
	}
	return &Server{
		cfg:        cfg,
		challenges: make(map[string]*challenge),
		sessions:   make(map[string]*sessionInfo),
	}
}

// LoginMessage 构造待签名消息。
func LoginMessage(sessionID string, nonce []byte) string {
	return MessagePrefix + sessionID + "|" + hex.EncodeToString(nonce)
}

// Handler 返回登录相关路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/challenge", s.handleChallenge)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("GET /api/me", s.handleMe)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /", s.handleIndex)
	return mux
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	sid := randomHex(16)
	nonce := randomBytes(32)
	message := LoginMessage(sid, nonce)

	s.mu.Lock()
	s.challenges[sid] = &challenge{nonce: nonce, expires: s.cfg.Now().Add(s.cfg.LoginTTL)}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"sessionId":  sid,
		"message":    message,
		"messageHex": hex.EncodeToString([]byte(message)),
		"expiresIn":  int(s.cfg.LoginTTL.Seconds()),
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"sessionId"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	sig, err := hex.DecodeString(req.Signature)
	if err != nil || len(sig) == 0 {
		writeError(w, http.StatusBadRequest, "签名编码错误")
		return
	}

	// 取即删：无论验签是否通过，该 challenge 都作废，防止重放。
	s.mu.Lock()
	ch, ok := s.challenges[req.SessionID]
	delete(s.challenges, req.SessionID)
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusUnauthorized, "挑战无效或已被使用")
		return
	}
	if s.cfg.Now().After(ch.expires) {
		writeError(w, http.StatusUnauthorized, "挑战已过期")
		return
	}

	message := LoginMessage(req.SessionID, ch.nonce)
	if !smcrypto.Verify(s.cfg.PublicKey, []byte(message), sig) {
		writeError(w, http.StatusUnauthorized, "签名校验失败")
		return
	}

	sessionID := randomHex(32)
	s.mu.Lock()
	s.sessions[sessionID] = &sessionInfo{expires: s.cfg.Now().Add(s.cfg.SessionTTL)}
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.cfg.SessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "subject": s.cfg.Subject})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if !s.loggedIn(r) {
		writeJSON(w, http.StatusOK, map[string]any{"loggedIn": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"loggedIn": true, "subject": s.cfg.Subject})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(s.cfg.IndexHTML)
}

func (s *Server) loggedIn(r *http.Request) bool {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.sessions[c.Value]
	if !ok {
		return false
	}
	if s.cfg.Now().After(info.expires) {
		delete(s.sessions, c.Value)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("weblogin: 随机数不可用: " + err.Error())
	}
	return b
}

func randomHex(n int) string {
	return hex.EncodeToString(randomBytes(n))
}

// NormalizeOrigin 去掉末尾斜杠，便于比较。
func NormalizeOrigin(origin string) string {
	return strings.TrimRight(strings.TrimSpace(origin), "/")
}
