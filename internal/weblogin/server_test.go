package weblogin

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"

	"ukey/internal/smcrypto"
)

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newFixture(t *testing.T) (*Server, *testClock, *sm2.PrivateKey, http.Handler) {
	t.Helper()
	priv, err := smcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	clock := &testClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	srv := New(Config{
		PublicKey: &priv.PublicKey,
		IndexHTML: []byte("<html>login</html>"),
		Subject:   "alice",
		Now:       clock.now,
	})
	return srv, clock, priv, srv.Handler()
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func getChallenge(t *testing.T, h http.Handler) (sessionID, message string) {
	t.Helper()
	rec := doJSON(t, h, http.MethodPost, "/api/challenge", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge 状态码 = %d, body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		SessionID string `json:"sessionId"`
		Message   string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.SessionID == "" || body.Message == "" {
		t.Fatal("challenge 响应缺少字段")
	}
	return body.SessionID, body.Message
}

func signHex(t *testing.T, priv *sm2.PrivateKey, message string) string {
	t.Helper()
	sig, err := smcrypto.Sign(priv, []byte(message))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return hex.EncodeToString(sig)
}

func TestLoginSuccess(t *testing.T) {
	_, _, priv, h := newFixture(t)
	sid, msg := getChallenge(t, h)

	rec := doJSON(t, h, http.MethodPost, "/api/login", map[string]string{
		"sessionId": sid,
		"signature": signHex(t, priv, msg),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login 状态码 = %d, body=%s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Name != CookieName || !cookies[0].HttpOnly {
		t.Fatalf("会话 Cookie 异常: %+v", cookies)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(cookies[0])
	meRec := httptest.NewRecorder()
	h.ServeHTTP(meRec, req)
	var me struct {
		LoggedIn bool   `json:"loggedIn"`
		Subject  string `json:"subject"`
	}
	if err := json.Unmarshal(meRec.Body.Bytes(), &me); err != nil {
		t.Fatalf("decode me: %v", err)
	}
	if !me.LoggedIn || me.Subject != "alice" {
		t.Fatalf("me = %+v", me)
	}
}

func TestLoginReplayRejected(t *testing.T) {
	_, _, priv, h := newFixture(t)
	sid, msg := getChallenge(t, h)
	sig := signHex(t, priv, msg)

	first := doJSON(t, h, http.MethodPost, "/api/login", map[string]string{"sessionId": sid, "signature": sig})
	if first.Code != http.StatusOK {
		t.Fatalf("首次登录状态码 = %d", first.Code)
	}
	second := doJSON(t, h, http.MethodPost, "/api/login", map[string]string{"sessionId": sid, "signature": sig})
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("重放状态码 = %d, want 401", second.Code)
	}
}

func TestLoginExpired(t *testing.T) {
	_, clock, priv, h := newFixture(t)
	sid, msg := getChallenge(t, h)
	clock.advance(6 * time.Minute)
	rec := doJSON(t, h, http.MethodPost, "/api/login", map[string]string{
		"sessionId": sid,
		"signature": signHex(t, priv, msg),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("过期 challenge 状态码 = %d, want 401", rec.Code)
	}
}

func TestLoginWrongSignature(t *testing.T) {
	_, _, _, h := newFixture(t)
	other, err := smcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sid, msg := getChallenge(t, h)
	rec := doJSON(t, h, http.MethodPost, "/api/login", map[string]string{
		"sessionId": sid,
		"signature": signHex(t, other, msg),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("错误签名状态码 = %d, want 401", rec.Code)
	}
}

func TestLoginUnknownSession(t *testing.T) {
	_, _, priv, h := newFixture(t)
	rec := doJSON(t, h, http.MethodPost, "/api/login", map[string]string{
		"sessionId": "deadbeef",
		"signature": signHex(t, priv, "ukey-web-login|deadbeef|00"),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("未知 session 状态码 = %d, want 401", rec.Code)
	}
}

func TestMeWhenAnonymous(t *testing.T) {
	_, _, _, h := newFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var me struct {
		LoggedIn bool `json:"loggedIn"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if me.LoggedIn {
		t.Fatal("匿名访问不应为已登录")
	}
}

func TestLogoutClearsSession(t *testing.T) {
	_, _, priv, h := newFixture(t)
	sid, msg := getChallenge(t, h)
	loginRec := doJSON(t, h, http.MethodPost, "/api/login", map[string]string{
		"sessionId": sid,
		"signature": signHex(t, priv, msg),
	})
	cookie := loginRec.Result().Cookies()[0]

	logoutReq := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	logoutReq.AddCookie(cookie)
	logoutRec := httptest.NewRecorder()
	h.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("logout 状态码 = %d", logoutRec.Code)
	}

	meReq := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	meReq.AddCookie(cookie)
	meRec := httptest.NewRecorder()
	h.ServeHTTP(meRec, meReq)
	var me struct {
		LoggedIn bool `json:"loggedIn"`
	}
	if err := json.Unmarshal(meRec.Body.Bytes(), &me); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if me.LoggedIn {
		t.Fatal("登出后仍为已登录")
	}
}

func TestIndexServed(t *testing.T) {
	_, _, _, h := newFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte("login")) {
		t.Fatalf("首页状态码 = %d", rec.Code)
	}
}

func TestLoginMessageFormat(t *testing.T) {
	msg := LoginMessage("abc", []byte{0x01, 0xff})
	if want := "ukey-web-login|abc|01ff"; msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
}
