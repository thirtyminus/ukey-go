package localagent

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/emmansun/gmsm/sm2"

	"ukey/internal/smcrypto"
	"ukey/internal/ukerr"
	"ukey/internal/weblogin"
)

type fakeSigner struct {
	priv  *sm2.PrivateKey
	alive bool
}

func (f *fakeSigner) Sign(msg []byte) ([]byte, error) { return smcrypto.Sign(f.priv, msg) }
func (f *fakeSigner) PublicKey() *ecdsa.PublicKey     { return &f.priv.PublicKey }
func (f *fakeSigner) KeyID() string                   { return "test-key-id" }

func (f *fakeSigner) CheckAlive() error {
	if !f.alive {
		return ukkerr.ErrMediaNotFound
	}
	return nil
}

func newAgent(t *testing.T, origins ...string) (*fakeSigner, http.Handler) {
	t.Helper()
	priv, err := smcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := &fakeSigner{priv: priv, alive: true}
	return signer, New(Config{Signer: signer, AllowedOrigins: origins}).Handler()
}

func doRequest(h http.Handler, method, path, origin string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestPing(t *testing.T) {
	_, h := newAgent(t)
	rec := doRequest(h, http.MethodGet, "/ping", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("ping 状态码 = %d", rec.Code)
	}
	var body struct {
		OK        bool   `json:"ok"`
		KeyID     string `json:"keyId"`
		PublicKey string `json:"publicKey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.OK || body.KeyID != "test-key-id" || len(body.PublicKey) != smcrypto.PublicKeySize*2 {
		t.Fatalf("ping 响应异常: %+v", body)
	}
}

func TestSignLoginMessage(t *testing.T) {
	signer, h := newAgent(t)
	msg := weblogin.LoginMessage("session-1", []byte("nonce"))
	rec := doRequest(h, http.MethodPost, "/sign", "", map[string]string{
		"messageHex": hex.EncodeToString([]byte(msg)),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("sign 状态码 = %d, body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	sig, err := hex.DecodeString(body.Signature)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !smcrypto.Verify(signer.PublicKey(), []byte(msg), sig) {
		t.Fatal("Agent 返回的签名校验失败")
	}
}

func TestSignRejectsForeignMessage(t *testing.T) {
	_, h := newAgent(t)
	rec := doRequest(h, http.MethodPost, "/sign", "", map[string]string{
		"messageHex": hex.EncodeToString([]byte("pay 100 to bob")),
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非登录消息状态码 = %d, want 400", rec.Code)
	}
}

func TestSignRejectsWhenMediaGone(t *testing.T) {
	signer, h := newAgent(t)
	signer.alive = false
	msg := weblogin.LoginMessage("session-1", []byte("nonce"))
	rec := doRequest(h, http.MethodPost, "/sign", "", map[string]string{
		"messageHex": hex.EncodeToString([]byte(msg)),
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("拔盘后签名状态码 = %d, want 401, body=%s", rec.Code, rec.Body.String())
	}
}

func TestPingReportsMediaGone(t *testing.T) {
	signer, h := newAgent(t)
	signer.alive = false
	rec := doRequest(h, http.MethodGet, "/ping", "", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("拔盘后 ping 状态码 = %d, want 503", rec.Code)
	}
	var body struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.OK || body.Error == "" {
		t.Fatalf("拔盘后 ping 响应异常: %+v", body)
	}
}

func TestOriginNotAllowed(t *testing.T) {
	_, h := newAgent(t, "http://127.0.0.1:8080")
	rec := doRequest(h, http.MethodGet, "/ping", "http://evil.example", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("非法来源状态码 = %d, want 403", rec.Code)
	}
}

func TestOriginAllowedCORS(t *testing.T) {
	_, h := newAgent(t, "http://127.0.0.1:8080")
	rec := doRequest(h, http.MethodGet, "/ping", "http://127.0.0.1:8080", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("白名单来源状态码 = %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:8080" {
		t.Fatalf("CORS 头 = %q", got)
	}
}

func TestPreflight(t *testing.T) {
	_, h := newAgent(t, "http://127.0.0.1:8080")
	rec := doRequest(h, http.MethodOptions, "/sign", "http://127.0.0.1:8080", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("预检状态码 = %d, want 204", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Fatal("预检缺少 Allow-Headers")
	}
}

func TestNoOriginAllowedForCurl(t *testing.T) {
	_, h := newAgent(t, "http://127.0.0.1:8080")
	rec := doRequest(h, http.MethodGet, "/ping", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("无 Origin 状态码 = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("无 Origin 时不应返回 CORS 头, got %q", got)
	}
}
