package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// passToken 是签发给通过验证访客的凭证载荷
type passToken struct {
	Exp int64  `json:"exp"` // 过期时间(unix 秒)
	UA  string `json:"ua"`  // User-Agent 短哈希，防止 Cookie 被跨客户端复用
}

// signPass 生成 base64(payload).hmac 形式的签名令牌
func signPass(secret []byte, uaHash string, ttl time.Duration) string {
	payload := passToken{
		Exp: time.Now().Add(ttl).Unix(),
		UA:  uaHash,
	}
	raw, _ := json.Marshal(payload)
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	sig := hmacHex(secret, b64)
	return b64 + "." + sig
}

// verifyPass 校验令牌签名、过期时间与 UA 绑定
func verifyPass(secret []byte, uaHash, token string) bool {
	parts := strings.SplitN(strings.TrimSpace(token), ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	expected := hmacHex(secret, parts[0])
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var payload passToken
	if json.Unmarshal(raw, &payload) != nil {
		return false
	}
	if payload.Exp < time.Now().Unix() {
		return false
	}
	if payload.UA != uaHash {
		return false
	}
	return true
}

func hmacHex(secret []byte, msg string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// uaShortHash 取 User-Agent 的短哈希用于绑定
func uaShortHash(ua string) string {
	sum := sha256.Sum256([]byte(ua))
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}
