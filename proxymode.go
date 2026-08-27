package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

// 反代模式：human-gate 自己监听端口，未通过验证的请求返回滑块页，
// 通过后由 human-gate 直接反代到上游。用于 nginx 缺 auth_request 模块的场景。
//
// 相关环境变量：
//   GATE_UPSTREAM       上游地址，如 http://127.0.0.1:8808（设置即启用反代模式）
//   GATE_BYPASS_PREFIX  免验证路径前缀，逗号分隔，如 /api/,/static/,/media/

var (
	upstreamURL   string
	bypassPrefix  []string
	reverseProxy  *httputil.ReverseProxy
)

func proxyModeEnabled() bool { return upstreamURL != "" }

func initProxyMode() {
	upstreamURL = os.Getenv("GATE_UPSTREAM")
	if upstreamURL == "" {
		return
	}
	u, err := url.Parse(upstreamURL)
	if err != nil {
		log.Fatalf("invalid GATE_UPSTREAM %q: %v", upstreamURL, err)
	}
	reverseProxy = httputil.NewSingleHostReverseProxy(u)
	// 保留原始 Host，并补充转发头，让上游拿到真实信息
	origDirector := reverseProxy.Director
	reverseProxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = u.Host
	}

	if v := os.Getenv("GATE_BYPASS_PREFIX"); v != "" {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				bypassPrefix = append(bypassPrefix, p)
			}
		}
	}
	log.Printf("proxy mode enabled -> %s (bypass=%v)", upstreamURL, bypassPrefix)
}

func isBypass(path string) bool {
	for _, p := range bypassPrefix {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// handleProxyRoot 是反代模式下的主处理器（非 /__gate/ 路径）
func handleProxyRoot(w http.ResponseWriter, r *http.Request) {
	ua := r.Header.Get("User-Agent")
	c, err := r.Cookie(cookieName)
	passed := err == nil && verifyPass(secret, uaShortHash(ua), c.Value)

	// 免验证路径：直接反代，但仍记录访问
	if isBypass(r.URL.Path) {
		recordVisit(r, boolToInt(passed))
		reverseProxy.ServeHTTP(w, r)
		return
	}

	recordVisit(r, boolToInt(passed))
	if passed {
		reverseProxy.ServeHTTP(w, r)
		return
	}
	// 未通过：跳转到滑块页，带上原始地址
	http.Redirect(w, r, "/__gate/?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
