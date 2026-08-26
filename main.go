package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	secret     []byte
	cookieName = "hg_pass"
	passTTL    = 12 * time.Hour
	capt       *captchaManager

	// 访客分析(可选启用)
	geo        *geoResolver
	store      *visitStore
	freq       *freqCounter
	adminUser  string
	adminPass  string
	analyticsOn bool
)

func main() {
	listen := envDefault("GATE_LISTEN", "127.0.0.1:9200")
	cookieName = envDefault("GATE_COOKIE", "hg_pass")
	secret = loadSecret(envDefault("GATE_SECRET_FILE", "/www/wwwroot/human-gate/secret.key"))

	if v := os.Getenv("GATE_PASS_TTL_HOURS"); v != "" {
		if h, err := strconv.Atoi(v); err == nil && h > 0 {
			passTTL = time.Duration(h) * time.Hour
		}
	}

	var err error
	capt, err = newCaptchaManager(3 * time.Minute)
	if err != nil {
		log.Fatalf("captcha init failed: %v", err)
	}

	initAnalytics()

	mux := http.NewServeMux()
	mux.HandleFunc("/__gate/check", handleCheck)     // nginx auth_request 内部调用
	mux.HandleFunc("/__gate/new", handleNew)          // 生成滑块
	mux.HandleFunc("/__gate/verify", handleVerify)    // 校验滑块并签发 Cookie
	mux.HandleFunc("/__gate/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	if analyticsOn {
		mux.HandleFunc("/__gate/admin/login", handleAdminLogin)
		mux.HandleFunc("/__gate/admin/api/", handleAdminAPI)
		mux.HandleFunc("/__gate/admin", handleAdminPage)
	}
	mux.HandleFunc("/__gate/", handleGateStatic) // 闸门页面(兜底，须放最后)

	log.Printf("human-gate listening on %s", listen)
	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// initAnalytics 按环境变量初始化访客分析(未配置库路径则关闭)
func initAnalytics() {
	cityPath := os.Getenv("GATE_GEO_CITY")
	asnPath := os.Getenv("GATE_GEO_ASN")
	dbPath := envDefault("GATE_DB", "/www/wwwroot/human-gate-data/visits.db")
	adminUser = envDefault("GATE_ADMIN_USER", "admin")
	adminPass = os.Getenv("GATE_ADMIN_PASS")

	if cityPath == "" || asnPath == "" || adminPass == "" {
		log.Printf("analytics disabled (need GATE_GEO_CITY/GATE_GEO_ASN/GATE_ADMIN_PASS)")
		return
	}
	var err error
	geo, err = newGeoResolver(cityPath, asnPath)
	if err != nil {
		log.Printf("geo init failed, analytics disabled: %v", err)
		return
	}
	retain := 30
	if v := os.Getenv("GATE_RETAIN_DAYS"); v != "" {
		if d, e := strconv.Atoi(v); e == nil && d > 0 {
			retain = d
		}
	}
	store, err = newVisitStore(dbPath, retain)
	if err != nil {
		log.Printf("store init failed, analytics disabled: %v", err)
		geo.Close()
		geo = nil
		return
	}
	freq = newFreqCounter(60) // 60 秒窗口统计频率
	analyticsOn = true
	log.Printf("analytics enabled: db=%s retain=%dd", dbPath, retain)
}

// clientIP 从 nginx 透传的头里取真实访客 IP
func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return strings.TrimSpace(v)
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		parts := strings.Split(v, ",")
		return strings.TrimSpace(parts[0])
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

// recordVisit 异步采集一次访问(仅在分析开启时)
func recordVisit(r *http.Request, passed int) {
	if !analyticsOn {
		return
	}
	ip := clientIP(r)
	ua := r.Header.Get("User-Agent")
	site := r.Header.Get("X-Forwarded-Host")
	if site == "" {
		site = r.Header.Get("Host")
	}
	uri := r.Header.Get("X-Original-URI")

	go func() {
		p := geo.Lookup(ip)
		n := freq.hit(ip)
		level, tags := assessRisk(ua, p, n)
		store.insert(visitRow{
			TS: time.Now().Unix(), IP: ip, UA: ua, Site: site, URI: uri, Passed: passed,
			Country: p.Country, Province: p.Province, City: p.City,
			ASN: p.ASN, ASNOrg: p.ASNOrg, IPType: p.IPType, ISP: p.ISP,
			RiskLevel: level, RiskTags: strings.Join(tags, ","),
		})
	}()
}

// handleCheck 由 nginx auth_request 调用：有合法 Cookie 返回 204，否则 401
func handleCheck(w http.ResponseWriter, r *http.Request) {
	ua := r.Header.Get("User-Agent")
	c, err := r.Cookie(cookieName)
	passed := 0
	if err == nil && verifyPass(secret, uaShortHash(ua), c.Value) {
		passed = 1
	}
	recordVisit(r, passed)
	if passed == 1 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
}

// handleNew 生成一张新滑块挑战
func handleNew(w http.ResponseWriter, r *http.Request) {
	id := randID()
	master, tile, tileY, tw, th, err := capt.generate(id)
	if err != nil {
		http.Error(w, "gen error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{
		"id":          id,
		"master":      master,
		"tile":        tile,
		"tile_y":      tileY,
		"tile_width":  tw,
		"tile_height": th,
	})
}

type verifyReq struct {
	ID string `json:"id"`
	X  int    `json:"x"`
	Y  int    `json:"y"`
}

// handleVerify 校验滑块，通过则种 Cookie
func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var req verifyReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false})
		return
	}
	if !capt.verify(req.ID, req.X, req.Y) {
		writeJSON(w, map[string]interface{}{"ok": false})
		return
	}

	ua := r.Header.Get("User-Agent")
	token := signPass(secret, uaShortHash(ua), passTTL)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		MaxAge:   int(passTTL.Seconds()),
	})
	writeJSON(w, map[string]interface{}{"ok": true})
}

// handleGateStatic 返回闸门页面 HTML
func handleGateStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/__gate")
	if path == "" || path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(gatePageHTML))
		return
	}
	http.NotFound(w, r)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func randID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func envDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// loadSecret 读取或生成持久化的 HMAC 密钥
func loadSecret(path string) []byte {
	if data, err := os.ReadFile(path); err == nil && len(data) >= 32 {
		return data
	}
	b := make([]byte, 48)
	rand.Read(b)
	if err := os.WriteFile(path, b, 0600); err != nil {
		log.Printf("warn: cannot persist secret: %v", err)
	}
	return b
}
