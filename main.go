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
	geo         *geoResolver
	store       *visitStore
	freq        *freqCounter
	adminUser   string
	adminPass   string
	analyticsOn bool

	// 分布式：远程上报器(远程节点侧) / ingest 密钥(中心侧)
	rpt         *reporter
	ingestToken string

	// 闸门总开关：off 时全站放行(仍可上报分析)，用于纯反代 API 等场景
	gateEnabled = true

	// 验证页客服：静态入口始终可见，第三方客服脚本为可选增强
	gateSupportEnabled   bool
	gateSupportURL       string
	gateSupportText      string
	gateSupportScriptURL string
	gateSupportHTML      string
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

	// 闸门总开关：GATE_ENABLE=off 关闭滑块验证(全站放行)，仍继续采集/上报访客数据
	if strings.EqualFold(os.Getenv("GATE_ENABLE"), "off") {
		gateEnabled = false
		log.Printf("gate DISABLED (GATE_ENABLE=off): 放行全部请求，仅采集数据")
	}
	initSupport()

	var err error
	capt, err = newCaptchaManager(3 * time.Minute)
	if err != nil {
		log.Fatalf("captcha init failed: %v", err)
	}

	initAnalytics()
	initDistributed()
	initProxyMode()

	mux := http.NewServeMux()
	mux.HandleFunc("/__gate/check", handleCheck)   // nginx auth_request 内部调用
	mux.HandleFunc("/__gate/new", handleNew)       // 生成滑块
	mux.HandleFunc("/__gate/verify", handleVerify) // 校验滑块并签发 Cookie
	mux.HandleFunc("/__gate/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	if analyticsOn {
		mux.HandleFunc("/__gate/admin/login", handleAdminLogin)
		mux.HandleFunc("/__gate/admin/api/", handleAdminAPI)
		mux.HandleFunc("/__gate/admin", handleAdminPage)
	}
	// 中心侧：接收远程节点上报(需 analytics 开启 + 配置 ingest 密钥)
	if analyticsOn && ingestToken != "" {
		mux.HandleFunc("/__gate/ingest", handleIngest)
		mux.HandleFunc("/__gate/policy", handlePolicy)
		log.Printf("ingest + policy endpoints enabled")
	}
	mux.HandleFunc("/__gate/", handleGateStatic) // 闸门页面(兜底，须放最后)

	// 反代模式：非 /__gate/ 的一切走验证+反代到上游
	if proxyModeEnabled() {
		mux.HandleFunc("/", handleProxyRoot)
	}

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
	// ip2region 国内库(可选)：补齐移动等运营商的地市级归属
	region4 := os.Getenv("GATE_IP2REGION_V4")
	region6 := os.Getenv("GATE_IP2REGION_V6")
	if region4 != "" || region6 != "" {
		geo.loadIP2Region(region4, region6)
		log.Printf("ip2region loaded: v4=%v v6=%v", geo.region4 != nil, geo.region6 != nil)
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

// initDistributed 初始化分布式相关配置
//   - GATE_REPORT_URL + GATE_REPORT_TOKEN：远程节点模式，把事件上报到中心
//   - GATE_INGEST_TOKEN：中心模式，接收远程节点上报(需 analytics 开启)
func initDistributed() {
	reportURL := os.Getenv("GATE_REPORT_URL")
	reportToken := os.Getenv("GATE_REPORT_TOKEN")
	if reportURL != "" && reportToken != "" {
		insecure := os.Getenv("GATE_REPORT_INSECURE") == "1"
		rpt = newReporter(reportURL, reportToken, insecure)
		log.Printf("remote report enabled -> %s (insecure=%v)", reportURL, insecure)
		policyURL := envDefault("GATE_POLICY_URL", derivePolicyURL(reportURL))
		interval := 60 * time.Second
		if v := os.Getenv("GATE_POLICY_INTERVAL_SEC"); v != "" {
			if sec, err := strconv.Atoi(v); err == nil && sec >= 10 {
				interval = time.Duration(sec) * time.Second
			}
		}
		nodePolicy = newPolicySyncer(policyURL, reportToken, rpt.client, interval)
		log.Printf("policy sync enabled -> %s interval=%s", policyURL, interval)
	}
	ingestToken = os.Getenv("GATE_INGEST_TOKEN")
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

// recordVisit 采集一次本地访问。
// - 中心/单机模式(store 就绪)：本地画像并入库
// - 远程节点模式(reporter 就绪)：把原始事件上报给中心，本地不画像
func recordVisit(r *http.Request, passed int) {
	if !analyticsOn && rpt == nil {
		return
	}
	ip := clientIP(r)
	ua := r.Header.Get("User-Agent")
	site := r.Header.Get("X-Forwarded-Host")
	if site == "" {
		site = r.Header.Get("Host")
	}
	uri := r.Header.Get("X-Original-URI")
	e := rawEvent{TS: time.Now().Unix(), IP: ip, UA: ua, Site: site, URI: uri, Passed: passed}
	if decision := nodePolicy.decide(ip); decision.Matched {
		e.PolicyVersion = decision.Version
		e.PolicyMode = decision.Mode
		e.PolicyAction = decision.Action
	}

	if rpt != nil {
		rpt.send(e)
		return
	}
	go processEvent(e)
}

// staticAssetExts 是页面加载时由浏览器自动并发拉取的子资源后缀。
// 这类请求一次页面访问会产生几十条，记录下来只会淹没真实的页面级访问日志。
var staticAssetExts = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".map": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".svg": true, ".ico": true, ".bmp": true, ".avif": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".mp4": true, ".webm": true, ".mp3": true, ".wav": true,
}

// isStaticAsset 判断 URI 是否为静态子资源(按扩展名 + 常见附属文件)。
// 命中则不计入访客分析，使"一次进站"回归页面级 1~2 条记录。
func isStaticAsset(uri string) bool {
	path := uri
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	switch path {
	case "/favicon.ico", "/manifest.json", "/robots.txt", "/sw.js", "/service-worker.js":
		return true
	}
	if dot := strings.LastIndex(path, "."); dot >= 0 {
		if slash := strings.LastIndex(path, "/"); dot > slash {
			return staticAssetExts[strings.ToLower(path[dot:])]
		}
	}
	return false
}

// processEvent 对一条原始事件做画像+风控打分并入库(中心/单机侧执行)
func processEvent(e rawEvent) {
	if !analyticsOn {
		return
	}
	// 静态子资源(JS/CSS/图片/字体等)不入库，避免一次页面加载刷出几十条记录
	if isStaticAsset(e.URI) {
		return
	}
	if e.PolicyMode != "" {
		store.insertPolicyHit(e)
	}
	p := geo.Lookup(e.IP)
	n := freq.hit(e.IP)
	level, tags := assessRisk(e.UA, p, n)
	store.insert(visitRow{
		TS: e.TS, IP: e.IP, UA: e.UA, Site: e.Site, URI: e.URI, Passed: e.Passed,
		Country: p.Country, Province: p.Province, City: p.City,
		ASN: p.ASN, ASNOrg: p.ASNOrg, IPType: p.IPType, ISP: p.ISP,
		RiskLevel: level, RiskTags: strings.Join(tags, ","),
	})
	// 第一阶段仅生成观察候选：danger + 公网IP + 非白名单，24小时自动过期。
	// 策略 mode 固定 observe，节点命中后只回传观察事件，不会拦截或跳转。
	if level == "danger" && !store.policyIPAllowed(e.IP) {
		if err := store.upsertPolicyCandidate(e.IP, e.Site, strings.Join(tags, ","), 24*time.Hour); err != nil {
			log.Printf("policy candidate error: %v", err)
		}
	}
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
	// 闸门关闭时全站放行(仍已记录访问)
	if !gateEnabled || passed == 1 {
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https: http:; connect-src 'self' https: http:; frame-src https: http:; font-src 'self' data: https:")
		w.Write([]byte(renderGatePage()))
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
