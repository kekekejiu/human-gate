package main

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const adminCookie = "hg_admin"

// handleAdminLogin 处理管理面板登录(表单 POST)
func handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/__gate/admin", http.StatusFound)
		return
	}
	u := r.FormValue("username")
	p := r.FormValue("password")
	okU := subtle.ConstantTimeCompare([]byte(u), []byte(adminUser)) == 1
	okP := subtle.ConstantTimeCompare([]byte(p), []byte(adminPass)) == 1
	if !okU || !okP {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("登录失败"))
		return
	}
	token := signPass(secret, "admin", 8*time.Hour)
	http.SetCookie(w, &http.Cookie{
		Name: adminCookie, Value: token, Path: "/__gate/admin",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: true,
		MaxAge: int((8 * time.Hour).Seconds()),
	})
	http.Redirect(w, r, "/__gate/admin", http.StatusFound)
}

func adminAuthed(r *http.Request) bool {
	c, err := r.Cookie(adminCookie)
	if err != nil {
		return false
	}
	return verifyPass(secret, "admin", c.Value)
}

// handleAdminPage 管理面板 HTML
func handleAdminPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if !adminAuthed(r) {
		w.Write([]byte(adminLoginHTML))
		return
	}
	w.Write([]byte(adminPageHTML))
}

// handleAdminAPI 管理面板数据接口(JSON)，需登录
func handleAdminAPI(w http.ResponseWriter, r *http.Request) {
	if !adminAuthed(r) {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]string{"error": "unauthorized"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/__gate/admin/api/")
	hours := atoiDefault(r.URL.Query().Get("hours"), 24)

	switch path {
	case "summary":
		writeJSON(w, store.summary(hours))
	case "recent":
		limit := atoiDefault(r.URL.Query().Get("limit"), 200)
		rows, err := store.recent(limit, r.URL.Query().Get("risk"))
		apiResult(w, rows, err)
	case "top_ip":
		rows, err := store.groupBy("ip", hours, 30)
		apiResult(w, rows, err)
	case "by_isp":
		rows, err := store.groupBy("isp", hours, 20)
		apiResult(w, rows, err)
	case "by_type":
		rows, err := store.groupBy("ip_type", hours, 20)
		apiResult(w, rows, err)
	case "by_country":
		rows, err := store.groupBy("country", hours, 20)
		apiResult(w, rows, err)
	case "policy_candidates":
		rows, err := store.activePolicyCandidates()
		apiResult(w, rows, err)
	case "policy_hits":
		limit := atoiDefault(r.URL.Query().Get("limit"), 200)
		rows, err := store.recentPolicyHits(limit)
		apiResult(w, rows, err)
	case "policy_allow":
		rows, err := store.policyAllows()
		apiResult(w, rows, err)
	case "policy_status":
		version, mode, action, redirect, err := store.policyMeta()
		if err != nil {
			apiResult(w, nil, err)
			return
		}
		candidates, err := store.activePolicyCandidates()
		if err != nil {
			apiResult(w, nil, err)
			return
		}
		allows, err := store.policyAllows()
		if err != nil {
			apiResult(w, nil, err)
			return
		}
		writeJSON(w, map[string]interface{}{
			"version": version, "mode": mode, "action": action,
			"redirect_url": redirect, "candidate_count": len(candidates), "allow_count": len(allows),
		})
	default:
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]string{"error": "not found"})
	}
}

func apiResult(w http.ResponseWriter, data interface{}, err error) {
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, data)
}

func atoiDefault(s string, d int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return d
}
