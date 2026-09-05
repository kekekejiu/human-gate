package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type policyRule struct {
	IP        string `json:"ip"`
	ExpiresAt int64  `json:"expires_at"`
	Reasons   string `json:"reasons,omitempty"`
}

type distributedPolicy struct {
	Version     int64        `json:"version"`
	GeneratedAt int64        `json:"generated_at"`
	ExpiresAt   int64        `json:"expires_at"`
	Mode        string       `json:"mode"`
	Action      string       `json:"action"`
	RedirectURL string       `json:"redirect_url,omitempty"`
	Allow       []string     `json:"allow"`
	Rules       []policyRule `json:"rules"`
	Signature   string       `json:"signature,omitempty"`
}

type compiledPolicy struct {
	Policy distributedPolicy
	Allow  []netip.Prefix
	Rules  map[netip.Addr]policyRule
}

type policyDecision struct {
	Matched bool
	Version int64
	Mode    string
	Action  string
}

type policySyncer struct {
	url      string
	token    string
	client   *http.Client
	interval time.Duration
	current  atomic.Pointer[compiledPolicy]
}

var nodePolicy *policySyncer

func policySign(p distributedPolicy, token string) string {
	p.Signature = ""
	b, _ := json.Marshal(p)
	m := hmac.New(sha256.New, []byte(token))
	m.Write(b)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func policyVerify(p distributedPolicy, token string) bool {
	got, err := base64.RawURLEncoding.DecodeString(p.Signature)
	if err != nil {
		return false
	}
	expect, _ := base64.RawURLEncoding.DecodeString(policySign(p, token))
	return subtle.ConstantTimeCompare(got, expect) == 1
}

func compilePolicy(p distributedPolicy) (*compiledPolicy, error) {
	if p.Mode != "observe" && p.Mode != "enforce" {
		return nil, fmt.Errorf("invalid mode")
	}
	if p.ExpiresAt <= time.Now().Unix() {
		return nil, fmt.Errorf("expired policy")
	}
	cp := &compiledPolicy{Policy: p, Rules: make(map[netip.Addr]policyRule)}
	for _, raw := range p.Allow {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid allow %q", raw)
		}
		cp.Allow = append(cp.Allow, prefix)
	}
	for _, rule := range p.Rules {
		addr, err := netip.ParseAddr(rule.IP)
		if err != nil {
			return nil, fmt.Errorf("invalid rule ip %q", rule.IP)
		}
		cp.Rules[addr.Unmap()] = rule
	}
	return cp, nil
}

func (p *compiledPolicy) decide(ip string) policyDecision {
	if p.Policy.ExpiresAt <= time.Now().Unix() {
		return policyDecision{}
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return policyDecision{}
	}
	addr = addr.Unmap()
	for _, allow := range p.Allow {
		if allow.Contains(addr) {
			return policyDecision{}
		}
	}
	rule, ok := p.Rules[addr]
	if !ok || rule.ExpiresAt <= time.Now().Unix() {
		return policyDecision{}
	}
	return policyDecision{Matched: true, Version: p.Policy.Version, Mode: p.Policy.Mode, Action: p.Policy.Action}
}

func newPolicySyncer(url, token string, client *http.Client, interval time.Duration) *policySyncer {
	s := &policySyncer{url: url, token: token, client: client, interval: interval}
	go s.loop()
	return s
}

func (s *policySyncer) loop() {
	s.pull()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for range ticker.C {
		s.pull()
	}
}

func (s *policySyncer) pull() {
	req, err := http.NewRequest(http.MethodGet, s.url, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Gate-Token", s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("policy pull error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("policy pull rejected: status=%d", resp.StatusCode)
		return
	}
	var p distributedPolicy
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&p); err != nil {
		log.Printf("policy decode error: %v", err)
		return
	}
	if !policyVerify(p, s.token) {
		log.Printf("policy signature invalid")
		return
	}
	compiled, err := compilePolicy(p)
	if err != nil {
		log.Printf("policy compile error: %v", err)
		return
	}
	s.current.Store(compiled)
	log.Printf("policy updated: version=%d mode=%s rules=%d allow=%d", p.Version, p.Mode, len(p.Rules), len(p.Allow))
}

func (s *policySyncer) decide(ip string) policyDecision {
	if s == nil {
		return policyDecision{}
	}
	cur := s.current.Load()
	if cur == nil {
		return policyDecision{}
	}
	return cur.decide(ip)
}

func derivePolicyURL(reportURL string) string {
	if strings.HasSuffix(reportURL, "/ingest") {
		return strings.TrimSuffix(reportURL, "/ingest") + "/policy"
	}
	return strings.TrimRight(reportURL, "/") + "/policy"
}

func handlePolicy(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Gate-Token")), []byte(ingestToken)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	version, mode, action, redirect, err := store.policyMeta()
	if err != nil {
		http.Error(w, "policy", http.StatusInternalServerError)
		return
	}
	if r.Header.Get("If-None-Match") == strconv.FormatInt(version, 10) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	allows, err := store.policyAllows()
	if err != nil {
		http.Error(w, "policy", http.StatusInternalServerError)
		return
	}
	candidates, err := store.activePolicyCandidates()
	if err != nil {
		http.Error(w, "policy", http.StatusInternalServerError)
		return
	}
	rules := make([]policyRule, 0, len(candidates))
	for _, c := range candidates {
		rules = append(rules, policyRule{IP: c.IP, ExpiresAt: c.ExpiresAt, Reasons: c.Reasons})
	}
	now := time.Now().Unix()
	p := distributedPolicy{Version: version, GeneratedAt: now, ExpiresAt: now + 300, Mode: mode, Action: action, RedirectURL: redirect, Allow: allows, Rules: rules}
	p.Signature = policySign(p, ingestToken)
	w.Header().Set("ETag", strconv.FormatInt(version, 10))
	writeJSON(w, p)
}
