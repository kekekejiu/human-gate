package main

import (
	"database/sql"
	"net/netip"
	"strings"
	"time"
)

var infrastructureAllowlist = map[string]string{
	"39.96.203.191/32":  "EZ主题可信反代",
	"120.55.94.106/32":  "EZ主题可信反代",
	"103.118.42.217/32": "EZ主题可信反代",
	"103.118.42.224/32": "EZ主题可信反代",
	"127.0.0.0/8":       "本机回环地址",
	"::1/128":           "本机IPv6回环地址",
	"10.0.0.0/8":        "私有网络",
	"172.16.0.0/12":     "私有网络",
	"192.168.0.0/16":    "私有网络",
}

type policyCandidate struct {
	IP        string `json:"ip"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
	ExpiresAt int64  `json:"expires_at"`
	HitCount  int    `json:"hit_count"`
	Sites     string `json:"sites"`
	Reasons   string `json:"reasons"`
}

type policyHit struct {
	TS      int64  `json:"ts"`
	IP      string `json:"ip"`
	Site    string `json:"site"`
	Version int64  `json:"version"`
	Action  string `json:"action"`
	Mode    string `json:"mode"`
}

func (s *visitStore) initPolicy() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS policy_meta (
  id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL,
  mode TEXT NOT NULL, action TEXT NOT NULL, redirect_url TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_allow (
  network TEXT PRIMARY KEY, note TEXT, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_candidates (
  ip TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, hit_count INTEGER NOT NULL,
  sites TEXT, reasons TEXT
);
CREATE TABLE IF NOT EXISTS policy_hits (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, ip TEXT,
  site TEXT, version INTEGER, action TEXT, mode TEXT
);
CREATE INDEX IF NOT EXISTS idx_policy_candidates_exp ON policy_candidates(expires_at);
CREATE INDEX IF NOT EXISTS idx_policy_hits_ts ON policy_hits(ts);
INSERT OR IGNORE INTO policy_meta(id,version,mode,action,redirect_url,updated_at)
VALUES(1,1,'observe','redirect','https://www.baidu.com/',strftime('%s','now'));
`)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	for network, note := range infrastructureAllowlist {
		if _, err = s.db.Exec(`INSERT OR IGNORE INTO policy_allow(network,note,created_at) VALUES(?,?,?)`, network, note, now); err != nil {
			return err
		}
	}
	return nil
}

func mergeCSV(old, value string) string {
	if value == "" {
		return old
	}
	for _, part := range strings.Split(old, ",") {
		if part == value {
			return old
		}
	}
	if old == "" {
		return value
	}
	return old + "," + value
}

func (s *visitStore) policyIPAllowed(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return true
	}
	rows, err := s.db.Query(`SELECT network FROM policy_allow`)
	if err != nil {
		return true // 白名单查询异常时安全放行，不生成候选
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

func (s *visitStore) upsertPolicyCandidate(ip, site, reasons string, ttl time.Duration) error {
	now := time.Now().Unix()
	expires := now + int64(ttl.Seconds())
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var old policyCandidate
	err = tx.QueryRow(`SELECT ip,first_seen,last_seen,expires_at,hit_count,sites,reasons FROM policy_candidates WHERE ip=?`, ip).
		Scan(&old.IP, &old.FirstSeen, &old.LastSeen, &old.ExpiresAt, &old.HitCount, &old.Sites, &old.Reasons)
	if err == sql.ErrNoRows {
		_, err = tx.Exec(`INSERT INTO policy_candidates(ip,first_seen,last_seen,expires_at,hit_count,sites,reasons) VALUES(?,?,?,?,?,?,?)`, ip, now, now, expires, 1, site, reasons)
	} else if err == nil {
		_, err = tx.Exec(`UPDATE policy_candidates SET last_seen=?,expires_at=?,hit_count=?,sites=?,reasons=? WHERE ip=?`, now, expires, old.HitCount+1, mergeCSV(old.Sites, site), mergeCSV(old.Reasons, reasons), ip)
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE policy_meta SET version=version+1,updated_at=? WHERE id=1`, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *visitStore) insertPolicyHit(e rawEvent) {
	_, _ = s.db.Exec(`INSERT INTO policy_hits(ts,ip,site,version,action,mode) VALUES(?,?,?,?,?,?)`, e.TS, e.IP, e.Site, e.PolicyVersion, e.PolicyAction, e.PolicyMode)
}

func (s *visitStore) policyMeta() (version int64, mode, action, redirect string, err error) {
	err = s.db.QueryRow(`SELECT version,mode,action,redirect_url FROM policy_meta WHERE id=1`).Scan(&version, &mode, &action, &redirect)
	return
}

func (s *visitStore) policyAllows() ([]string, error) {
	rows, err := s.db.Query(`SELECT network FROM policy_allow ORDER BY network`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *visitStore) activePolicyCandidates() ([]policyCandidate, error) {
	rows, err := s.db.Query(`SELECT ip,first_seen,last_seen,expires_at,hit_count,sites,reasons FROM policy_candidates WHERE expires_at>? ORDER BY last_seen DESC`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []policyCandidate
	for rows.Next() {
		var v policyCandidate
		if err := rows.Scan(&v.IP, &v.FirstSeen, &v.LastSeen, &v.ExpiresAt, &v.HitCount, &v.Sites, &v.Reasons); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *visitStore) recentPolicyHits(limit int) ([]policyHit, error) {
	rows, err := s.db.Query(`SELECT ts,ip,site,version,action,mode FROM policy_hits ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []policyHit
	for rows.Next() {
		var v policyHit
		if err := rows.Scan(&v.TS, &v.IP, &v.Site, &v.Version, &v.Action, &v.Mode); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
